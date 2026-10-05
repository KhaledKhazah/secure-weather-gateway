import argparse
import json
import socket
import struct
import threading

from collections import deque
from pathlib import Path

from flask import (
    Flask,
    jsonify,
    send_from_directory
)


DATA_FORMAT = "!HIfffI"
DATA_SIZE = 22


# =================================
# Shared application data
# =================================

sensor_data = {}

statistics = {
    "valid_packets": 0,
    "blocked_packets": 0
}

# Store only the latest 20 events
security_events = deque(
    maxlen=20
)

data_lock = threading.Lock()


# =================================
# Dashboard directory
# =================================

BASE_DIR = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

DASHBOARD_DIR = (
    BASE_DIR / "dashboard"
)


app = Flask(__name__)


# =================================
# VALID SENSOR DATA COLLECTOR
# =================================

def udp_collector(
    ip,
    port
):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.bind(
        (ip, port)
    )

    print(
        f"UDP Collector listening on "
        f"{ip}:{port}"
    )

    try:
        while True:

            data, addr = sock.recvfrom(
                2048
            )

            if len(data) != DATA_SIZE:

                print(
                    "[WARNING] "
                    f"Invalid packet size: "
                    f"{len(data)} bytes"
                )

                continue

            (
                uid,
                sequence_number,
                temperature,
                humidity,
                wind_speed,
                source_port
            ) = struct.unpack(
                DATA_FORMAT,
                data
            )

            sensor = {
                "uid": uid,

                "sequence_number":
                    sequence_number,

                "temperature":
                    round(
                        temperature,
                        2
                    ),

                "humidity":
                    round(
                        humidity,
                        2
                    ),

                "wind_speed":
                    round(
                        wind_speed,
                        2
                    ),

                "source_port":
                    source_port
            }

            with data_lock:

                sensor_data[uid] = sensor

                statistics[
                    "valid_packets"
                ] += 1

            print(
                f"[VALID] "
                f"UID={uid} "
                f"SEQ={sequence_number} "
                f"TEMP={temperature:.2f}°C "
                f"HUM={humidity:.2f}% "
                f"WIND={wind_speed:.2f}km/h"
            )

    except KeyboardInterrupt:

        print(
            "\nUDP Collector stopped"
        )

    finally:
        sock.close()


# =================================
# SECURITY EVENT COLLECTOR
# =================================

def security_event_collector(
    ip,
    port
):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.bind(
        (ip, port)
    )

    print(
        f"Security Event Collector "
        f"listening on {ip}:{port}"
    )

    try:
        while True:

            data, addr = sock.recvfrom(
                2048
            )

            try:

                event = json.loads(
                    data.decode(
                        "utf-8"
                    )
                )

            except (
                json.JSONDecodeError,
                UnicodeDecodeError
            ):

                print(
                    "[WARNING] "
                    "Invalid security event"
                )

                continue


            event_type = event.get(
                "type"
            )


            with data_lock:

                # Only invalid HMAC packets
                # increase the blocked counter.
                if (
                    event_type
                    == "invalid_hmac"
                ):

                    statistics[
                        "blocked_packets"
                    ] += 1

                security_events.appendleft(
                    event
                )


            if (
                event_type
                == "invalid_hmac"
            ):

                print(
                    f"[BLOCKED] "
                    f"UID={event.get('uid')} "
                    f"SEQ="
                    f"{event.get('sequence_number')} "
                    f"REASON=INVALID_HMAC"
                )

            elif (
                event_type
                == "hmac_verified"
            ):

                print(
                    f"[VERIFIED] "
                    f"UID={event.get('uid')} "
                    f"SEQ="
                    f"{event.get('sequence_number')} "
                    f"HMAC=VALID"
                )

            else:

                print(
                    "[WARNING] "
                    "Unknown security event type"
                )

    except KeyboardInterrupt:

        print(
            "\nSecurity Event "
            "Collector stopped"
        )

    finally:
        sock.close()


# =================================
# REST API
# =================================

@app.route(
    "/api/sensors",
    methods=["GET"]
)
def get_sensors():

    with data_lock:

        sensors = list(
            sensor_data.values()
        )

    return jsonify(
        sensors
    )


@app.route(
    "/api/security-events",
    methods=["GET"]
)
def get_security_events():

    with data_lock:

        events = list(
            security_events
        )

    return jsonify(
        events
    )


@app.route(
    "/api/status",
    methods=["GET"]
)
def get_status():

    with data_lock:

        sensor_count = len(
            sensor_data
        )

        valid_packets = (
            statistics[
                "valid_packets"
            ]
        )

        blocked_packets = (
            statistics[
                "blocked_packets"
            ]
        )

    return jsonify({
        "status": "online",

        "sensors":
            sensor_count,

        "valid_packets":
            valid_packets,

        "blocked_packets":
            blocked_packets
    })


# =================================
# DASHBOARD
# =================================

@app.route("/")
def dashboard():

    return send_from_directory(
        DASHBOARD_DIR,
        "index.html"
    )


@app.route(
    "/<path:filename>"
)
def dashboard_files(
    filename
):

    return send_from_directory(
        DASHBOARD_DIR,
        filename
    )


# =================================
# MAIN
# =================================

def main(
    udp_ip,
    udp_port,
    event_port,
    http_ip,
    http_port
):

    print(
        "Dashboard directory:",
        DASHBOARD_DIR
    )

    print(
        "Index exists:",
        (
            DASHBOARD_DIR
            / "index.html"
        ).exists()
    )


    # Thread 1:
    # Valid sensor packets
    udp_thread = threading.Thread(
        target=udp_collector,

        args=(
            udp_ip,
            udp_port
        ),

        daemon=True
    )

    udp_thread.start()


    # Thread 2:
    # Security events
    event_thread = threading.Thread(
        target=security_event_collector,

        args=(
            udp_ip,
            event_port
        ),

        daemon=True
    )

    event_thread.start()


    print(
        f"HTTP API running on "
        f"http://{http_ip}:{http_port}"
    )


    # Main thread:
    # Flask web server
    app.run(
        host=http_ip,
        port=http_port,
        debug=False
    )


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description=(
            "Weather Collector "
            "with REST API"
        )
    )

    parser.add_argument(
        "--udp-ip",
        default="127.0.0.1"
    )

    parser.add_argument(
        "--udp-port",
        type=int,
        default=4811,

        help=(
            "Port for verified "
            "sensor packets"
        )
    )

    parser.add_argument(
        "--event-port",
        type=int,
        default=4812,

        help=(
            "Port for "
            "security events"
        )
    )

    parser.add_argument(
        "--http-ip",
        default="127.0.0.1"
    )

    parser.add_argument(
        "--http-port",
        type=int,
        default=8000
    )

    args = parser.parse_args()

    main(
        args.udp_ip,
        args.udp_port,
        args.event_port,
        args.http_ip,
        args.http_port
    )