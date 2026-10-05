import argparse
import socket
import struct
import threading
from pathlib import Path

from flask import Flask, jsonify, send_from_directory


DATA_FORMAT = "!HIfffI"
DATA_SIZE = 22

sensor_data = {}
data_lock = threading.Lock()


BASE_DIR = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = BASE_DIR / "dashboard"


app = Flask(__name__)


def udp_collector(ip, port):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.bind((ip, port))

    print(f"UDP Collector listening on {ip}:{port}")

    try:
        while True:
            data, addr = sock.recvfrom(2048)

            if len(data) != DATA_SIZE:
                print(
                    f"[WARNING] Invalid packet size: "
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
            ) = struct.unpack(DATA_FORMAT, data)

            sensor = {
                "uid": uid,
                "sequence_number": sequence_number,
                "temperature": round(temperature, 2),
                "humidity": round(humidity, 2),
                "wind_speed": round(wind_speed, 2),
                "source_port": source_port
            }

            with data_lock:
                sensor_data[uid] = sensor

            print(
                f"[VALID] "
                f"UID={uid} "
                f"SEQ={sequence_number} "
                f"TEMP={temperature:.2f}°C "
                f"HUM={humidity:.2f}% "
                f"WIND={wind_speed:.2f}km/h"
            )

    except KeyboardInterrupt:
        print("\nUDP Collector stopped")

    finally:
        sock.close()


@app.route("/")
def dashboard():
    return send_from_directory(
        DASHBOARD_DIR,
        "index.html"
    )


@app.route("/<path:filename>")
def dashboard_files(filename):
    return send_from_directory(
        DASHBOARD_DIR,
        filename
    )


@app.route("/api/sensors", methods=["GET"])
def get_sensors():
    with data_lock:
        sensors = list(sensor_data.values())

    return jsonify(sensors)


@app.route("/api/status", methods=["GET"])
def get_status():
    with data_lock:
        sensor_count = len(sensor_data)

    return jsonify({
        "status": "online",
        "sensors": sensor_count
    })


def main(udp_ip, udp_port, http_ip, http_port):
    print("Dashboard directory:", DASHBOARD_DIR)
    print(
        "Index exists:",
        (DASHBOARD_DIR / "index.html").exists()
    )

    udp_thread = threading.Thread(
        target=udp_collector,
        args=(udp_ip, udp_port),
        daemon=True
    )

    udp_thread.start()

    print(
        f"HTTP API running on "
        f"http://{http_ip}:{http_port}"
    )

    app.run(
        host=http_ip,
        port=http_port,
        debug=False
    )


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Weather Collector with REST API"
    )

    parser.add_argument(
        "--udp-ip",
        default="127.0.0.1"
    )

    parser.add_argument(
        "--udp-port",
        type=int,
        default=4811
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
        args.http_ip,
        args.http_port
    )