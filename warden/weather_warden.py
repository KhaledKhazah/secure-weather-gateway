import argparse
import json
import socket
import struct
import sys

from Cryptodome.Hash import SHA256


BLOCKSIZE = 32

DATA_FORMAT = "!HIfffI"
DATA_SIZE = 22
HMAC_SIZE = 32
PACKET_SIZE = DATA_SIZE + HMAC_SIZE


def create_pad_keys(key):
    assert len(key) == BLOCKSIZE

    o_key_pad = bytes.fromhex("5c") * BLOCKSIZE
    i_key_pad = bytes.fromhex("36") * BLOCKSIZE

    o_key = bytes(
        a ^ b
        for a, b in zip(key, o_key_pad)
    )

    i_key = bytes(
        a ^ b
        for a, b in zip(key, i_key_pad)
    )

    return o_key, i_key


def create_event(
    event_type,
    uid,
    sequence_number,
    temperature,
    humidity,
    wind_speed,
    source_port
):
    return {
        "type": event_type,
        "uid": uid,
        "sequence_number": sequence_number,
        "temperature": round(temperature, 2),
        "humidity": round(humidity, 2),
        "wind_speed": round(wind_speed, 2),
        "source_port": source_port
    }


def send_event(
    sock,
    event,
    ip,
    event_port
):
    event_data = json.dumps(
        event
    ).encode("utf-8")

    sock.sendto(
        event_data,
        (ip, event_port)
    )


def main(
    ip,
    port_in,
    port_out,
    port_serv,
    event_port,
    key
):
    key_bytes = key.encode("utf-8")

    if len(key_bytes) > BLOCKSIZE:
        derived_key = SHA256.new(
            key_bytes
        ).digest()

    else:
        derived_key = (
            key_bytes
            + b"\x00"
            * (BLOCKSIZE - len(key_bytes))
        )

    o_key, i_key = create_pad_keys(
        derived_key
    )

    # Receives packets from sensors
    socket_in = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    socket_in.bind(
        (ip, port_in)
    )

    # Sends packets to collector
    # and security events
    socket_out = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    socket_out.bind(
        (ip, port_out)
    )

    print(
        f"Warden listening on "
        f"{ip}:{port_in}"
    )

    print(
        f"Valid packets -> "
        f"{ip}:{port_serv}"
    )

    print(
        f"Security events -> "
        f"{ip}:{event_port}"
    )

    try:
        while True:

            packet, addr = socket_in.recvfrom(
                2048
            )

            if len(packet) < PACKET_SIZE:
                print(
                    "[WARNING] Packet too small"
                )
                continue

            # First 22 bytes:
            # actual sensor data
            data_rec = packet[:DATA_SIZE]

            # Next 32 bytes:
            # received HMAC
            hmac_rec = packet[
                DATA_SIZE:
                DATA_SIZE + HMAC_SIZE
            ]

            # Calculate the HMAC ourselves
            h_inner = SHA256.new(
                i_key + data_rec
            )

            h_outer = SHA256.new(
                o_key + h_inner.digest()
            )

            hmac_cal = h_outer.digest()

            (
                uid,
                sequence_number,
                temperature,
                humidity,
                wind_speed,
                source_port
            ) = struct.unpack(
                DATA_FORMAT,
                data_rec
            )

            # =================================
            # VALID HMAC
            # =================================

            if hmac_rec == hmac_cal:

                print(
                    f"[VALID] "
                    f"UID={uid} "
                    f"SEQ={sequence_number} "
                    f"TEMP={temperature:.2f}°C "
                    f"HUM={humidity:.2f}% "
                    f"WIND={wind_speed:.2f}km/h "
                    f"PORT={source_port}"
                )

                # Forward valid sensor data
                socket_out.sendto(
                    data_rec,
                    (ip, port_serv)
                )

                # Create green security event
                event = create_event(
                    "hmac_verified",
                    uid,
                    sequence_number,
                    temperature,
                    humidity,
                    wind_speed,
                    source_port
                )

                send_event(
                    socket_out,
                    event,
                    ip,
                    event_port
                )

            # =================================
            # INVALID HMAC
            # =================================

            else:

                print(
                    f"[WARNING] "
                    f"Value integrity compromised: "
                    f"UID={uid} "
                    f"SEQ={sequence_number} "
                    f"TEMP={temperature:.2f}°C "
                    f"HUM={humidity:.2f}% "
                    f"WIND={wind_speed:.2f}km/h "
                    f"PORT={source_port}"
                )

                # Create red security event
                event = create_event(
                    "invalid_hmac",
                    uid,
                    sequence_number,
                    temperature,
                    humidity,
                    wind_speed,
                    source_port
                )

                send_event(
                    socket_out,
                    event,
                    ip,
                    event_port
                )

                # Important:
                # Invalid sensor data is NOT
                # forwarded to the collector.

    except KeyboardInterrupt:
        print(
            "\nWarden shutting down"
        )

    finally:
        socket_in.close()
        socket_out.close()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description=(
            "Weather Station UDP "
            "Security Warden"
        )
    )

    parser.add_argument(
        "--ip",
        default="127.0.0.1",
        help="IP address"
    )

    parser.add_argument(
        "--port_in",
        default=4711,
        type=int,
        help=(
            "Port for incoming "
            "sensor packets"
        )
    )

    parser.add_argument(
        "--port_out",
        default=4810,
        type=int,
        help=(
            "Source port for "
            "outgoing packets"
        )
    )

    parser.add_argument(
        "--port_serv",
        default=4811,
        type=int,
        help=(
            "Collector port for "
            "verified sensor data"
        )
    )

    parser.add_argument(
        "--event_port",
        default=4812,
        type=int,
        help=(
            "Collector port for "
            "security events"
        )
    )

    parser.add_argument(
        "--key",
        default="isdfbuzasvduavsudhvasdv",
        type=str,
        help="HMAC secret key"
    )

    args = parser.parse_args()

    try:
        main(
            args.ip,
            args.port_in,
            args.port_out,
            args.port_serv,
            args.event_port,
            args.key
        )

    except KeyboardInterrupt:
        sys.exit(0)