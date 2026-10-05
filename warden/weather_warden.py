import argparse
import json
import socket
import struct
import sys

from Cryptodome.Hash import SHA256


BLOCKSIZE = 32


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


def main(
    ip,
    port_in,
    port_out,
    port_serv,
    event_port,
    key
):
    key_byte = key.encode("utf-8")

    if len(key_byte) > BLOCKSIZE:
        derived_key = SHA256.new(
            key_byte
        ).digest()

    else:
        derived_key = (
            key_byte
            + b"\x00"
            * (BLOCKSIZE - len(key_byte))
        )

    o_key, i_key = create_pad_keys(
        derived_key
    )

    # Socket for incoming sensor packets
    socket_in = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    socket_in.bind(
        (ip, port_in)
    )

    # Socket for outgoing packets
    socket_out = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    socket_out.bind(
        (ip, port_out)
    )

    data_size = 22
    hmac_size = 32
    packet_size = data_size + hmac_size

    print(
        f"Warden listening on "
        f"{ip}:{port_in}"
    )

    print(
        f"Valid packets → "
        f"{ip}:{port_serv}"
    )

    print(
        f"Security events → "
        f"{ip}:{event_port}"
    )

    try:
        while True:
            packet, addr = socket_in.recvfrom(
                2048
            )

            if len(packet) < packet_size:
                print(
                    "[WARNING] Packet too small"
                )
                continue

            # Split sensor data and HMAC
            data_rec = packet[:data_size]

            hmac_rec = packet[
                data_size:
                data_size + hmac_size
            ]

            # Calculate HMAC ourselves
            h_inner = SHA256.new(
                i_key + data_rec
            )

            h_outer = SHA256.new(
                o_key + h_inner.digest()
            )

            hmac_cal = h_outer.digest()

            # Decode sensor data
            (
                uid,
                seq_num,
                temp,
                hum,
                wind_speed,
                port
            ) = struct.unpack(
                "!HIfffI",
                data_rec
            )

            # -------------------------
            # VALID HMAC
            # -------------------------

            if hmac_rec == hmac_cal:

                print(
                    f"[VALID] "
                    f"UID={uid} "
                    f"SEQ={seq_num} "
                    f"TEMP={temp:.2f}°C "
                    f"HUM={hum:.2f}% "
                    f"WIND={wind_speed:.2f}km/h "
                    f"PORT={port}"
                )

                # Forward only the sensor data.
                # The collector does not need the HMAC.
                socket_out.sendto(
                    data_rec,
                    (ip, port_serv)
                )

            # -------------------------
            # INVALID HMAC
            # -------------------------

            else:
                print(
                    f"[WARNING] "
                    f"Value integrity compromised: "
                    f"UID={uid} "
                    f"SEQ={seq_num} "
                    f"TEMP={temp:.2f}°C "
                    f"HUM={hum:.2f}% "
                    f"WIND={wind_speed:.2f}km/h "
                    f"PORT={port}"
                )

                # Create security event
                event = {
                    "type": "invalid_hmac",
                    "uid": uid,
                    "sequence_number": seq_num,
                    "temperature": round(
                        temp,
                        2
                    ),
                    "humidity": round(
                        hum,
                        2
                    ),
                    "wind_speed": round(
                        wind_speed,
                        2
                    ),
                    "source_port": port
                }

                # Python dictionary
                # → JSON string
                # → bytes
                event_data = json.dumps(
                    event
                ).encode("utf-8")

                # Send security event
                # to the collector
                socket_out.sendto(
                    event_data,
                    (ip, event_port)
                )

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
        help="Port for incoming sensor packets"
    )

    parser.add_argument(
        "--port_out",
        default=4810,
        type=int,
        help="Source port for outgoing packets"
    )

    parser.add_argument(
        "--port_serv",
        default=4811,
        type=int,
        help="Collector port for valid packets"
    )

    parser.add_argument(
        "--event_port",
        default=4812,
        type=int,
        help="Collector port for security events"
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