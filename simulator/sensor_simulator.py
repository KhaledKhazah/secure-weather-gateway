import argparse
import random
import socket
import struct
import time

from Cryptodome.Hash import SHA256


BLOCKSIZE = 32
DATA_FORMAT = "!HIfffI"

DEFAULT_KEY = "isdfbuzasvduavsudhvasdv"


def create_hmac(key, data):
    """
    Creates the HMAC exactly like the original weather_warden.
    """

    key_bytes = key.encode("utf-8")

    # Prepare key
    if len(key_bytes) > BLOCKSIZE:
        derived_key = SHA256.new(key_bytes).digest()
    else:
        derived_key = key_bytes + b"\x00" * (BLOCKSIZE - len(key_bytes))

    # HMAC pads
    o_key_pad = bytes.fromhex("5c") * BLOCKSIZE
    i_key_pad = bytes.fromhex("36") * BLOCKSIZE

    # XOR key with pads
    o_key = bytes(
        a ^ b
        for a, b in zip(derived_key, o_key_pad)
    )

    i_key = bytes(
        a ^ b
        for a, b in zip(derived_key, i_key_pad)
    )

    # Inner hash
    h_inner = SHA256.new(i_key + data)

    # Outer hash
    h_outer = SHA256.new(
        o_key + h_inner.digest()
    )

    return h_outer.digest()


def create_sensor_data(uid, sequence_number, source_port):
    """
    Generates random weather measurements.
    """

    temperature = random.uniform(-10.0, 35.0)
    humidity = random.uniform(20.0, 90.0)
    wind_speed = random.uniform(0.0, 120.0)

    data = struct.pack(
        DATA_FORMAT,
        uid,
        sequence_number,
        temperature,
        humidity,
        wind_speed,
        source_port
    )

    return data, temperature, humidity, wind_speed


def manipulate_data(data):
    """
    Simulates an attacker changing sensor values
    without knowing the secret HMAC key.
    """

    uid, sequence_number, temperature, humidity, wind_speed, port = \
        struct.unpack(DATA_FORMAT, data)

    # Manipulate the temperature
    temperature += random.uniform(20.0, 50.0)

    manipulated_data = struct.pack(
        DATA_FORMAT,
        uid,
        sequence_number,
        temperature,
        humidity,
        wind_speed,
        port
    )

    return manipulated_data


def main(
    uid,
    source_ip,
    source_port,
    destination_ip,
    destination_port,
    key,
    interval,
    bad_actor
):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.bind(
        (source_ip, source_port)
    )

    sequence_number = 0

    print("Sensor simulator started")
    print(f"UID: {uid}")
    print(f"Source: {source_ip}:{source_port}")
    print(
        f"Destination: "
        f"{destination_ip}:{destination_port}"
    )

    if bad_actor:
        print("Mode: BAD ACTOR")
    else:
        print("Mode: NORMAL")

    print()

    try:
        while True:

            data, temperature, humidity, wind_speed = \
                create_sensor_data(
                    uid,
                    sequence_number,
                    source_port
                )

            # Calculate HMAC BEFORE possible manipulation
            hmac_value = create_hmac(
                key,
                data
            )

            status = "VALID"

            if bad_actor:
                # Modify data but keep the old HMAC
                data = manipulate_data(data)

                status = "MANIPULATED"

            packet = data + hmac_value

            sock.sendto(
                packet,
                (
                    destination_ip,
                    destination_port
                )
            )

            print(
                f"[SEND] "
                f"UID={uid} "
                f"SEQ={sequence_number} "
                f"TEMP={temperature:.2f}°C "
                f"HUM={humidity:.2f}% "
                f"WIND={wind_speed:.2f}km/h "
                f"STATUS={status}"
            )

            sequence_number += 1

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nSensor simulator stopped")

    finally:
        sock.close()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="UDP Weather Sensor Simulator"
    )

    parser.add_argument(
        "--uid",
        type=int,
        default=0,
        help="Unique sensor ID"
    )

    parser.add_argument(
        "--source_ip",
        default="127.0.0.1",
        help="Sensor source IP"
    )

    parser.add_argument(
        "--source_port",
        type=int,
        default=5000,
        help="Sensor source port"
    )

    parser.add_argument(
        "--dest_ip",
        default="127.0.0.1",
        help="Weather Warden IP"
    )

    parser.add_argument(
        "--dest_port",
        type=int,
        default=4711,
        help="Weather Warden port"
    )

    parser.add_argument(
        "--key",
        default=DEFAULT_KEY,
        help="Secret HMAC key"
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Seconds between packets"
    )

    parser.add_argument(
        "--bad-actor",
        action="store_true",
        help="Send manipulated sensor data"
    )

    args = parser.parse_args()

    main(
        args.uid,
        args.source_ip,
        args.source_port,
        args.dest_ip,
        args.dest_port,
        args.key,
        args.interval,
        args.bad_actor
    )