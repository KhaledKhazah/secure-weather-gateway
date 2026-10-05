import argparse
import random
import socket
import struct
import threading
import time

from Cryptodome.Hash import SHA256


BLOCKSIZE = 32
DATA_FORMAT = "!HIfffI"

DEFAULT_KEY = "isdfbuzasvduavsudhvasdv"


def create_hmac(key, data):
    key_bytes = key.encode("utf-8")

    if len(key_bytes) > BLOCKSIZE:
        derived_key = SHA256.new(key_bytes).digest()
    else:
        derived_key = (
            key_bytes
            + b"\x00" * (BLOCKSIZE - len(key_bytes))
        )

    o_key_pad = bytes.fromhex("5c") * BLOCKSIZE
    i_key_pad = bytes.fromhex("36") * BLOCKSIZE

    o_key = bytes(
        a ^ b
        for a, b in zip(
            derived_key,
            o_key_pad
        )
    )

    i_key = bytes(
        a ^ b
        for a, b in zip(
            derived_key,
            i_key_pad
        )
    )

    h_inner = SHA256.new(
        i_key + data
    )

    h_outer = SHA256.new(
        o_key + h_inner.digest()
    )

    return h_outer.digest()


def create_sensor_data(
    uid,
    sequence_number,
    source_port
):
    temperature = random.uniform(
        -10.0,
        35.0
    )

    humidity = random.uniform(
        20.0,
        90.0
    )

    wind_speed = random.uniform(
        0.0,
        120.0
    )

    data = struct.pack(
        DATA_FORMAT,
        uid,
        sequence_number,
        temperature,
        humidity,
        wind_speed,
        source_port
    )

    return data


def manipulate_data(data):
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

    # Simulate manipulated temperature
    temperature += random.uniform(
        20.0,
        50.0
    )

    manipulated_data = struct.pack(
        DATA_FORMAT,
        uid,
        sequence_number,
        temperature,
        humidity,
        wind_speed,
        source_port
    )

    return manipulated_data


def sensor_worker(
    uid,
    source_ip,
    source_port,
    destination_ip,
    destination_port,
    key,
    interval,
    bad_actor,
    stop_event
):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.bind(
        (source_ip, source_port)
    )

    sequence_number = 0

    mode = (
        "BAD ACTOR"
        if bad_actor
        else "NORMAL"
    )

    print(
        f"[START] "
        f"Sensor {uid} "
        f"Port={source_port} "
        f"Mode={mode}"
    )

    try:
        while not stop_event.is_set():

            data = create_sensor_data(
                uid,
                sequence_number,
                source_port
            )

            # HMAC is calculated from the
            # original sensor data.
            hmac_value = create_hmac(
                key,
                data
            )

            if bad_actor:
                # Change the data AFTER
                # calculating the HMAC.
                data = manipulate_data(
                    data
                )

            (
                _,
                _,
                temperature,
                humidity,
                wind_speed,
                _
            ) = struct.unpack(
                DATA_FORMAT,
                data
            )

            packet = (
                data
                + hmac_value
            )

            sock.sendto(
                packet,
                (
                    destination_ip,
                    destination_port
                )
            )

            status = (
                "MANIPULATED"
                if bad_actor
                else "VALID"
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

            stop_event.wait(
                interval
            )

    finally:
        sock.close()

        print(
            f"[STOP] Sensor {uid}"
        )


def main(
    sensor_count,
    bad_actor_count,
    source_ip,
    base_source_port,
    destination_ip,
    destination_port,
    key,
    interval
):
    if sensor_count < 1:
        raise ValueError(
            "Sensor count must be at least 1."
        )

    if bad_actor_count < 0:
        raise ValueError(
            "Bad actor count cannot be negative."
        )

    if bad_actor_count > sensor_count:
        raise ValueError(
            "Bad actor count cannot be greater "
            "than sensor count."
        )

    stop_event = threading.Event()

    threads = []

    first_bad_actor_uid = (
        sensor_count
        - bad_actor_count
    )

    print()
    print(
        "Secure Weather Sensor Simulator"
    )

    print(
        f"Sensors: {sensor_count}"
    )

    print(
        f"Bad actors: {bad_actor_count}"
    )

    print(
        f"Destination: "
        f"{destination_ip}:"
        f"{destination_port}"
    )

    print()

    for uid in range(
        sensor_count
    ):
        source_port = (
            base_source_port
            + uid
        )

        bad_actor = (
            uid
            >= first_bad_actor_uid
        )

        thread = threading.Thread(
            target=sensor_worker,
            args=(
                uid,
                source_ip,
                source_port,
                destination_ip,
                destination_port,
                key,
                interval,
                bad_actor,
                stop_event
            )
        )

        threads.append(
            thread
        )

        thread.start()

    try:
        for thread in threads:
            thread.join()

    except KeyboardInterrupt:
        print(
            "\nStopping all sensors..."
        )

        stop_event.set()

        for thread in threads:
            thread.join()

        print(
            "All sensors stopped."
        )


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description=(
            "Multi-Sensor UDP "
            "Weather Simulator"
        )
    )

    parser.add_argument(
        "--sensors",
        type=int,
        default=1,
        help="Total number of sensors"
    )

    parser.add_argument(
        "--bad-actors",
        type=int,
        default=0,
        help=(
            "Number of manipulated sensors"
        )
    )

    parser.add_argument(
        "--source-ip",
        default="127.0.0.1",
        help="Sensor source IP"
    )

    parser.add_argument(
        "--base-source-port",
        type=int,
        default=5000,
        help=(
            "First sensor source port"
        )
    )

    parser.add_argument(
        "--dest-ip",
        default="127.0.0.1",
        help="Weather Warden IP"
    )

    parser.add_argument(
        "--dest-port",
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
        help=(
            "Seconds between packets"
        )
    )

    args = parser.parse_args()

    main(
        args.sensors,
        args.bad_actors,
        args.source_ip,
        args.base_source_port,
        args.dest_ip,
        args.dest_port,
        args.key,
        args.interval
    )