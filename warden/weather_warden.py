import argparse
import socket
import struct
import sys
from Cryptodome.Hash import SHA256

blocksize=32

def create_pad_keys(key):
    assert len(key) == blocksize
    o_key_pad = bytes.fromhex('5c')*blocksize
    i_key_pad = bytes.fromhex('36')*blocksize
    o_key =  bytes(a ^ b for a, b in zip(key, o_key_pad))
    i_key = bytes(a ^ b for a, b in zip(key, i_key_pad))
    return o_key, i_key


def main(ip, port_in, port_out, port_serv, key):
    key_byte = key.encode('utf-8')
    if len(key_byte) > blocksize:
        derived_key = SHA256.new(key_byte).digest()
    else:
        derived_key = key_byte + b'\x00' *(blocksize - len(key_byte))

    o_key, i_key = create_pad_keys(derived_key)
    
    socket_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socket_in.bind((ip, port_in))
    
    socket_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socket_out.bind((ip, port_out))
    
    data_size = 22
    hmac_size = 32
    packet_size = data_size + hmac_size
    
    try:
        while True:
            packet, addr = socket_in.recvfrom(2048)
            
            if len(packet) < packet_size:
                continue
            
            data_rec = packet[:data_size]
            hmac_rec = packet[data_size:]
            
            h_inner = SHA256.new(i_key + data_rec)
            h_outer = SHA256.new(o_key + h_inner.digest())
            hmac_cal = h_outer.digest()
            
            uid, seq_num, temp, hum, wind_speed, port = struct.unpack("!HIfffI", data_rec)
            
            if hmac_rec == hmac_cal:
                print(f"{uid} {seq_num} {temp:.2f} {hum:.2f} {wind_speed:.2f} {port}")
                socket_out.sendto(data_rec, (ip, port_serv))
            else:
                print(f"[WARNING] Value integrity compromised: {uid} {seq_num} {temp:.2f} {hum:.2f} {wind_speed:.2f} {port}")
                
    except KeyboardInterrupt:
        print("Warden shutting down")
    finally:
        socket_in.close()
        socket_out.close()
            

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WeatherStation UDP Server Warden")
    parser.add_argument("--ip", default="127.0.0.1", help="IP address to bind the server warden")
    parser.add_argument("--port_in", default=4711, type=int, help="Port to bind the server warden")
    parser.add_argument("--port_out", default=4810, type=int, help="Port to use for transmission to server")
    parser.add_argument("--port_serv", default=4811, type=int, help="Server port as transmission target for server")
    parser.add_argument("--key", default="isdfbuzasvduavsudhvasdv", type=str, help="Key for the HMAC integrity verification")

    args = parser.parse_args()
    try:
        main(args.ip, args.port_in, args.port_out, args.port_serv, args.key)
    except KeyboardInterrupt:
        sys.exit(0)
