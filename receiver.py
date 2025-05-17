#!/usr/bin/env python3
import argparse
import base64
import socket
import requests
from scapy.all import sniff, IP, ICMP, Raw
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# Function to remove padding from decrypted data
def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

# Function to decrypt data using AES (CBC mode) with PBKDF2 key derivation
def decrypt_data(enc_data, password):
    salt = enc_data[:16]                 # First 16 bytes are the salt
    iv = enc_data[16:32]                 # Next 16 bytes are the initialization vector (IV)
    ct = enc_data[32:]                   # Remaining bytes are the ciphertext
    key = PBKDF2(password, salt, dkLen=32, count=100000)  # Generate key using PBKDF2
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct))     # Decrypt and unpad the ciphertext

# Function to retrieve local and public IP addresses
def get_ip_info():
    local_ip = socket.gethostbyname(socket.gethostname())
    try:
        public_ip = requests.get('https://api.ipify.org').text
    except:
        public_ip = 'N/A'
    return local_ip, public_ip

# Main function
def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-P", required=True, help="Logical port (tag) to filter")
    parser.add_argument("-R", required=True, help="Password for decryption")
    parser.add_argument("-o", "--output", required=True, help="Output filename")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    # Print local and public IP addresses
    print("[*] Local IP information:")
    local, public = get_ip_info()
    print(f"    ↪ Local: {local}")
    print(f"    ↪ Public: {public}")

    packets = {}

    # Handler function to process captured ICMP packets
    def handler(pkt):
        if ICMP in pkt and pkt[ICMP].type == 8:
            print(pkt.summary())
            if pkt.haslayer(Raw):
                raw_data = pkt[Raw].load
                print("[DEBUG] RAW payload:", raw_data)
                try:
                    payload = raw_data.decode(errors='ignore')
                    print("[DEBUG] Decoded payload:", payload)
                    # Check if payload starts with specified logical port (tag)
                    if not payload.startswith(args.P):
                        print("[DEBUG] Packet discarded (logical port not found)")
                        return
                    _, idx, content = payload.split(":", 2)
                    # Check for EOF indicator
                    if idx == "EOF":
                        print("[+] EOF received. Starting reconstruction...")
                        return True
                    packets[int(idx)] = content
                    if args.verbose:
                        print(f"[+] Received chunk {idx}")
                except Exception as e:
                    print("[!] Error parsing packet:", e)
            else:
                print("[DEBUG] No Raw layer in ICMP packet")

    # Start sniffing ICMP packets on eth0 interface
    sniff(filter="icmp", prn=handler, iface="eth0")

    # Reconstruct the binary stream from received packets
    bitstream = ''.join(packets[k] for k in sorted(packets.keys()))

    # Convert binary stream to bytes
    encrypted = bytes(int(bitstream[i:i+8], 2) for i in range(0, len(bitstream), 8))

    # Decrypt the received binary data
    decrypted_bin = decrypt_data(encrypted, args.R).decode()

    # Convert decrypted binary data back to original file content
    base64_bytes = bytes(int(decrypted_bin[i:i+8], 2) for i in range(0, len(decrypted_bin), 8))
    file_data = base64.b64decode(base64_bytes)

    # Save the reconstructed file
    with open(args.output, "wb") as f:
        f.write(file_data)

    print(f"[+] File successfully saved as: {args.output}")

if __name__ == "__main__":
    main()
