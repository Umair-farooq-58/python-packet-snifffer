# Python Packet Sniffer 🐍📡

An **educational Python project** to capture and analyze network packets in real time.  
Built purely for learning purposes — helps understand **Ethernet, IPv4, TCP, UDP, and ICMP protocols**.

> ⚠️ **Note:** Only run on your own machine/network. Requires Linux and root privileges. Do **not** use on unauthorized networks.


##  Features

- **Layer 2 Decoding:** Parses Ethernet Frames to extract MAC addresses and protocols.
- **Layer 3 Decoding:** Unpacks IPv4 packets, including TTL, protocol IDs, and IP addresses.
- **Layer 4 Support:** Detailed breakdown of:
  - **TCP:** Port numbers, sequence numbers, and all control flags (SYN, ACK, FIN, etc.).
  - **UDP:** Port numbers and segment size.
  - **ICMP:** Type, code, and checksum.
- **Human Readable:** Color-coded terminal output for easy debugging and data visualization.
- **Data Inspection:** Formatted multi-line hex/string data output for payload analysis.

##  Prerequisites

To run this sniffer, you need:
- **Python 3.x**
- **Root/Administrator Privileges:** Raw sockets require elevated permissions to access the network interface directly.
- **Linux/Unix Environment:** This script uses `AF_PACKET`, which is specific to Linux. (For Windows/macOS, libraries like Scapy or structural changes are usually required).

##  Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/your-username/network-packet-sniffer.git](https://github.com/your-username/network-packet-sniffer.git)
   cd network-packet-sniffer
   ```
2. **No External Dependancies required,** the script uses standard python libraries (Socket, struct, textwrap)
3. **Usage**
   Run with sudo:
   ```bash
   sudo python3 network_packet_sniffer.py
   ```

## Example Output:
```bash
Ethernet Frame:
     - Destination: AA:BB:CC:DD:EE:FF, Source: 11:22:33:44:55:66, Protocol: 8
     - IPv4 Packet:
         - Version:4, Header Length:20, TTL:64
         - Protocol:6, Source:192.168.1.5, Target:142.250.190.46
     - TCP Segment:
         - Source Port:54321, Destination Port:443
         - Sequence:123456789, Acknowledgment:987654321
         - Flags:
             - URG:0, ACK:1, PSH:0, RST:0, SYN:0, FIN:0
         - Data:
             \x17\x03\x03\x00\x2b\x00\x00\x00...
```

## How it works:
1. Raw Sockets: The script opens a socket with socket.AF_PACKET to capture every packet flowing through the network card, regardless of the protocol.
2. Struct Unpacking: It uses the struct module to unpack binary data based on the standard network protocol headers (Big-Endian).
3. Bit Manipulation: Extracts specific flags (like TCP SYN/ACK) using bit-shifting and masking.
4. Formatting: The textwrap and custom color constants ensure the data is readable in a standard terminal.

## Disclaimer
This tool is for educational and ethical security testing purposes only. Using this tool to capture traffic on a network you do not have permission to monitor is illegal and unethical.

## Author
Umair Farooq
   

