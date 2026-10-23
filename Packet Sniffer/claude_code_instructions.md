# NetPeek - Network Traffic Analyzer Implementation Guide
**Target Agent:** Claude Code (or equivalent AI coding assistant)
**Task:** Scaffold and implement a custom Python network traffic analyzer from scratch.

## 1. Context & Constraints
You are a senior systems engineer building a low-level network packet sniffer.
*   **Language:** Python 3.10+
*   **OS:** Linux / macOS (Must use standard Unix raw sockets).
*   **CRITICAL CONSTRAINT:** Do **NOT** use `scapy`, `pyshark`, or any third-party packet parsing libraries. You must use Python's built-in `socket` and `struct` modules to manually unpack byte frames.
*   **Goal:** Read live Ethernet frames, parse IPv4 and TCP/UDP headers, and run basic security heuristics (port scan detection, cleartext analysis) on the payloads.

## 2. Directory Structure
Please create the following exact directory structure in the current working directory:

```text
.
├── main.py
└── core/
    ├── __init__.py
    ├── decoder.py
    └── analyzer.py
```

## 3. Implementation Steps

Please create the files listed below with the exact provided code.

### Task 1: Create `core/decoder.py`
This file handles the byte-level unpacking of network headers using `struct`. Create it and insert this exact code:

```python
import struct
import socket
import textwrap

def unpack_ethernet(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def unpack_ipv4(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4_format(src), ipv4_format(target), data[header_length:]

def ipv4_format(addr):
    return '.'.join(map(str, addr))

def unpack_tcp(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def unpack_udp(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]
```

### Task 2: Create `core/analyzer.py`
This file contains the security heuristics. Create it and insert this code:

```python
import time
from collections import defaultdict

class SecurityAnalyzer:
    def __init__(self):
        self.connection_attempts = defaultdict(lambda: {"targets": defaultdict(set), "timestamp": time.time()})
        self.port_scan_threshold = 15
        self.time_window = 10
        self.insecure_ports = {21: "FTP", 23: "Telnet", 80: "HTTP"}
        self.sensitive_keywords = ["password=", "pwd=", "user=", "login", "admin", "auth"]

    def detect_port_scan(self, src_ip, dest_ip, dest_port):
        current_time = time.time()
        record = self.connection_attempts[src_ip]

        if current_time - record["timestamp"] > self.time_window:
            record["targets"].clear()
            record["timestamp"] = current_time

        record["targets"][dest_ip].add(dest_port)

        if len(record["targets"][dest_ip]) > self.port_scan_threshold:
            print(f"\n[!!!] SECURITY ALERT: Potential Port Scan Detected!")
            print(f"      Source IP {src_ip} has scanned {len(record['targets'][dest_ip])} ports on {dest_ip}.")
            record["targets"][dest_ip].clear() 

    def inspect_payload(self, payload, src_port, dest_port):
        if not payload:
            return

        if dest_port in self.insecure_ports or src_port in self.insecure_ports:
            port = dest_port if dest_port in self.insecure_ports else src_port
            print(f"\n[!] WARNING: Unencrypted {self.insecure_ports[port]} traffic detected.")

        try:
            decoded_payload = payload.decode('utf-8', errors='ignore').lower()
            for keyword in self.sensitive_keywords:
                if keyword in decoded_payload:
                    print(f"\n[!!!] CRITICAL: Potential sensitive data (Cleartext) found in payload!")
                    print(f"      Matched Keyword: '{keyword}'")
                    break
        except Exception:
            pass
```

### Task 3: Create `core/__init__.py`
Create this as an empty file to ensure Python treats the `core` directory as a module.

### Task 4: Create `main.py`
This is the orchestrator that sets up the raw socket and runs the main loop. Create it and insert this code:

```python
import socket
import sys
import os
import argparse
from core import decoder
from core.analyzer import SecurityAnalyzer

def main():
    if os.geteuid() != 0:
        print("Error: NetPeek requires root privileges to bind to raw sockets.")
        print("Please run this script using 'sudo'.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="NetPeek - Custom Network Traffic Analyzer")
    parser.add_argument("-i", "--interface", help="Network interface to bind to (e.g., eth0). Default captures all.", default="all")
    args = parser.parse_args()

    print(f"[*] Starting NetPeek on interface: {args.interface}")
    print("[*] Listening for traffic. Press Ctrl+C to stop...\n")

    analyzer = SecurityAnalyzer()
    
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except socket.error as e:
        print(f"Socket could not be created. Error Code: {e}")
        sys.exit(1)

    packets_captured = 0
    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            packets_captured += 1
            dest_mac, src_mac, eth_proto, data = decoder.unpack_ethernet(raw_data)
            
            if eth_proto == 8:
                version, header_length, ttl, proto, src_ip, target_ip, data = decoder.unpack_ipv4(data)
                
                if proto == 6:
                    src_port, dest_port, seq, ack, urg, ack_flag, psh, rst, syn, fin, data = decoder.unpack_tcp(data)
                    print(f"TCP | {src_ip}:{src_port} -> {target_ip}:{dest_port}")
                    analyzer.detect_port_scan(src_ip, target_ip, dest_port)
                    analyzer.inspect_payload(data, src_port, dest_port)
                elif proto == 17:
                    src_port, dest_port, size, data = decoder.unpack_udp(data)
                    print(f"UDP | {src_ip}:{src_port} -> {target_ip}:{dest_port} | Size: {size}")
                    analyzer.detect_port_scan(src_ip, target_ip, dest_port)
                    analyzer.inspect_payload(data, src_port, dest_port)

    except KeyboardInterrupt:
        print("\n\n[*] Stopping NetPeek Capture...")
        print(f"[*] Total Packets Processed: {packets_captured}")
        sys.exit(0)

if __name__ == "__main__":
    main()
```

### Task 5: Verification
After generating the files:
1. Verify that `main.py` successfully imports from `core.decoder` and `core.analyzer`.
2. Do not attempt to execute `main.py` directly in the agent environment, as it requires root privileges and network hardware access which the sandbox likely restricts.
3. Report back to the user that the project has been successfully scaffolded and is ready for them to run locally via `sudo python3 main.py`.