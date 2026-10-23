import argparse
import os
import socket
import struct
import sys

from core import decoder
from core.analyzer import SecurityAnalyzer
from core.inspector import PacketStore, interactive_viewer


def is_privileged():
    if sys.platform == "win32":
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def default_local_ip():
    """IP of the adapter that routes to the internet (no packet is actually sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            return probe.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())


def open_capture_socket(interface):
    """Open a raw capture socket. Returns (socket, has_ethernet_header)."""
    if hasattr(socket, "AF_PACKET"):
        # Linux: raw Ethernet frames. 0x0003 == ETH_P_ALL.
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if interface != "all":
            conn.bind((interface, 0))
        return conn, True

    if sys.platform == "win32":
        # Windows has no AF_PACKET. A raw IP socket in "receive all" mode sees every
        # IPv4 packet on one adapter, starting at the IP header (no Ethernet header).
        host = default_local_ip() if interface == "all" else interface
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((host, 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        print(f"[*] Capturing on adapter with IP {host}")
        return conn, False

    raise OSError("raw packet capture is only supported on Linux (AF_PACKET) and Windows; "
                  "macOS exposes packets through BPF (/dev/bpf*) instead.")


def tcp_flag_names(urg, ack, psh, rst, syn, fin):
    names = [n for n, on in (("SYN", syn), ("ACK", ack), ("FIN", fin), ("RST", rst), ("PSH", psh), ("URG", urg)) if on]
    return ",".join(names) or "-"


def process_frame(raw_data, has_ethernet, analyzer, packet_id):
    """Decode one captured frame, print it as #packet_id and run the heuristics.

    Returns the one-line summary for TCP/UDP packets, or None for anything that is
    skipped. Raises ValueError/struct.error on truncated or malformed frames.
    """
    if has_ethernet:
        _dest_mac, _src_mac, eth_proto, data = decoder.unpack_ethernet(raw_data)
        if eth_proto != decoder.ETH_P_IPV4:
            return None
    else:
        data = raw_data

    _version, _header_length, _ttl, proto, src_ip, target_ip, frag_offset, data = decoder.unpack_ipv4(data)
    if frag_offset:
        return None  # mid-datagram fragment: no transport header to parse

    if proto == decoder.PROTO_TCP:
        src_port, dest_port, _seq, _ack, urg, ack, psh, rst, syn, fin, data = decoder.unpack_tcp(data)
        flags = tcp_flag_names(urg, ack, psh, rst, syn, fin)
        summary = f"TCP | {src_ip}:{src_port} -> {target_ip}:{dest_port} | Flags: {flags}"
        print(f"#{packet_id} {summary}")
        # Only bare SYNs are new connection attempts; counting every packet would
        # make a server answering a client look like it is scanning the client.
        if syn and not ack:
            analyzer.detect_port_scan(src_ip, target_ip, dest_port)
    elif proto == decoder.PROTO_UDP:
        src_port, dest_port, size, data = decoder.unpack_udp(data)
        summary = f"UDP | {src_ip}:{src_port} -> {target_ip}:{dest_port} | Size: {size}"
        print(f"#{packet_id} {summary}")
        # No port-scan detection for UDP: without tracking replies, a request and a
        # response look the same and servers would be flagged as scanners.
    else:
        return None

    analyzer.inspect_payload(data, src_ip, src_port, target_ip, dest_port)
    return summary


def main():
    parser = argparse.ArgumentParser(description="HexHound - Custom Network Traffic Analyzer")
    parser.add_argument("-i", "--interface",
                        help="Interface to bind to (e.g., eth0). On Windows, the IP address of the adapter. "
                             "Default captures all (Linux) or the main adapter (Windows).",
                        default="all")
    parser.add_argument("-b", "--buffer", type=int, default=10000,
                        help="Number of most recent TCP/UDP packets to keep for inspection after Ctrl+C (default 10000).")
    args = parser.parse_args()

    if args.buffer < 1:
        parser.error("--buffer must be at least 1")

    if not is_privileged():
        if sys.platform == "win32":
            print("Error: HexHound requires Administrator privileges to open raw sockets.")
            print("Please run this script from an elevated terminal.")
        else:
            print("Error: HexHound requires root privileges to bind to raw sockets.")
            print("Please run this script using 'sudo'.")
        sys.exit(1)

    print(f"[*] Starting HexHound on interface: {args.interface}")

    analyzer = SecurityAnalyzer()

    try:
        conn, has_ethernet = open_capture_socket(args.interface)
    except OSError as e:
        print(f"Socket could not be created. Error: {e}")
        sys.exit(1)

    print("[*] Listening for traffic. Press Ctrl+C to stop...\n")

    store = PacketStore(args.buffer)
    packets_captured = 0
    packets_skipped = 0
    try:
        while True:
            raw_data, _addr = conn.recvfrom(65535)
            packets_captured += 1
            try:
                summary = process_frame(raw_data, has_ethernet, analyzer, store.next_id)
            except (ValueError, struct.error):
                packets_skipped += 1  # truncated or malformed packet
                continue
            if summary is not None:
                store.add(raw_data, has_ethernet, summary)
    except KeyboardInterrupt:
        print("\n\n[*] Stopping HexHound Capture...")
        print(f"[*] Total Packets Processed: {packets_captured} ({packets_skipped} malformed/truncated)")
    finally:
        if not has_ethernet:
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        conn.close()

    interactive_viewer(store)


if __name__ == "__main__":
    main()
