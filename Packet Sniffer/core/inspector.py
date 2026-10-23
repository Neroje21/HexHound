import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime

from core import decoder

LIST_DEFAULT = 30

HELP = """\
Commands:
  <number>        show every detail of that packet (e.g. 12 or #12)
  l [text]        list the last %d packets, optionally only those containing <text>
                  (e.g. 'l 10.0.0.5', 'l :80', 'l SYN')
  h               show this help
  q               quit""" % LIST_DEFAULT


@dataclass
class CapturedPacket:
    number: int
    timestamp: float
    raw: bytes
    has_ethernet: bool
    summary: str


class PacketStore:
    """Keeps the most recent `capacity` packets so they can be inspected after capture stops."""

    def __init__(self, capacity=10000):
        self.packets = deque(maxlen=capacity)
        self.next_id = 1

    def add(self, raw, has_ethernet, summary):
        packet = CapturedPacket(self.next_id, time.time(), raw, has_ethernet, summary)
        self.next_id += 1
        self.packets.append(packet)
        return packet

    def get(self, number):
        # Numbers are consecutive and only ever evicted from the left, so this is a simple offset.
        if not self.packets:
            return None
        index = number - self.packets[0].number
        return self.packets[index] if 0 <= index < len(self.packets) else None


def hexdump(data, indent="  "):
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{offset:04x}  {hex_part:<47}  |{ascii_part}|")
    return "\n".join(lines)


def as_text(data):
    """Return the payload as readable text if it mostly is text, else None."""
    if not data:
        return None
    readable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    if readable / len(data) < 0.85:
        return None
    return "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "." for b in data)


def _field(label, value):
    return f"  {label:<18}: {value}"


def _options(options):
    return options.hex(" ") if options else "none"


def _tcp_flag_names(tcp):
    names = [name for name, key in (("CWR", "flag_cwr"), ("ECE", "flag_ece"), ("URG", "flag_urg"), ("ACK", "flag_ack"),
                                    ("PSH", "flag_psh"), ("RST", "flag_rst"), ("SYN", "flag_syn"), ("FIN", "flag_fin"))
             if tcp[key]]
    return " ".join(names) or "none"


def format_packet(packet):
    """Re-parse a stored packet and describe every header field plus the payload."""
    when = datetime.fromtimestamp(packet.timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    out = [
        "=" * 70,
        f" Packet #{packet.number}   captured {when}   {len(packet.raw)} bytes on the wire",
        "=" * 70,
    ]

    data = packet.raw
    if packet.has_ethernet:
        eth = decoder.parse_ethernet(data)
        name = decoder.ETHERTYPE_NAMES.get(eth["ethertype"], "unknown")
        out += ["", "[Ethernet]",
                _field("Destination MAC", eth["dest_mac"]),
                _field("Source MAC", eth["src_mac"]),
                _field("EtherType", f"0x{eth['ethertype']:04x} ({name})")]
        data = eth["payload"]
    else:
        out += ["", "[Ethernet]", "  not available (this capture starts at the IP layer)"]

    ip = decoder.parse_ipv4(data)
    proto_name = decoder.PROTOCOL_NAMES.get(ip["proto"], "unknown")
    ip_flags = [n for n, k in (("Reserved", "flag_reserved"), ("Don't Fragment", "flag_df"), ("More Fragments", "flag_mf")) if ip[k]]
    out += ["", "[IPv4]",
            _field("Version", ip["version"]),
            _field("Header length", f"{ip['header_length']} bytes"),
            _field("DSCP / ECN", f"{ip['dscp']} / {ip['ecn']}"),
            _field("Total length", f"{ip['total_length']} bytes"),
            _field("Identification", f"0x{ip['identification']:04x} ({ip['identification']})"),
            _field("Flags", ", ".join(ip_flags) or "none"),
            _field("Fragment offset", ip["frag_offset"]),
            _field("TTL", ip["ttl"]),
            _field("Protocol", f"{ip['proto']} ({proto_name})"),
            _field("Header checksum", f"0x{ip['checksum']:04x}"),
            _field("Source IP", ip["src"]),
            _field("Destination IP", ip["dest"]),
            _field("Options", _options(ip["options"]))]

    payload = ip["payload"]
    if ip["proto"] == decoder.PROTO_TCP and not ip["frag_offset"]:
        tcp = decoder.parse_tcp(payload)
        out += ["", "[TCP]",
                _field("Source port", tcp["src_port"]),
                _field("Destination port", tcp["dest_port"]),
                _field("Sequence number", tcp["sequence"]),
                _field("Acknowledgment", tcp["acknowledgment"]),
                _field("Header length", f"{tcp['offset']} bytes"),
                _field("Flags", _tcp_flag_names(tcp)),
                _field("Window size", tcp["window"]),
                _field("Checksum", f"0x{tcp['checksum']:04x}"),
                _field("Urgent pointer", tcp["urgent_pointer"]),
                _field("Options", _options(tcp["options"]))]
        payload = tcp["payload"]
    elif ip["proto"] == decoder.PROTO_UDP and not ip["frag_offset"]:
        udp = decoder.parse_udp(payload)
        out += ["", "[UDP]",
                _field("Source port", udp["src_port"]),
                _field("Destination port", udp["dest_port"]),
                _field("Length", f"{udp['length']} bytes (header + payload)"),
                _field("Checksum", f"0x{udp['checksum']:04x}")]
        payload = udp["payload"]

    out += ["", f"[Payload] {len(payload)} bytes"]
    if payload:
        text = as_text(payload)
        if text is not None:
            out += ["  --- as text ---"] + ["  " + line for line in text.splitlines()] + ["  --- hex dump ---"]
        out.append(hexdump(payload))
    else:
        out.append("  (empty)")
    out.append("")
    return "\n".join(out)


def _list(store, text):
    matches = [p for p in store.packets if not text or text.lower() in f"#{p.number} {p.summary}".lower()]
    if not matches:
        print("  no matching packets")
        return
    for p in matches[-LIST_DEFAULT:]:
        print(f"  #{p.number} {p.summary}")
    if len(matches) > LIST_DEFAULT:
        print(f"  ... {len(matches) - LIST_DEFAULT} older match(es) not shown, narrow it down with 'l <text>'")


def interactive_viewer(store):
    """Prompt for packet numbers and print everything inside the chosen packet."""
    if not store.packets:
        print("[*] No TCP/UDP packets were stored, nothing to inspect.")
        return

    first, last = store.packets[0].number, store.packets[-1].number
    print(f"\n[*] Packet inspector: {len(store.packets)} packets stored (#{first} to #{last}).")
    print(HELP)

    while True:
        try:
            cmd = input("\nhexhound> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        word, _, rest = cmd.partition(" ")
        word = word.lstrip("#").lower()

        if not cmd:
            continue
        if word in ("q", "quit", "exit"):
            break
        if word in ("h", "help", "?"):
            print(HELP)
        elif word in ("l", "list"):
            _list(store, rest.strip())
        elif word.isdigit():
            packet = store.get(int(word))
            if packet is None:
                print(f"  packet #{word} is not available (stored: #{first} to #{last})")
            else:
                print(format_packet(packet))
        else:
            print("  unknown command, type 'h' for help")
