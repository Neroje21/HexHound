import struct

ETH_P_IPV4 = 0x0800

PROTO_TCP = 6
PROTO_UDP = 17

ETHERTYPE_NAMES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "802.1Q VLAN"}
PROTOCOL_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6"}


# --- Full header parsers (every field, used by the packet inspector) ----------------

def parse_ethernet(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return {
        "dest_mac": get_mac_addr(dest_mac),
        "src_mac": get_mac_addr(src_mac),
        "ethertype": proto,
        "payload": data[14:],
    }


def parse_ipv4(data):
    """Parse an IPv4 header. Raises ValueError for anything that isn't a well-formed one.

    A non-zero frag_offset means the payload is a mid-datagram fragment with no
    transport header, so callers must not try to parse it as TCP/UDP.
    """
    if len(data) < 20:
        raise ValueError("truncated IPv4 header")

    version = data[0] >> 4
    header_length = (data[0] & 15) * 4
    if version != 4 or header_length < 20 or len(data) < header_length:
        raise ValueError("malformed IPv4 header")

    tos, total_length, ident, flags_frag, ttl, proto, checksum, src, target = struct.unpack('!1x B H H H B B H 4s 4s', data[:20])

    # total_length trims the zero padding Ethernet adds to short frames.
    end = total_length if total_length >= header_length else len(data)
    return {
        "version": version,
        "header_length": header_length,
        "dscp": tos >> 2,
        "ecn": tos & 3,
        "total_length": total_length,
        "identification": ident,
        "flag_reserved": (flags_frag >> 15) & 1,
        "flag_df": (flags_frag >> 14) & 1,
        "flag_mf": (flags_frag >> 13) & 1,
        "frag_offset": flags_frag & 0x1FFF,
        "ttl": ttl,
        "proto": proto,
        "checksum": checksum,
        "src": ipv4_format(src),
        "dest": ipv4_format(target),
        "options": data[20:header_length],
        "payload": data[header_length:end],
    }


def parse_tcp(data):
    if len(data) < 20:
        raise ValueError("truncated TCP header")

    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags, window, checksum, urgent = struct.unpack('!HHLLHHHH', data[:20])
    offset = (offset_reserved_flags >> 12) * 4
    if offset < 20 or len(data) < offset:
        raise ValueError("malformed TCP header")

    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "sequence": sequence,
        "acknowledgment": acknowledgment,
        "offset": offset,
        "flag_cwr": (offset_reserved_flags & 128) >> 7,
        "flag_ece": (offset_reserved_flags & 64) >> 6,
        "flag_urg": (offset_reserved_flags & 32) >> 5,
        "flag_ack": (offset_reserved_flags & 16) >> 4,
        "flag_psh": (offset_reserved_flags & 8) >> 3,
        "flag_rst": (offset_reserved_flags & 4) >> 2,
        "flag_syn": (offset_reserved_flags & 2) >> 1,
        "flag_fin": offset_reserved_flags & 1,
        "window": window,
        "checksum": checksum,
        "urgent_pointer": urgent,
        "options": data[20:offset],
        "payload": data[offset:],
    }


def parse_udp(data):
    if len(data) < 8:
        raise ValueError("truncated UDP header")

    # Header is src, dest, length, checksum; length covers header + payload.
    src_port, dest_port, length, checksum = struct.unpack('!HHHH', data[:8])
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "length": length,
        "checksum": checksum,
        "payload": data[8:],
    }


# --- Tuple-style unpackers (used by the capture loop) -------------------------------

def unpack_ethernet(data):
    """Return (dest_mac, src_mac, ethertype, payload). Ethertype is in host order (IPv4 == 0x0800)."""
    eth = parse_ethernet(data)
    return eth["dest_mac"], eth["src_mac"], eth["ethertype"], eth["payload"]


def unpack_ipv4(data):
    """Return (version, header_length, ttl, proto, src, target, frag_offset, payload)."""
    ip = parse_ipv4(data)
    return ip["version"], ip["header_length"], ip["ttl"], ip["proto"], ip["src"], ip["dest"], ip["frag_offset"], ip["payload"]


def unpack_tcp(data):
    t = parse_tcp(data)
    return (t["src_port"], t["dest_port"], t["sequence"], t["acknowledgment"], t["flag_urg"], t["flag_ack"],
            t["flag_psh"], t["flag_rst"], t["flag_syn"], t["flag_fin"], t["payload"])


def unpack_udp(data):
    u = parse_udp(data)
    return u["src_port"], u["dest_port"], u["length"], u["payload"]


def get_mac_addr(bytes_addr):
    return ':'.join(f'{b:02x}' for b in bytes_addr).upper()


def ipv4_format(addr):
    return '.'.join(map(str, addr))
