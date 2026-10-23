import time
from collections import defaultdict

MAX_TRACKED_FLOWS = 10000


class SecurityAnalyzer:
    def __init__(self):
        self.connection_attempts = {}
        self.port_scan_threshold = 15
        self.time_window = 10
        self.insecure_ports = {21: "FTP", 23: "Telnet", 80: "HTTP"}
        # Bytes, so payloads are matched as-is without decoding every packet.
        self.sensitive_keywords = [b"password=", b"pwd=", b"user=", b"login", b"admin", b"auth"]

        self._last_prune = time.time()
        self._warned_flows = set()
        self._flagged = set()

    def detect_port_scan(self, src_ip, dest_ip, dest_port):
        """Record one connection attempt (call for TCP SYN-only packets) and alert on a scan.

        Counting every packet would flag servers replying to a client's ephemeral
        ports, so callers should only feed this new-connection attempts.
        """
        current_time = time.time()
        self._prune(current_time)

        record = self.connection_attempts.get(src_ip)
        if record is None or current_time - record["timestamp"] > self.time_window:
            record = {"targets": defaultdict(set), "timestamp": current_time}
            self.connection_attempts[src_ip] = record

        ports = record["targets"][dest_ip]
        ports.add(dest_port)

        if len(ports) > self.port_scan_threshold:
            print("\n[!!!] SECURITY ALERT: Potential Port Scan Detected!")
            print(f"      Source IP {src_ip} has scanned {len(ports)} ports on {dest_ip}.")
            ports.clear()

    def inspect_payload(self, payload, src_ip, src_port, dest_ip, dest_port):
        if not payload:
            return

        flow = tuple(sorted([(src_ip, src_port), (dest_ip, dest_port)]))
        if len(self._warned_flows) > MAX_TRACKED_FLOWS:
            self._warned_flows.clear()
        if len(self._flagged) > MAX_TRACKED_FLOWS:
            self._flagged.clear()

        # Alert once per flow / keyword, otherwise every packet of a connection repeats it.
        port = dest_port if dest_port in self.insecure_ports else src_port
        if port in self.insecure_ports and flow not in self._warned_flows:
            self._warned_flows.add(flow)
            print(f"\n[!] WARNING: Unencrypted {self.insecure_ports[port]} traffic detected "
                  f"({src_ip}:{src_port} <-> {dest_ip}:{dest_port}).")

        lowered = payload.lower()
        matched = [k for k in self.sensitive_keywords if k in lowered and (flow, k) not in self._flagged]
        if matched:
            self._flagged.update((flow, k) for k in matched)
            print("\n[!!!] CRITICAL: Potential sensitive data (Cleartext) found in payload!")
            print(f"      Flow: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")
            print(f"      Matched Keyword(s): {', '.join(repr(k.decode()) for k in matched)}")

    def _prune(self, current_time):
        """Drop scan records for sources that have been quiet longer than the window."""
        if current_time - self._last_prune < self.time_window:
            return
        self._last_prune = current_time
        stale = [ip for ip, rec in self.connection_attempts.items()
                 if current_time - rec["timestamp"] > self.time_window]
        for ip in stale:
            del self.connection_attempts[ip]
