#!/usr/bin/env python3
"""
cups_detector.py - CUPS / cups-browsed network attack detector
================================================================
DAT505 Ethical Hacking - CUPS printer-discovery assignment.

Defensive monitoring tool. Watches network traffic (live or from a
saved .pcap) for the behaviour that the CVE-2024-47176/47076/47175
chain abuses: unsolicited "I'm a new printer" announcements sent to
cups-browsed on UDP/631, and the suspicious call-backs that follow.
It does NOT attack anything. It only observes and raises alerts.

NORMAL (your captured baseline): CUPS traffic is TCP, port 631,
client -> server, with a handshake (SYN/SYN-ACK/ACK) and teardown.
ATTACK: UDP to port 631 = a cups-browsed browse announcement, sent
unsolicited, often repeated / from an odd source / malformed.

Four detections required by the brief:
  1. Unauthorized printer advertisements  (UDP/631 browse packets)
  2. Suspicious IPP connections           (odd call-backs / ports)
  3. Repeated / abnormal discovery        (rate / flood heuristic)
  4. Malformed or unexpected fields       (payload sanity checks)

Modes:  --read-pcap FILE  (offline)   |   --interface IFACE  (live)
Output: console alerts, plus optional --csv / --json export.

Examples:
  sudo python3 cups_detector.py --interface br-31afe2e83747 --json alerts.json
  python3 cups_detector.py --read-pcap pcap_files/attack.pcap --csv alerts.csv
"""

import argparse
import csv
import json
import sys
import time
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff, rdpcap, IP, IPv6, UDP, TCP, Raw
except ImportError:
    sys.exit("scapy is required:  sudo apt install python3-scapy")

# --- Configuration (tweak for your lab; defaults match the brief) ---
CUPS_PORT = 631
ALLOWLIST = []            # e.g. ["172.18.0.50"] ; empty = all adverts are unauthorised
RATE_LIMIT = 5            # >N browse packets from one source...
RATE_WINDOW = 10.0        # ...within this many seconds = flood
EXPECTED_URI_MARKERS = (b"ipp://", b"ipps://")


class AlertSink:
    """Collects alerts, prints them, exports to CSV/JSON."""
    def __init__(self):
        self.alerts = []

    def add(self, category, severity, src, dst, detail, raw_summary=""):
        alert = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "category": category, "severity": severity,
            "src": src, "dst": dst, "detail": detail, "packet": raw_summary,
        }
        self.alerts.append(alert)
        print(f"[{severity:<8}] {category}: {detail}  ({src} -> {dst})")

    def export_csv(self, path):
        if not self.alerts:
            print(f"[info] no alerts to write to {path}")
            return
        with open(path, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(self.alerts[0].keys()))
            w.writeheader()
            w.writerows(self.alerts)
        print(f"[info] wrote {len(self.alerts)} alerts to {path}")

    def export_json(self, path):
        with open(path, "w") as fh:
            json.dump(self.alerts, fh, indent=2)
        print(f"[info] wrote {len(self.alerts)} alerts to {path}")


class CupsDetector:
    def __init__(self, sink, allowlist, rate_limit, rate_window):
        self.sink = sink
        self.allowlist = set(allowlist)
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self.recent = defaultdict(deque)
        self.stats = defaultdict(int)

    @staticmethod
    def _ip_pair(pkt):
        if IP in pkt:
            return pkt[IP].src, pkt[IP].dst
        if IPv6 in pkt:
            return pkt[IPv6].src, pkt[IPv6].dst
        return None, None

    @staticmethod
    def _payload(pkt):
        return bytes(pkt[Raw].load) if Raw in pkt else b""

    def inspect(self, pkt):
        src, dst = self._ip_pair(pkt)
        if src is None:
            return
        if UDP in pkt and CUPS_PORT in (pkt[UDP].dport, pkt[UDP].sport):
            self._udp_browse(pkt, src, dst)
        elif TCP in pkt and CUPS_PORT in (pkt[TCP].dport, pkt[TCP].sport):
            self._tcp_ipp(pkt, src, dst)

    def _udp_browse(self, pkt, src, dst):
        self.stats["udp_browse_seen"] += 1
        payload = self._payload(pkt)

        # Detection 1: unauthorized printer advertisement
        if not self.allowlist or src not in self.allowlist:
            self.sink.add(
                "UNAUTH_ADVERTISEMENT", "HIGH", src, dst,
                "Unsolicited UDP/631 printer announcement "
                "(normal discovery to the server is TCP)",
                payload[:120].decode("latin-1", "replace"))

        # Detection 1b: intruder check - is the source a known lab host?
        KNOWN_HOSTS = ("172.18.0.1", "172.18.0.2")
        if src not in KNOWN_HOSTS:
            self.sink.add(
                "INTRUDER_ALERT", "HIGH", src, dst,
                f"Unauthorized host {src} is advertising a printer "
                f"- possible attacker (not a known lab host)",
                payload[:120].decode("latin-1", "replace"))

        # Detection 4: malformed / unexpected fields
        if payload and not any(m in payload for m in EXPECTED_URI_MARKERS):
            self.sink.add(
                "MALFORMED_FIELD", "MEDIUM", src, dst,
                "UDP/631 payload has no ipp:// printer URI "
                "(hand-crafted / unexpected packet)",
                payload[:120].decode("latin-1", "replace"))
        if not payload:
            self.sink.add("MALFORMED_FIELD", "LOW", src, dst,
                          "UDP/631 packet with empty payload")

        # Detection 3: repeated / abnormal rate
        now = pkt.time if hasattr(pkt, "time") else time.time()
        win = self.recent[src]
        win.append(now)
        while win and now - win[0] > self.rate_window:
            win.popleft()
        if len(win) > self.rate_limit:
            self.sink.add(
                "REPEATED_DISCOVERY", "HIGH", src, dst,
                f"{len(win)} browse packets in {self.rate_window:.0f}s "
                f"from {src} (flood / repeated spoofing)")

    def _tcp_ipp(self, pkt, src, dst):
        self.stats["tcp_ipp_seen"] += 1
        flags = pkt[TCP].flags
        is_syn = (flags & 0x02) and not (flags & 0x10)   # SYN without ACK
        if is_syn and self.allowlist and dst not in self.allowlist:
            self.sink.add(
                "SUSPICIOUS_IPP", "MEDIUM", src, dst,
                f"New IPP/TCP connection to non-allowlisted host "
                f"{dst}:{pkt[TCP].dport} (possible insecure call-back)")

    def summary(self):
        print("\n--- detector summary ---")
        print(f"UDP/631 browse packets inspected : {self.stats['udp_browse_seen']}")
        print(f"TCP/631 IPP packets inspected    : {self.stats['tcp_ipp_seen']}")
        print(f"total alerts raised              : {len(self.sink.alerts)}")


def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Detect CUPS/cups-browsed printer-discovery attacks.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--interface", "-i", help="network interface for live capture")
    src.add_argument("--read-pcap", "-r", help="analyse an existing .pcap file")
    p.add_argument("--csv", help="write alerts to this CSV file")
    p.add_argument("--json", help="write alerts to this JSON file")
    p.add_argument("--count", "-c", type=int, default=0,
                   help="live mode: stop after N packets (0 = until Ctrl-C)")
    p.add_argument("--allow", action="append", default=list(ALLOWLIST),
                   metavar="IP", help="allowlisted legitimate printer source (repeatable)")
    p.add_argument("--rate-limit", type=int, default=RATE_LIMIT,
                   help=f"browse packets per window before flood alert (default {RATE_LIMIT})")
    p.add_argument("--rate-window", type=float, default=RATE_WINDOW,
                   help=f"rate window in seconds (default {RATE_WINDOW})")
    return p


def main():
    args = build_arg_parser().parse_args()
    sink = AlertSink()
    detector = CupsDetector(sink, args.allow, args.rate_limit, args.rate_window)
    bpf = f"port {CUPS_PORT}"

    if args.read_pcap:
        print(f"[*] reading {args.read_pcap} ...")
        for pkt in rdpcap(args.read_pcap):
            detector.inspect(pkt)
    else:
        print(f"[*] live capture on {args.interface} (Ctrl-C to stop) ...")
        try:
            sniff(iface=args.interface, filter=bpf, prn=detector.inspect,
                  count=args.count, store=False)
        except PermissionError:
            sys.exit("permission denied - run with sudo for live capture")
        except KeyboardInterrupt:
            pass

    detector.summary()
    if args.csv:
        sink.export_csv(args.csv)
    if args.json:
        sink.export_json(args.json)


if __name__ == "__main__":
    main()
