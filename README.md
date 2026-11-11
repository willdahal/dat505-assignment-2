# Ethical Hacking Assignment 2: CUPS Printer-Discovery Attack and Detection

Scapy-based attack and detection tools investigating the 2024 CUPS
vulnerability chain (CVE-2024-47176 / 47076 / 47175) in an isolated lab.

## Overview

cups-browsed listens on UDP port 631 and trusts unsolicited "new printer"
announcements, calling back to any advertised address without authentication.
This project demonstrates that insecure printer-discovery mechanism and builds
a detector that flags the malicious traffic.

Scope: discovery demonstration only (no PPD injection / RCE). Lab use on
isolated, authorized hosts only.

## Lab environment

| Role            | Host            | Notes                                  |
|-----------------|-----------------|----------------------------------------|
| Attacker        | 172.18.0.1      | Kali Linux, Python, Scapy, tcpdump     |
| Victim          | 172.18.0.2      | Vulhub CUPS container (cups-browsed)   |
| Virtual printer | 172.18.0.1:8632 | OpenPrinting ippserver                 |
| Bridge iface    | br-31afe2e83747 | Docker bridge network (172.18.0.0/16)  |

## Files

    dat505-assignment-2/
    |-- cups_attack.py      Scapy attack tool (rogue printer advertiser)
    |-- cups_detector.py    Scapy detection tool (live + pcap, CSV/JSON alerts)
    |-- requirements.txt    Python dependencies
    |-- README.md           This file
    |-- pcap_files/         Captured traffic (baseline, attack, mitigation)
    |-- evidence/           Detector alert exports (JSON) and logs

## Requirements

- Kali Linux (or Ubuntu) with Python 3
- Docker + Docker Compose (for the Vulhub victim)
- Python dependency: scapy (see requirements.txt)

Install:

    pip install -r requirements.txt
    # or: sudo apt install python3-scapy

## Setup

Start the vulnerable victim container (from the Vulhub CVE-2024-47177 dir):

    cd vulhub/cups-browsed/CVE-2024-47177
    sudo docker compose up -d

Start a virtual printer (optional, for legitimate discovery traffic):

    ippserver --no-dns-sd -v "Lab-Virtual-Printer" -p 8632

## Usage

### Attack tool: advertise a rogue printer

    sudo python3 cups_attack.py --target 172.18.0.2 --attacker 172.18.0.1 --port 8632 --pcap pcap_files/attack_sent.pcap

Options: --target, --attacker, --port, --count, --pcap, --printer-name,
--location, --info.

### Detection tool: monitor for attacks

Live capture (replace the interface name with your own, found via ip a):

    sudo python3 cups_detector.py --interface br-31afe2e83747 --json evidence/alerts.json

Offline pcap analysis:

    python3 cups_detector.py --read-pcap pcap_files/attack_discovery.pcap --csv alerts.csv

### Detections implemented

1. UNAUTH_ADVERTISEMENT: unsolicited UDP/631 printer announcement
   (normal discovery to the server is TCP).
2. INTRUDER_ALERT: advertisement from a host not on the known-hosts list.
3. REPEATED_DISCOVERY: rate/flood heuristic (many browse packets fast).
4. MALFORMED_FIELD: payload missing a valid ipp:// printer URI, or empty.
5. SUSPICIOUS_IPP: unexpected outbound IPP call-back to an unknown host.

## Experiments (summary)

| Experiment            | Result                                          |
|-----------------------|-------------------------------------------------|
| Normal baseline       | TCP/631 only, 0 alerts (no false positives)     |
| Rogue advertisement   | UNAUTH_ADVERTISEMENT raised                      |
| Spoofed source IP     | UNAUTH_ADVERTISEMENT + INTRUDER_ALERT raised     |
| Flood (10 packets)    | REPEATED_DISCOVERY raised after threshold        |
| Callback test         | Victim connected back to the attacker's printer  |
| After mitigation      | 0 alerts, attack inert                          |

## Mitigation

Stopping the vulnerable cups-browsed service (it runs as the container's
PID 1, so stopping the container disables it):

    sudo docker compose stop

After mitigation, re-running the attack produces no response from the victim
and the detector raises zero alerts, so the attack reaches no service.

## Ethical considerations

All testing was performed in an isolated Docker/VM lab on hosts owned by the
author. No public, university, or third-party systems were targeted. The tools
are for educational and defensive research only.
