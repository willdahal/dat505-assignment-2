# Ethical Hacking Assignment 2 — CUPS Printer-Discovery Attack & Detection

Scapy-based attack and detection tools investigating the 2024 CUPS
vulnerability chain (CVE-2024-47176 / 47076 / 47175) in an isolated lab.

## Overview

`cups-browsed` listens on UDP port 631 and trusts unsolicited "new printer"
announcements, calling back to any advertised address without authentication.
This project demonstrates that insecure printer-discovery mechanism and builds
a detector that flags the malicious traffic.

**Scope:** discovery demonstration only (no PPD injection / RCE). Lab use on
isolated, authorized hosts only.

## Lab environment

| Role            | Host          | Notes                                   |
|-----------------|---------------|-----------------------------------------|
| Attacker        | 172.18.0.1    | Kali Linux, Python, Scapy, tcpdump      |
| Victim          | 172.18.0.2    | Vulhub CUPS container (cups-browsed)    |
| Virtual printer | 172.18.0.1:8632 | OpenPrinting ippserver                |
| Bridge iface    | br-31afe2e83747 | Docker bridge network (172.18.0.0/16) |

## Files
