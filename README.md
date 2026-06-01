# NetSleuth

> ## ⚠️ Authorized use only
> NetSleuth is a **defensive, educational** tool. Run it **only** against systems
> you own or have **explicit written permission** to test. Port scanning and
> packet capture of networks you don't control may be illegal. All examples
> default to `127.0.0.1` or the bundled `lab/` network. You are responsible for
> how you use this tool.

NetSleuth integrates two from-scratch modules:

1. **Scanner** — an Nmap-style TCP/UDP port scanner with banner grabbing and an
   OS *family heuristic* (a coarse TTL/window-size best guess — **not** real OS
   fingerprinting).
2. **Sniffer** — a Wireshark-style live packet capture + protocol analyzer.

The scanning and capture logic is implemented ourselves with `socket` and
`scapy` — NetSleuth does **not** wrap the `nmap` or `tshark` binaries.

## Install

```bash
pip install -e .
# or: pip install -r requirements.txt
```

## Usage

```bash
# scan localhost (works unprivileged via connect scan)
python main.py 127.0.0.1 -p 1-1024

# privileged SYN scan (needs sudo / Administrator)
sudo python main.py 127.0.0.1 -p 22,80,443

# UDP scan
python main.py 127.0.0.1 -p 53,123 --udp

# live packet capture for 10s (needs sudo / Administrator)
sudo python main.py --sniff --duration 10
sudo python main.py --sniff --filter "tcp port 80" --count 50 --hex

# integrated: scan, then sniff the open ports behind a live dashboard,
# with anomaly flags + a JSON/HTML report (written to reports/)
sudo python main.py 127.0.0.1 --scan-then-sniff --duration 15

# write a report from any mode
python main.py 127.0.0.1 -p 1-1024 --report-dir reports
```

Run unprivileged and NetSleuth **warns and degrades** — it falls back to a TCP
connect scan and skips live capture rather than crashing (the scan still runs
and a scan-only report is still written).

## Practice legally

A `lab/` directory provides deliberately-open containers so you have a legal
target out of the box. See `lab/README.md`.

## Status

- [x] Phase 1 — Scanner (connect + SYN, UDP, banner grab, OS family heuristic)
- [x] Phase 2 — Sniffer (threaded scapy capture, TCP/UDP/ICMP/ARP/DNS decode, per-IP stats)
- [x] Phase 3 — Integration (--scan-then-sniff), analyzer anomaly flags, live dashboard, JSON/HTML reports
- [ ] Phase 4 — Stretch (PCAP import, honeypot mode, CVE lookup)
