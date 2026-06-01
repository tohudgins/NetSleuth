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
# Phase 1: scan localhost (works unprivileged via connect scan)
python main.py 127.0.0.1 -p 1-1024

# privileged SYN scan (needs sudo / Administrator)
sudo python main.py 127.0.0.1 -p 22,80,443
```

Run unprivileged and NetSleuth **warns and degrades** to a connect scan rather
than crashing.

## Practice legally

A `lab/` directory provides deliberately-open containers so you have a legal
target out of the box. See `lab/README.md`.

## Status

- [x] Phase 1 — Scanner (connect + SYN, banner grab, OS family heuristic)
- [ ] Phase 2 — Sniffer
- [ ] Phase 3 — Integration, analyzer, dashboard, JSON/HTML reports
- [ ] Phase 4 — Stretch (PCAP import, honeypot mode, CVE lookup)
