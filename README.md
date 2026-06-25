# NetSleuth

[![CI](https://github.com/tohudgins/NetSleuth/actions/workflows/ci.yml/badge.svg)](https://github.com/tohudgins/NetSleuth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

> ## ⚠️ Authorized use only
> NetSleuth is a **defensive, educational** tool. Run it **only** against systems
> you own or have **explicit written permission** to test. Port scanning and
> packet capture of networks you don't control may be illegal. Every example
> defaults to `127.0.0.1` or the bundled `lab/` network. You are responsible for
> how you use it.

## What it is

NetSleuth is a network-security toolkit that **reimplements, from scratch, the
core of `nmap` and Wireshark** — and wires them into one analysis pipeline. It
has three pillars:

1. **Port scanner** — TCP (connect / SYN / FIN / NULL / Xmas) and UDP scanning
   over IPv4 and IPv6, with banner grabbing and an OS *family heuristic*.
2. **Packet sniffer + analyzer** — live capture and protocol decode feeding an
   anomaly-detection engine (port scans, floods, ARP spoofing, DNS tunneling,
   C2 beaconing).
3. **Vulnerability mapper** — matches discovered service versions to NVD CVEs.

The point of the project is the *first word*: **from scratch.** The scanner
speaks TCP with raw `socket` calls and crafts SYN packets with `scapy`; the
sniffer decodes layers itself. It never shells out to the `nmap` or `tshark`
binaries — `scapy` is used as a packet library we compose, not a tool we
orchestrate. The handshake logic, the packet decode, even the hex dump are ours.

The three pillars share one engine: a scan can auto-trigger focused sniffing of
a target's open ports, and every mode feeds the same analyzer, live dashboard,
and JSON/HTML report.

## Install

```bash
pip install -e .
pip install -e ".[geoip]"   # optional: GeoIP/ASN enrichment (you supply the DB)
```

Python 3.10+. Live SYN scan and packet capture need root (Linux/macOS) or
Administrator (Windows); everything else — connect scans, PCAP analysis, the web
UI — runs unprivileged. Run unprivileged and NetSleuth **warns and degrades**
(falls back to a connect scan, skips live capture) rather than crashing.

## Usage

The fastest way in is the **web dashboard** — a loopback-only browser UI for
scanning, host discovery, PCAP analysis, and live capture with charts and a
packet hexdump:

```bash
netsleuth-web          # → http://127.0.0.1:8765
sudo netsleuth-web     # also enables the Live capture tab (needs root)
```

The CLI exposes the same engine:

```bash
# scan (connect scan unprivileged; SYN scan with sudo). CIDR, comma-lists, IPv6 all work.
python main.py 127.0.0.1 -p 1-1024
sudo python main.py 192.168.1.0/28 -p 22,80,443

# stealth + UDP scans, timing templates (-T0 paranoid … -T5 insane)
sudo python main.py 127.0.0.1 -p 1-1024 --scan-type xmas -T2
python main.py 127.0.0.1 -p 53,123,161 --udp        # real DNS/NTP/SNMP probes

# discover live hosts on a subnet (ARP sweep w/ sudo, else TCP-ping)
sudo python main.py 192.168.1.0/24 --discover

# live capture → optionally save a .pcap for Wireshark / re-analysis
sudo python main.py --sniff --duration 30 --write-pcap capture.pcap

# analyze a saved capture offline — the legal way to run detection on real
# adversarial traffic (no privileges needed)
python main.py --pcap capture.pcap --report-dir reports

# integrated: scan, then sniff the open ports behind a live dashboard + report
sudo python main.py 127.0.0.1 --scan-then-sniff --duration 15
```

Other capabilities, each opt-in: `--save`/`--diff` persist runs to SQLite and
answer *"what changed since last time?"* (a new port, a moved gateway MAC);
`--cve` maps banners to NVD CVEs (CPE-accurate, cached, fails soft offline);
`--alert-jsonl`/`--alert-webhook`/`--alert-syslog` forward anomaly and
ARP-spoofing alerts to a SIEM or honeypot.

## Run with Docker

The repo ships a [`Dockerfile`](Dockerfile) so you can run the CLI or web UI
without a local Python install. Build once:

```bash
docker build -t netsleuth .
```

**CLI scans** — the default entrypoint is the `netsleuth` CLI:

```bash
# connect scan (unprivileged). NOTE: 127.0.0.1 is the CONTAINER's loopback —
# to scan services on your host, target host.docker.internal instead.
docker run --rm netsleuth host.docker.internal -p 1-1024 --connect

# SYN scan / live capture need raw-socket capabilities
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN netsleuth <target> --sniff
```

**Web UI** — the server **binds to `127.0.0.1` only by design** and refuses any
non-loopback bind, so it needs the host's network namespace rather than a
published port. This works on **Linux**:

```bash
docker run --rm --network host --entrypoint netsleuth-web netsleuth
# → browse http://127.0.0.1:8765
```

> **macOS / Windows (Docker Desktop):** `--network host` shares the Docker *VM's*
> loopback, not your machine's, so the web UI is unreachable from your browser
> (and the server refuses to bind `0.0.0.0`, so port-publishing won't help).
> Run the dashboard natively instead — it needs no privileges:
>
> ```bash
> pip install -e . && netsleuth-web   # → http://127.0.0.1:8765
> ```

## Architecture

```
 FRONT ENDS    cli.py (argparse + rich)      web.py (Flask + SSE browser UI)
                          └──────────────┬──────────────┘
                                         │  (both wire the same modules)
 ─────────────────────────────────────────────────────────────────────────
 COLLECTORS   scanner.py   sniffer.py    discovery.py   pcap.py
              socket +     scapy sniff   ARP / TCP-ping  offline
              scapy        in a thread   subnet sweep    capture replay
                  │            │              │             │
                  └────────────┴──────┬───────┴─────────────┘
                                      ▼
 CORE TYPES        ScanReport · PacketSummary · DiscoveryReport
                                      │
 DETECTION         ├──► analyzer.py ──► AnomalyFlag     (port/stealth scan,
                   │                                     floods, tunnels, beacons)
                   └──► defense.py  ──► DefenseAlert     (ARP-spoof / MITM)
                                      │
 ENRICHERS (opt-in, fail-soft)   cve.py (NVD CVEs)   geoip.py (country / ASN)
                                      │
 OUTPUT       ui.py (rich)   reporter.py (JSON + HTML)   alerts.py (jsonl/webhook/syslog)
                                      │
 STATE        store.py (SQLite history) ──► diff.py  ("what changed since last run")

 privileges.py gates all raw I/O and drives graceful unprivileged degradation.
```

Dependencies point **inward**: presentation, serialization, and forwarding
depend on the core data types (`ScanReport`, `PacketSummary`, `AnomalyFlag`) —
never the reverse. Because **live capture and PCAP import both produce
`PacketSummary`**, the analyzer, traffic stats, reporter, and alert pipeline are
identical for live and offline traffic — PCAP import is ~30 lines because it
reuses the sniffer's `summarize()`.

## Design decisions

The "why" behind the build — the points a security reviewer cares about more
than the feature list:

- **No binary wrappers.** Raw `socket` for the connect scan, hand-crafted
  `scapy` SYNs for the half-open scan, scapy `sniff()` + our own layer decode for
  capture. We never orchestrate `nmap`/`tshark`. The TCP logic is ours, so it's
  ours to reason about.

- **Honest OS detection → an OS *family heuristic*.** Real fingerprinting needs
  dozens of probes and a signature DB. We map TTL to a coarse family, refined by
  TCP window size as a weak secondary signal, and label it a "best guess
  (heuristic)" *everywhere* — code, CLI, and report. Calling a TTL check "OS
  detection" would be dishonest.

- **One concurrency model: threads, never asyncio.** The scanner fans probes
  across ports with a single `ThreadPoolExecutor`; the sniffer runs blocking
  `sniff()` in one dedicated thread governed by a `threading.Event`. The web UI is
  synchronous Flask + Server-Sent Events, deliberately not async FastAPI, so the
  one model holds across the whole stack.

- **The server never exposes itself.** A tool that runs scans and captures must
  not be reachable over the network: `netsleuth-web` binds to `127.0.0.1` only
  and rejects non-loopback `Host` headers (DNS-rebinding) and cross-origin
  `Origin` (CSRF) with 403.

- **Graceful privilege degradation.** `privileges.py` detects root/Admin once;
  unprivileged, the scanner falls back to a connect scan and the sniffer skips
  with a clear message — never a bare `PermissionError`.

- **External calls are opt-in, injectable, fail-soft.** Only CVE lookup touches
  the internet: opt-in, takes an injectable `fetch` (tests never hit the network),
  caches by `(product, version)`, and degrades to a warning offline.

## Detection — and its honest limits

The analyzer flags patterns over decoded packets. These are **coarse heuristics
— triage signals, not an IDS verdict** — and every flag says so. Thresholds live
in `AnalysisConfig` and are tunable per environment (`--config thresholds.json`).

| Flag | Signal | Honest limitation |
|---|---|---|
| **port-scan** | one source touches ≥ N distinct TCP ports | a busy client can look similar |
| **stealth-scan** | NULL/FIN/Xmas flag combos from one source | abnormal combos, but a broken stack could emit them |
| **SYN / ICMP flood** | ≥ N SYN-only / ICMP packets to one dst | volume-based; a benign ping sweep can trip ICMP |
| **ARP spoof** | one IP advertised with > 1 MAC | legitimate failover can also trigger it |
| **DNS tunnel** | one source: many queries + long avg name | high-volume legit DNS with long names can trip it |
| **beacon** | regular-interval connections, low jitter | cron-like legit traffic looks similar |
| **new-host** | a source absent from a known-host baseline | only as good as the baseline you pass |

**One engine, two modes.** The default *whole-capture* mode uses absolute counts.
A *windowed* mode (`--stream`, and what live capture uses) drives the same engine
off packet timestamps over a sliding window — so floods are measured as events
*per second* (a long quiet capture won't accumulate a false positive) and it adds
a **`slow-scan`** flag that catches the low-and-slow scan a fixed count can't tell
from a busy host. It processes live capture incrementally — O(new), not a
re-scan per tick.

A separate, gateway-aware **ARP-spoofing / MITM detector** (`defense.py`) watches
captured ARP traffic for poisoning signs — baseline MAC changes (critical for a
configured/learned gateway), duplicate IPs, one MAC impersonating many hosts, and
gratuitous-ARP floods. For live capture it learns the gateway's MAC up front
(trust-on-first-use), so a later swap raises a critical alert.
**NetSleuth detects MITM; it never performs it.**

## Practice legally

The `lab/` directory ships legal targets so you never have to point this at
something you don't own:

- **Docker containers** — deliberately-open nginx + FTP bound to `127.0.0.1`.
- **Sample malicious captures** — `python lab/generate_samples.py` crafts a
  `.pcap` for each detection (port-scan, SYN-flood, ARP-spoof, ICMP-flood,
  DNS-tunnel, beacon) plus a benign baseline — written on disk, never sent on the
  wire — to feed `--pcap`.
- **Real-world datasets** — pointers to Wireshark samples, malware-traffic-analysis.net,
  and CTF/CICIDS pcaps.

Because it reimplements `nmap` and Wireshark, NetSleuth doubles as a study lab:
[`docs/learning-with-netsleuth.md`](docs/learning-with-netsleuth.md) maps each
feature to the nmap flag / Wireshark filter it mirrors, and
[`tests/test_nmap_parity.py`](tests/test_nmap_parity.py) diffs our raw-socket
scan against real `nmap -sT -oX` (skipping cleanly when nmap is absent).

## Testing & quality

```bash
pip install -e ".[dev]"
ruff check . && mypy netsleuth main.py && pytest -q
```

`ruff` + `mypy` clean, type-hinted throughout, CI on Python 3.10–3.12. Tests are
**hermetic** — loopback listeners or in-memory scapy packets, no external host —
and detection is tested **end-to-end against ground truth**: the sample generator
produces each attack and tests assert the matching flag fires while benign
traffic stays clean. Network boundaries (CVE `fetch`, alert webhook) are injected,
not hit.

## Status & limitations

All phases ship: scanner, sniffer, analyzer (batch + windowed), integration +
reporting, web dashboard, discovery, SQLite history/diff, and opt-in
CVE/GeoIP/alert enrichment. The git history reads as a phase-by-phase build story.

Honest boundaries:

- Capture only sees what reaches the host's interface; on a switched LAN that's
  your own traffic + broadcast/ARP. Detection is intentionally heuristic triage,
  not an IDS.
- The MITM gateway baseline is trust-on-first-use — it catches a MAC change
  *after* capture starts, not a gateway already poisoned beforehand — and
  `--known-hosts auto` assumes a /24.
- CVE mapping is only as good as the banner: known products get a version-aware
  CPE match; unknown ones fall back to keyword *candidates* to verify. Not a
  Nessus-class authenticated scanner, by design.
- The privileged IPv6 UDP scan doesn't yet decode ICMPv6 port-unreachable, so a
  closed IPv6 UDP port reads `open|filtered` rather than `closed`.
- Nice-to-have: a recorded `docs/demo.gif`. [`docs/demo.sh`](docs/demo.sh) is a
  one-command offline walkthrough ready to record.
