# NetSleuth

> ## ⚠️ Authorized use only
> NetSleuth is a **defensive, educational** tool. Run it **only** against systems
> you own or have **explicit written permission** to test. Port scanning and
> packet capture of networks you don't control may be illegal. All examples
> default to `127.0.0.1` or the bundled `lab/` network. You are responsible for
> how you use this tool.

A from-scratch, defensive network security toolkit: an Nmap-style port scanner
and a Wireshark-style packet sniffer that share one anomaly analyzer, live
dashboard, and reporting pipeline — with the scanning and capture logic
implemented ourselves (`socket` + `scapy`), **not** wrapped around the `nmap` or
`tshark` binaries.

## Contents

- [Highlights](#highlights)
- [Install](#install)
- [Web dashboard](#web-dashboard)
- [Usage (CLI)](#usage-cli)
- [Analyzing real-world captures (blue-team)](#analyzing-real-world-captures-blue-team)
- [Alert forwarding + CVE lookup](#alert-forwarding--cve-lookup)
- [Architecture](#architecture)
- [Design decisions](#design-decisions)
- [Detection heuristics — and their limits](#detection-heuristics--and-their-limits)
  - [ARP-spoofing / MITM detector](#arp-spoofing--mitm-detector-defensepy)
- [Practice legally](#practice-legally)
- [Testing & quality](#testing--quality)
- [Project status](#project-status)
- [Limitations & future work](#limitations--future-work)

## Highlights

- **Web dashboard** — a polished dark-theme browser UI to run scans, discover
  hosts, analyze uploaded captures, and watch live capture stream in real time:
  SVG protocol donut + traffic-over-time chart, sortable tables, and a
  click-to-inspect packet hexdump.
- **Host & network discovery** — map the live hosts on a subnet you own: a
  privileged ARP sweep (with MAC + best-guess vendor) or an unprivileged
  TCP-ping sweep fallback.
- **Port scanner** — TCP connect scan (unprivileged), half-open SYN scan
  (privileged, scapy), and UDP scan; banner grabbing incl. TLS for HTTPS; an OS
  *family heuristic* (a coarse TTL best guess — **not** real fingerprinting).
- **Packet sniffer** — scapy `sniff()` in a dedicated thread with a stop event;
  decodes TCP/UDP/ICMP/ARP/DNS; per-IP and per-protocol traffic stats; our own
  hex dump.
- **Anomaly analyzer** — coarse, clearly-labelled heuristics for port scans,
  SYN floods, ARP spoofing, ICMP floods, DNS tunneling/exfil, C2 beaconing, and
  new-host detection.
- **ARP-spoofing / MITM detector** — the *defensive* side of MITM: watches the
  captured ARP traffic for poisoning signs (baseline MAC changes, duplicate IPs,
  one MAC impersonating many hosts, gratuitous-ARP floods). NetSleuth detects
  MITM; it never performs it.
- **Integration** — `--scan-then-sniff` scans a target, then focuses capture on
  its open ports behind a live `rich` dashboard.
- **Reporting** — unified JSON + HTML reports from any mode.
- **PCAP import** — run the full detection pipeline over saved capture files
  (offline, no privileges) — analyze real-world datasets legally.
- **Alert forwarding** — emit anomaly *and* ARP-spoofing alerts as JSON-lines /
  webhook / syslog for SIEM-style integration.
- **CVE lookup** — map detected banners to candidate CVEs via NVD (opt-in).
- **Graceful degradation** — unprivileged, it falls back to a connect scan and
  skips live capture instead of crashing.

## Install

```bash
pip install -e .
# or: pip install -r requirements.txt
```

Requires Python 3.10+. Live SYN scan and packet capture need root (Linux/macOS)
or Administrator (Windows); everything else, including PCAP analysis, runs
unprivileged.

## Web dashboard

The easiest way to use NetSleuth — a browser UI for scans, capture analysis, and
live capture:

```bash
netsleuth-web                 # → http://127.0.0.1:8765  (scans + pcap analysis)
sudo netsleuth-web            # also enables the Live capture tab (needs root)
```

It binds to `127.0.0.1` only (this server runs scans/captures — never expose it
on a network). The dashboard has four tabs:

- **Scan** — port scan a target, with optional CVE lookup.
- **Discover** — sweep a subnet into a host inventory (IP / MAC / vendor / open
  ports), sortable by any column.
- **Live capture** — start/stop a capture; packets stream in live with a
  protocol donut and a traffic-over-time chart, ARP-spoofing + anomaly alerts,
  and **click any packet to see its hexdump** in a side panel.
- **Analyze capture** — drag in a `.pcap` for the same offline analysis.

It's a thin layer over the same engine as the CLI — built on Flask with
synchronous Server-Sent Events, so the "threads, not asyncio" model holds. The
charts are hand-drawn SVG (no chart-library / CDN dependency), keeping the tool
self-contained and offline.

> Run the server with `sudo` only for live capture. If launched unprivileged, the
> Live tab reports that capture needs root instead of failing.

## Usage (CLI)

```bash
# scan localhost (works unprivileged via connect scan)
python main.py 127.0.0.1 -p 1-1024

# discover live hosts on a subnet (ARP sweep w/ sudo, else TCP-ping)
sudo python main.py 192.168.1.0/24 --discover

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

### Analyzing real-world captures (blue-team, no privileges)

You don't need to capture live traffic to exercise the detection — point
NetSleuth at a saved capture file. This is the legal way to run it over real
adversarial traffic (see `lab/README.md` for public dataset sources):

```bash
# generate the lab's sample malicious captures (writes files, sends nothing)
python lab/generate_samples.py

# detect the attack in a capture — no sudo required
python main.py --pcap lab/samples/port_scan.pcap
python main.py --pcap lab/samples/beacon.pcap --report-dir reports
python main.py --pcap lab/samples/dns_tunnel.pcap
python main.py --pcap path/to/real-world.pcap   # e.g. a malware-traffic capture

# escalate spoofing against your gateway to critical, and flag unknown hosts
python main.py --pcap lab/samples/arp_spoof.pcap --gateway 10.0.0.1
python main.py --pcap capture.pcap --known-hosts 10.0.0.10,10.0.0.53
```

The analyzer flags port-scan, SYN-flood, ARP-spoof, ICMP-flood, DNS-tunnel,
beacon, and new-host patterns (and the spoofing detector raises its own alerts),
writing the same JSON/HTML report as the live modes. The lab ships a sample
capture for each of these.

### Alert forwarding + CVE lookup

Forward detected anomalies **and ARP-spoofing alerts** into your alerting
pipeline (a honeypot, a SIEM, a log shipper — all just sinks for the same JSON),
and look up candidate CVEs for detected service versions:

```bash
# forward anomaly + spoofing alerts as JSON-lines / to a webhook / to syslog
python main.py --pcap capture.pcap --alert-jsonl alerts.jsonl
python main.py --pcap capture.pcap --alert-webhook https://example/hook
sudo python main.py --scan-then-sniff 127.0.0.1 --alert-syslog localhost:514

# look up candidate CVEs for detected banners (queries NVD; opt-in, fails soft offline)
python main.py 127.0.0.1 -p 80,22 --cve --report-dir reports
```

CVE results are keyword-matched *candidates* from NVD — verify before acting,
they are not a confirmed-vulnerable verdict.

## Architecture

```
        ┌──────────────────────┬──────────────────────┐
   cli.py (argparse, rich)      web.py (Flask + SSE, browser UI)
        └───────────┬──────────┴───────────┬──────────┘
        ┌──────────┬────────┼────────┬─────────┬─────────┐
        ▼          ▼        ▼        ▼         ▼         ▼
  scanner.py  sniffer.py discovery pcap.py  cve.py  (privileges.py
  (socket+   (scapy sniff .py (ARP/ (offline (NVD      gates raw I/O)
   scapy)     in a thread) ping sweep) caps)  lookup)
        │          │                  │
        └───► PacketSummary / ScanReport / DiscoveryReport ◄──┐
                        │                                      │
                        ├──► analyzer.py ──► AnomalyFlag ──────┤
                        └──► defense.py  ──► DefenseAlert ─────┤
                        │                                      │
              ┌─────────┼───────────┬───────────┐             │
              ▼         ▼           ▼            ▼             │
          ui.py     reporter.py   alerts.py ◄─────────────────┘
        (rich)    (JSON + HTML)  (jsonl/webhook/syslog)
```

Dependencies point **inward**: presentation (`ui`, `web`), serialization
(`reporter`), and forwarding (`alerts`) depend on the core data types —
`ScanReport`, `PacketSummary`, `AnomalyFlag` — never the reverse. Both front
ends (`cli.py`, `web.py`) wire the same modules; every other module is
independently importable and unit-tested. The web layer is thin: each endpoint
returns `reporter.build_report(...)` as JSON for the browser to render.

Because **live capture and PCAP import both produce `PacketSummary`**, the
analyzer, traffic stats, reporter, and alert pipeline are identical for live and
offline traffic. PCAP import is ~30 lines precisely because it reuses the
sniffer's `summarize()`.

## Design decisions

The "why" behind the build — these are the points a security reviewer cares
about more than the feature list.

**Implement the logic ourselves — no binary wrappers.** The scanner uses raw
`socket` (connect scan) and crafts TCP SYNs with `scapy` (half-open scan); the
sniffer uses scapy's `sniff()` and decodes layers itself. We never shell out to
`nmap`/`tshark`. `scapy` is used as a packet construction/decode *library* we
compose, not a finished tool we orchestrate. Even the hex dump is hand-rolled.

**Honest OS detection → an OS *family heuristic*.** Real fingerprinting needs
dozens of probes and a signature database. We map an observed TTL to a coarse
family and label it a "best guess (heuristic)" everywhere — in code, CLI, and
report. Calling a TTL check "OS detection" would be dishonest.

**One concurrency model: threads, never asyncio.** The scanner fans probes
across ports with a single `ThreadPoolExecutor`; the sniffer runs scapy's
blocking `sniff()` in one dedicated thread governed by a `threading.Event`. We
avoid mixing asyncio with threads and blocking scapy. The live dashboard reads
the capture buffer via atomic `list()` snapshots rather than iterating a list
the capture thread is mutating. **The web UI uses Flask (synchronous, threaded)
with Server-Sent Events — deliberately not async FastAPI — so this one model
holds across the whole stack.**

**The server never exposes itself.** `netsleuth-web` binds to `127.0.0.1` only
and refuses non-loopback hosts: a tool that runs scans and captures must not be
reachable over the network.

**Graceful privilege degradation.** `privileges.py` detects root/Admin once;
unprivileged, the scanner falls back to a connect scan and the sniffer prints a
clear message and skips — never a bare `PermissionError`. The privilege notice
is mode-neutral; each mode reports its own degraded behaviour.

**Detection off structured fields, not regex on display text.**
`PacketSummary` carries `sport/dport/flags/mac` alongside its human-readable
string, so the analyzer reads typed fields and is trivially testable with
hand-built summaries.

**External calls are opt-in, injectable, and fail soft.** Only CVE lookup
reaches the internet: it's opt-in (`--cve`), takes an injectable `fetch` (so
tests never touch the network), caches by `(product, version)`, and degrades to
a warning when offline. Alert webhook/syslog are likewise fail-soft.

## Detection heuristics — and their limits

The analyzer flags these patterns over a batch of decoded packets:

| Flag | Signal | Honest limitation |
|---|---|---|
| **port-scan** | one source touches ≥ N distinct TCP ports | a busy client can look similar; threshold-based |
| **SYN flood** | ≥ N SYN-only segments toward one destination | no rate/time window; volume-based |
| **ARP spoof** | one IP advertised with > 1 MAC | legitimate failover can also trigger it |
| **ICMP flood** | ≥ N ICMP/ICMPv6 packets toward one destination | also fires on a benign ping sweep |
| **DNS tunnel** | one source: many queries *and* long avg query names | high-volume legit DNS with long names can trip it |
| **beacon** | regular-interval connections to one dst:port (low jitter) | needs enough events; cron-like legit traffic looks similar |
| **new-host** | a source absent from a supplied known-host baseline | only as good as the baseline you pass |

These are coarse heuristics — *triage signals*, not an IDS verdict — and are
labelled as such in every flag. Thresholds live in `AnalysisConfig` so they can
be tuned per environment. `analyze(..., known_hosts=...)` enables the new-host
check against a baseline (e.g. from a trusted discovery sweep).

### ARP-spoofing / MITM detector (`defense.py`)

A focused, gateway-aware detector for man-in-the-middle activity on your wire —
the defensive counterpart to an ARP-poisoning attack. It reads the same captured
ARP traffic and emits severity-rated alerts:

| Alert | Signal | Severity |
|---|---|---|
| **arp-mac-change** | an IP's MAC differs from a trusted baseline | warning, or **critical** for a configured gateway IP |
| **duplicate-ip** | one IP currently claimed by multiple MACs | warning |
| **mac-many-ips** | one MAC answering for many IPs (subnet-wide poisoning) | warning |
| **gratuitous-arp** | a flood of unsolicited is-at replies | warning |

Pass a `baseline` (IP → known-good MAC, e.g. from a discovery sweep) and a set of
`critical_ips` (your gateway) to turn on the strongest, escalated check. Without
a baseline the other three still work off the captured traffic alone. It surfaces
in the CLI (`--sniff`, `--scan-then-sniff`, `--pcap`) and the web Live/Analyze
tabs. **NetSleuth detects MITM; it never performs it.**

## Practice legally

The `lab/` directory gives you legal targets out of the box:

- **Docker containers** — deliberately-open nginx + FTP bound to `127.0.0.1`.
- **Sample malicious captures** — `python lab/generate_samples.py` writes a
  `.pcap` for each detection (port-scan, SYN-flood, ARP-spoof, ICMP-flood,
  DNS-tunnel, beacon) plus a benign baseline — crafted on disk, never sent on
  the wire — to feed `--pcap`.
- **Real-world datasets** — pointers to Wireshark sample captures,
  malware-traffic-analysis.net, and CTF/CICIDS pcaps.

See [`lab/README.md`](lab/README.md).

## Testing & quality

- `ruff` + `mypy` clean, type hints throughout; CI runs on Python 3.10–3.12.
- Tests are **hermetic**: scanner/sniffer tests use loopback listeners or build
  scapy packets in memory; nothing depends on an external host.
- Detection is tested **end-to-end against ground truth**: the sample generator
  produces each attack and tests assert the matching flag fires (and benign
  traffic stays clean).
- Network boundaries are **injected, not hit**: CVE lookup takes a `fetch`
  callable; the alert webhook is monkeypatched.
- `tests/test_nmap_parity.py` optionally diffs our scan against the real `nmap`
  binary as *validation* — and skips cleanly when it's absent, so we never
  depend on it.

```bash
pip install -e ".[dev]"
ruff check . && mypy netsleuth main.py && pytest -q
```

## Project status

- [x] Phase 1 — Scanner (connect + SYN, UDP, banner grab, OS family heuristic)
- [x] Phase 2 — Sniffer (threaded scapy capture, TCP/UDP/ICMP/ARP/DNS decode, per-IP stats)
- [x] Phase 3 — Integration (--scan-then-sniff), analyzer anomaly flags, live dashboard, JSON/HTML reports
- [x] Phase 4 — PCAP import, attack-sample lab, alert forwarding (JSON-lines/webhook/syslog), CVE lookup
- [x] Phase 5 — Web dashboard (Flask + SSE): scan, pcap analysis, live capture in the browser
- [x] Phase 6 — Host & network discovery, ARP-spoofing/MITM detector, deeper anomaly
      heuristics (ICMP flood, DNS tunneling, beaconing, new-host), and a polished
      dark dashboard with SVG charts, sortable tables, and packet hexdump drill-down

## Limitations & future work

- Capture only sees what reaches the host's interface; on a switched LAN that's
  your own traffic + broadcast/ARP. NetSleuth **detects** MITM (the spoofing
  detector) but never **performs** it — by design.
- Discovery is local-scope: the ARP sweep only reaches your own broadcast
  domain, and the unprivileged TCP-ping fallback can miss hosts that drop all
  probes. The OUI vendor table is a small, partial best-guess map, not the full
  IEEE registry.
- Anomaly heuristics are stateless over a batch; a streaming/windowed analyzer
  would catch slow scans and cut false positives.
- CVE matching is keyword-based against NVD; CPE-accurate matching would be more
  precise.
- Nice-to-have: a recorded `docs/demo.gif` of the dashboard catching an attack.
