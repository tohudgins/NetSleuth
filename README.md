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
- [Usage](#usage)
- [Analyzing real-world captures (blue-team)](#analyzing-real-world-captures-blue-team)
- [Alert forwarding + CVE lookup](#alert-forwarding--cve-lookup)
- [Architecture](#architecture)
- [Design decisions](#design-decisions)
- [Detection heuristics — and their limits](#detection-heuristics--and-their-limits)
- [Practice legally](#practice-legally)
- [Testing & quality](#testing--quality)
- [Project status](#project-status)
- [Limitations & future work](#limitations--future-work)

## Highlights

- **Port scanner** — TCP connect scan (unprivileged), half-open SYN scan
  (privileged, scapy), and UDP scan; banner grabbing incl. TLS for HTTPS; an OS
  *family heuristic* (a coarse TTL best guess — **not** real fingerprinting).
- **Packet sniffer** — scapy `sniff()` in a dedicated thread with a stop event;
  decodes TCP/UDP/ICMP/ARP/DNS; per-IP and per-protocol traffic stats; our own
  hex dump.
- **Anomaly analyzer** — coarse, clearly-labelled heuristics for port scans,
  SYN floods, and ARP spoofing.
- **Integration** — `--scan-then-sniff` scans a target, then focuses capture on
  its open ports behind a live `rich` dashboard.
- **Reporting** — unified JSON + HTML reports from any mode.
- **PCAP import** — run the full detection pipeline over saved capture files
  (offline, no privileges) — analyze real-world datasets legally.
- **Alert forwarding** — emit anomalies as JSON-lines / webhook / syslog for
  SIEM-style integration.
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

### Analyzing real-world captures (blue-team, no privileges)

You don't need to capture live traffic to exercise the detection — point
NetSleuth at a saved capture file. This is the legal way to run it over real
adversarial traffic (see `lab/README.md` for public dataset sources):

```bash
# generate the lab's sample malicious captures (writes files, sends nothing)
python lab/generate_samples.py

# detect the attack in a capture — no sudo required
python main.py --pcap lab/samples/port_scan.pcap
python main.py --pcap lab/samples/syn_flood.pcap --report-dir reports
python main.py --pcap path/to/real-world.pcap   # e.g. a malware-traffic capture
```

The analyzer flags port-scan, SYN-flood, and ARP-spoof patterns and writes the
same JSON/HTML report as the live modes.

### Alert forwarding + CVE lookup

Forward detected anomalies into your alerting pipeline (a honeypot, a SIEM, a
log shipper — all just sinks for the same JSON), and look up candidate CVEs for
detected service versions:

```bash
# forward anomaly flags as JSON-lines / to a webhook / to syslog
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
                 ┌─────────────┐
   CLI (main.py) │ argparse +  │  picks a mode, wires modules, owns no logic
                 │ run_* funcs │
                 └──────┬──────┘
        ┌───────────────┼───────────────┬───────────────┐
        ▼               ▼               ▼               ▼
   scanner.py       sniffer.py       pcap.py         cve.py
   (socket+scapy)   (scapy sniff     (offline read   (NVD lookup,
                     in a thread)     of captures)    injectable fetch)
        │               │               │
        └──────► PacketSummary / ScanReport ◄─────────┐
                        │                              │
                        ▼                              │
                   analyzer.py  ──► AnomalyFlag ───────┤
                        │                              │
              ┌─────────┼───────────┬──────────────┐  │
              ▼         ▼           ▼              ▼  ▼
          ui.py     reporter.py   alerts.py    (privileges.py gates raw I/O)
        (rich)    (JSON + HTML)  (jsonl/webhook/syslog)
```

Dependencies point **inward**: presentation (`ui`), serialization (`reporter`),
and forwarding (`alerts`) depend on the core data types — `ScanReport`,
`PacketSummary`, `AnomalyFlag` — never the reverse. `main.py` is the only place
that knows about all modules; every other module is independently importable and
unit-tested.

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
the capture thread is mutating.

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

The analyzer flags three patterns over a batch of decoded packets:

| Flag | Signal | Honest limitation |
|---|---|---|
| **port-scan** | one source touches ≥ N distinct TCP ports | a busy client can look similar; threshold-based |
| **SYN flood** | ≥ N SYN-only segments toward one destination | no rate/time window; volume-based |
| **ARP spoof** | one IP advertised with > 1 MAC | legitimate failover can also trigger it |

These are coarse heuristics — *triage signals*, not an IDS verdict — and are
labelled as such in every flag. Thresholds live in `AnalysisConfig` so they can
be tuned per environment.

## Practice legally

The `lab/` directory gives you legal targets out of the box:

- **Docker containers** — deliberately-open nginx + FTP bound to `127.0.0.1`.
- **Sample malicious captures** — `python lab/generate_samples.py` writes
  port-scan / SYN-flood / ARP-spoof / benign `.pcap` files (crafted on disk,
  never sent on the wire) to feed `--pcap`.
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

## Limitations & future work

- Capture only sees what reaches the host's interface; on a switched LAN that's
  your own traffic + broadcast/ARP. NetSleuth does no MITM — by design.
- Anomaly heuristics are stateless over a batch; a streaming/windowed analyzer
  would catch slow scans and cut false positives.
- CVE matching is keyword-based against NVD; CPE-accurate matching would be more
  precise.
- Nice-to-have: a recorded `docs/demo.gif` of a sample capture being flagged.
```
