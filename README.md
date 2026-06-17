# NetSleuth

[![CI](https://github.com/tohudgins/NetSleuth/actions/workflows/ci.yml/badge.svg)](https://github.com/tohudgins/NetSleuth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

> ## ⚠️ Authorized use only
> NetSleuth is a **defensive, educational** tool. Run it **only** against systems
> you own or have **explicit written permission** to test. Port scanning and
> packet capture of networks you don't control may be illegal. All examples
> default to `127.0.0.1` or the bundled `lab/` network. You are responsible for
> how you use this tool.

**NetSleuth** is a from-scratch, defensive network-security toolkit with three
integrated capabilities:

1. **Port scanner** — Nmap-style TCP (connect / SYN / FIN / NULL / Xmas) and UDP
   scanning over **IPv4 and IPv6**, across single hosts, comma-lists, or CIDR
   ranges, with banner grabbing and an OS *family heuristic*.
2. **Packet sniffer + traffic analyzer** — Wireshark-style live capture and
   protocol decode, feeding an anomaly-detection engine.
3. **Vulnerability mapper** — matches the service versions it finds to NVD CVEs
   (opt-in, CPE-accurate, cached).

The three are wired together — a scan can auto-trigger focused sniffing of a
target's open ports, and everything feeds one anomaly analyzer, live dashboard,
and JSON/HTML reporting pipeline. The scanning and capture logic is implemented
ourselves (`socket` + `scapy`) — **not** wrapped around the `nmap` or `tshark`
binaries.

## Contents

- [Highlights](#highlights)
- [Install](#install)
  - [Docker](#docker)
  - [Diagnostics & tuning](#diagnostics--tuning)
- [Web dashboard](#web-dashboard)
- [Usage (CLI)](#usage-cli)
- [Analyzing real-world captures (blue-team)](#analyzing-real-world-captures-blue-team)
- [History & diff](#history--diff--what-changed-since-last-time)
- [Alert forwarding + CVE lookup](#alert-forwarding--cve-lookup)
- [Stealth & politeness — scan timing](#stealth--politeness--scan-timing--t05)
- [Architecture](#architecture)
- [Design decisions](#design-decisions)
- [Detection heuristics — and their limits](#detection-heuristics--and-their-limits)
  - [ARP-spoofing / MITM detector](#arp-spoofing--mitm-detector-defensepy)
- [Practice legally](#practice-legally)
- [Testing & quality](#testing--quality)
- [Project status](#project-status)
- [Limitations & future work](#limitations--future-work)

## Highlights

The core is the from-scratch networking: the scan, capture, and analysis logic
is implemented with `socket` + `scapy`, **not** wrapped around the `nmap` or
`tshark` binaries. Everything under *Beyond the core* is a layer on top of that
same engine.

### Core — built from scratch

- **Port scanner** — TCP connect scan (unprivileged, `socket.connect_ex`),
  half-open **SYN scan** (privileged: we craft the SYN with scapy and classify
  the reply ourselves), **FIN/NULL/Xmas stealth scans** (`--scan-type`, RFC 793
  half-open techniques), and a UDP scan with **protocol-aware probes** (real
  DNS/NTP/SNMP requests, not a null byte) and honest `open|filtered` states; banner
  grabbing incl. TLS for HTTPS; an OS *family heuristic* (a coarse TTL + TCP
  window best guess — **not** real fingerprinting); nmap-style **timing templates**
  (`-T0..5`, paranoid→insane); a `ThreadPoolExecutor` concurrency model.
- **Packet sniffer** — scapy `sniff()` in a dedicated thread with a stop event;
  decodes TCP/UDP/ICMP/ARP/DNS; per-IP and per-protocol traffic stats; our own
  hex dump.
- **Anomaly analyzer** — coarse, clearly-labelled heuristics for port scans,
  SYN floods, ARP spoofing, ICMP floods, DNS tunneling/exfil, C2 beaconing, and
  new-host detection. One engine, two modes: a whole-capture **count** verdict,
  and a windowed **rate** mode (`--stream`) that catches **low-and-slow scans**
  and true flood rates — and processes live capture incrementally (O(new), not a
  re-scan every tick).
- **ARP-spoofing / MITM detector** — the *defensive* side of MITM: watches the
  captured ARP traffic for poisoning signs (baseline MAC changes, duplicate IPs,
  one MAC impersonating many hosts, gratuitous-ARP floods). NetSleuth detects
  MITM; it never performs it.
- **Host & network discovery** — map the live hosts on a subnet you own: a
  privileged ARP sweep (with MAC + best-guess vendor), an unprivileged TCP-ping
  fallback, and **IPv6** discovery via NDP (`ping6 ff02::1`).
- **Integration** — `--scan-then-sniff` scans a target, then focuses capture on
  its open ports behind a live `rich` dashboard.
- **Graceful degradation** — unprivileged, it falls back to a connect scan and
  skips live capture instead of crashing.

### Beyond the core — layers on the same engine

- **Reporting** — unified JSON + HTML reports from any mode.
- **PCAP import** — run the full detection pipeline over saved captures (offline,
  no privileges).
- **Web dashboard** — dark-theme browser UI (Flask + SSE): scan, discover, analyze
  captures, and watch live capture stream with SVG charts and a packet hexdump.
- **History & diff** — persist scans/discoveries to SQLite and answer *"what
  changed since last time?"* (new ports, hosts, a moved gateway MAC).
- **Alert forwarding** — emit anomaly + ARP-spoofing alerts as JSON-lines / webhook
  / syslog for SIEM-style integration.
- **CVE lookup** — map detected service versions to NVD CVEs (opt-in, CPE-accurate,
  cached).

## Install

```bash
pip install -e .
# or: pip install -r requirements.txt
pip install -e ".[geoip]"   # optional: GeoIP/ASN enrichment (you supply the DB)
```

Requires Python 3.10+. Live SYN scan and packet capture need root (Linux/macOS)
or Administrator (Windows); everything else, including PCAP analysis, runs
unprivileged.

### Docker

```bash
docker build -t netsleuth .
docker run --rm netsleuth 127.0.0.1 -p 1-1024 --connect    # CLI scan
# raw sockets (SYN scan / live capture):
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN netsleuth <target> --sniff
# web UI — loopback-only by design, so use the host network, then browse :8765:
docker run --rm --network host --entrypoint netsleuth-web netsleuth
```

### Diagnostics & tuning

`-v`/`-vv` turn on INFO/DEBUG logging. `--config thresholds.json` overrides any
[`AnalysisConfig`](netsleuth/analyzer.py) field (e.g. `{"syn_flood_count": 200,
"window": 5}`) — handy for tuning detection per environment without code changes.

With a MaxMind **GeoLite2** database (you provide it; licensed, can't be bundled),
external talkers in a capture get country + ASN/org columns:

```bash
python main.py --pcap capture.pcap --geoip-db GeoLite2-City.mmdb --geoip-asn GeoLite2-ASN.mmdb
netsleuth-web --geoip-db GeoLite2-City.mmdb     # same, in the dashboard
```

Private/loopback addresses are skipped, and everything degrades to nothing when
the DB or `geoip2` package is absent.

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

# scan a CIDR range or comma-list; IPv6 works too; --grep for pipe-friendly output
python main.py 192.168.1.0/28 -p 22,80,443 --grep
python main.py ::1 -p 1-1024

# discover live hosts on a subnet (ARP sweep w/ sudo, else TCP-ping)
sudo python main.py 192.168.1.0/24 --discover

# privileged SYN scan (needs sudo / Administrator)
sudo python main.py 127.0.0.1 -p 22,80,443

# UDP scan (sends real DNS/NTP/SNMP probes to elicit replies)
python main.py 127.0.0.1 -p 53,123,161 --udp

# stealth scans — FIN / NULL / Xmas (need sudo; degrade to connect otherwise)
sudo python main.py 127.0.0.1 -p 1-1024 --scan-type xmas

# live packet capture for 10s (needs sudo / Administrator)
sudo python main.py --sniff --duration 10
sudo python main.py --sniff --filter "tcp port 80" --count 50 --hex

# capture and save to a .pcap — reopen in Wireshark or re-analyze with --pcap
sudo python main.py --sniff --duration 30 --write-pcap capture.pcap
python main.py --pcap capture.pcap                 # round-trips into the analyzer

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

# windowed/rate analysis — catches a low-and-slow scan a count threshold misses
python main.py --pcap lab/samples/slow_scan.pcap            # batch → port-scan
python main.py --pcap lab/samples/slow_scan.pcap --stream   # windowed → slow-scan
```

The analyzer flags port-scan, stealth-scan (NULL/FIN/Xmas), SYN-flood, ARP-spoof,
ICMP-flood, DNS-tunnel, beacon, and new-host patterns (and the spoofing detector
raises its own alerts), writing the same JSON/HTML report as the live modes. The
lab ships a sample capture for each of these.

### History & diff — "what changed since last time?"

Make the tool *stateful*: persist a scan or discovery and compare it to the last
saved run of the same target. A changed gateway MAC between two sweeps is exactly
the ARP-poisoning signal the live detector hunts — now visible over time.

```bash
# save a run; --diff also compares to the previous saved run of this target
python main.py 127.0.0.1 -p 1-1024 --save
python main.py 127.0.0.1 -p 1-1024 --diff          # → "+ opened port 8080", etc.
sudo python main.py 192.168.1.0/24 --discover --diff   # → "+ host …", "! MAC changed …"

# list everything stored, and pick a custom DB location
python main.py --history
python main.py 127.0.0.1 --diff --db /tmp/lab.db
```

Runs live in `~/.netsleuth/history.db` by default (override with `--db`).
Persistence is **explicit** — nothing is written unless you pass `--save`/`--diff`.
A scan diff is most meaningful when the two runs cover the **same ports** (a port
absent from one run can't be told apart from a closed one), so re-run the same
target + port spec to compare like-for-like. In the **web dashboard**, tick *Save
to history* on the Scan/Discover tabs, then open the **History** tab to browse
past runs and see each one's diff against its predecessor.

### Alert forwarding + CVE lookup

Forward detected anomalies **and ARP-spoofing alerts** into your alerting
pipeline (a honeypot, a SIEM, a log shipper — all just sinks for the same JSON),
and look up candidate CVEs for detected service versions:

```bash
# forward anomaly + spoofing alerts as JSON-lines / to a webhook / to syslog
python main.py --pcap capture.pcap --alert-jsonl alerts.jsonl
python main.py --pcap capture.pcap --alert-webhook https://example/hook
sudo python main.py --scan-then-sniff 127.0.0.1 --alert-syslog localhost:514

# look up CVEs for detected banners (NVD; opt-in, fails soft offline; cached)
python main.py 127.0.0.1 -p 80,22 --cve --report-dir reports
```

For a known product (OpenSSH, nginx, Apache, vsftpd) the lookup uses a precise,
version-aware **CPE** query (`virtualMatchString`) — each result is tagged `cpe`;
unknown products fall back to a keyword search, tagged `keyword` (a *candidate*,
verify before acting). Results are cached at `~/.netsleuth/cve-cache.json`
(7-day TTL), so a repeat scan resolves offline and instantly.

### Stealth & politeness — scan timing (`-T0..5`)

nmap-style timing templates trade speed for stealth/politeness by tuning worker
count, per-port timeout, and inter-probe spacing. `-T0` (paranoid) is serial and
slow; `-T3` is the default; `-T5` (insane) is fast and loud. Explicit
`--workers`/`--timeout` override the template.

```bash
python main.py 192.168.1.10 -p 1-1024 -T2     # polite
sudo python main.py 192.168.1.10 -p 1-65535 -T4   # aggressive SYN scan
```

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

Two **opt-in enrichers** hang off the report without the core depending on them:
`cve.py` (NVD CVEs per open port, CPE-matched + cached) and `geoip.py`
(country/ASN for external talkers via a user-supplied MaxMind DB). Both are
fail-soft — absent network, key, or database, the rest of the tool is unchanged.

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
family, refined by the TCP window size as a weak secondary signal (a tiny window
leans toward embedded/network gear), and label it a "best guess (heuristic)"
everywhere — in code, CLI, and report. Calling a TTL+window check "OS detection"
would be dishonest.

**One concurrency model: threads, never asyncio.** The scanner fans probes across
ports with a single `ThreadPoolExecutor`; the sniffer runs scapy's blocking
`sniff()` in one dedicated thread governed by a `threading.Event`, and the live
dashboard reads its buffer via atomic `list()` snapshots. The web UI is Flask
(synchronous, threaded) with Server-Sent Events — deliberately not async FastAPI —
so the one model holds across the whole stack.

**The server never exposes itself.** A tool that runs scans and captures must not
be reachable over the network: `netsleuth-web` binds to `127.0.0.1` only and
rejects with 403 any request carrying a non-loopback `Host` header (DNS-rebinding)
or a cross-origin `Origin` (CSRF).

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
| **stealth-scan** | one source probes ≥ N ports with NULL/FIN/Xmas flag combos | catches stealth scans by their *flags* even at low volume; the combos are abnormal but a broken stack could emit them |
| **SYN flood** | ≥ N SYN-only segments toward one destination | no rate/time window; volume-based |
| **ARP spoof** | one IP advertised with > 1 MAC | legitimate failover can also trigger it |
| **ICMP flood** | ≥ N ICMP/ICMPv6 packets toward one destination | also fires on a benign ping sweep |
| **DNS tunnel** | one source: many queries *and* long avg query names | high-volume legit DNS with long names can trip it |
| **beacon** | regular-interval connections to one dst:port (low jitter) | needs enough events; cron-like legit traffic looks similar |
| **new-host** | a source absent from a supplied known-host baseline | only as good as the baseline you pass |

These are coarse heuristics — *triage signals*, not an IDS verdict — and are
labelled as such in every flag. Thresholds live in `AnalysisConfig` so they can
be tuned per environment. The new-host check runs against a known-host baseline:
pass `--known-hosts ip,ip` explicitly, or `--known-hosts auto` to seed it from a
live discovery sweep of your subnet.

**One engine, two modes.** The detector above runs in *whole-capture* mode
(absolute counts over everything) — the default for `--pcap` and a finished
capture. A *windowed* mode (`--stream`, and what live capture uses) drives the
same engine off packet timestamps over a sliding window, which buys two things a
count threshold can't:

| | whole / batch (default) | windowed (`--stream`, live) |
|---|---|---|
| **floods** | total count ≥ N | events **per second** ≥ rate (a long quiet capture won't slowly accumulate into a false positive) |
| **scans** | distinct ports ≥ N | fast `port-scan` *and* a new **`slow-scan`** — distinct ports over a 5-min window at low rate, the low-and-slow scan a fixed count can't tell from a busy host |
| **cost** | re-scan the whole buffer | incremental, O(new packets) per tick (kills the old per-tick O(n²)); repeats deduped by a per-alert cooldown |

Time is read from each packet's captured timestamp, so windowed detection is
deterministic and behaves identically on a live wire and a saved pcap.

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

The strongest check, `arp-mac-change`, needs a baseline of the gateway's
known-good MAC. For **live capture** NetSleuth learns this automatically: before
sniffing it resolves the gateway (explicit `--gateway`, else the OS default
route) via a single ARP request and remembers its MAC, so a poisoner that later
swaps the gateway MAC raises a **critical** alert. This is *trust-on-first-use* —
it catches a change from this point on, not a gateway already being impersonated
when capture starts. Pair it with `--known-hosts auto`, which sweeps the local
subnet up front so new devices appearing in the capture are flagged too:

```bash
sudo python main.py --sniff --duration 30 --known-hosts auto
sudo python main.py 192.168.1.50 --scan-then-sniff --gateway 192.168.1.1
```

Without a learned baseline (offline `--pcap`, or unprivileged) the other three
checks still work off the captured traffic alone, and `--gateway` still escalates
any alert against that IP to critical. The detector surfaces in the CLI
(`--sniff`, `--scan-then-sniff`, `--pcap`) and the web Live/Analyze tabs — the web
live-capture tab learns the gateway baseline the same way.
**NetSleuth detects MITM; it never performs it.**

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

### Learn the fundamentals with it

NetSleuth reimplements what `nmap` and Wireshark do, so it doubles as a study lab
for the packet-level networking skills security **engineer/analyst** roles screen
for. [`docs/learning-with-netsleuth.md`](docs/learning-with-netsleuth.md) is a
guided walkthrough: run the real tools side by side, map each feature to the
nmap flag / Wireshark display filter it mirrors, and reproduce every detection in
Wireshark. The automated counterpart is
[`tests/test_nmap_parity.py`](tests/test_nmap_parity.py) — it diffs our raw-socket
scan against real `nmap -sT -oX` and asserts they agree (skips if nmap is absent).

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

Built as a phased story (the git history reads phase by phase); all phases ship:

- [x] **Scanner** — connect / SYN / FIN / NULL / Xmas / UDP, banner grab, OS family heuristic, timing templates
- [x] **Sniffer** — threaded scapy capture, TCP/UDP/ICMP/ARP/DNS decode, per-IP/per-protocol stats
- [x] **Analyzer** — one engine, two modes (batch counts + windowed rates); scan/flood/tunnel/beacon/MITM heuristics
- [x] **Integration & reporting** — `--scan-then-sniff`, live `rich` dashboard, JSON + HTML reports
- [x] **Web dashboard** — Flask + SSE: scan, discover, pcap analysis, and live capture in the browser
- [x] **Discovery** — ARP / TCP-ping / IPv6-NDP subnet sweep with vendor guess
- [x] **History** — SQLite persistence + scan/discovery diffing (`--save`/`--diff`/`--history`)
- [x] **Enrichment** — opt-in CVE (CPE-matched, cached) and GeoIP/ASN; alert forwarding to jsonl/webhook/syslog

## Limitations & future work

- Capture only sees what reaches the host's interface; on a switched LAN that's
  your own traffic + broadcast/ARP. NetSleuth **detects** MITM (the spoofing
  detector) but never **performs** it — by design.
- Discovery is local-scope: the ARP sweep only reaches your own broadcast
  domain, and the unprivileged TCP-ping fallback can miss hosts that drop all
  probes. The OUI vendor table is a small, partial best-guess map, not the full
  IEEE registry.
- The MITM detector's gateway baseline is trust-on-first-use and assumes a /24
  for `--known-hosts auto`: it catches a MAC change *after* capture starts, not a
  gateway already poisoned beforehand, and won't auto-detect non-/24 subnets.
- History diffing covers scans and discoveries (point-in-time inventories), not
  live captures (which are time-series); it compares the latest two runs of a
  target rather than tracking per-asset first/last-seen.
- The windowed analyzer drives time off captured packet timestamps (not wall
  clock), and re-alerts a *sustained* condition once per cooldown rather than
  tracking a single episode; a wall-clock `watch` mode and per-flow reassembly
  remain future work.
- Vulnerability mapping is only as good as the banner: known products get a
  version-aware **CPE** match against NVD, but unknown products fall back to a
  keyword search that returns *candidates* to verify, not confirmed findings.
  There is no authenticated/deep vulnerability scanning (it is not a Nessus-class
  tool, by design).
- IPv6 scanning covers connect / SYN / FIN / NULL / Xmas; the privileged UDP scan
  doesn't yet decode ICMPv6 port-unreachable, so a closed IPv6 UDP port reads as
  `open|filtered` rather than `closed`.
- Nice-to-have: a recorded `docs/demo.gif`. [`docs/demo.sh`](docs/demo.sh) is a
  one-command, offline walkthrough (sample attacks → detection → history diff)
  ready to record with `asciinema`/`agg`, `vhs`, or any screen recorder.
