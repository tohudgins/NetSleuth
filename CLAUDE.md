# CLAUDE.md — NetSleuth

> Project instructions for Claude Code. Read this fully before generating or editing any code.

## What we're building

**NetSleuth** is a portfolio-grade network security tool that integrates two modules:

1. **Scanner** — an Nmap-style TCP/UDP port scanner with banner grabbing and an OS *family* heuristic.
2. **Sniffer** — a Wireshark-style live packet capture + protocol analyzer.

The two are integrated: scanning a target can auto-trigger focused sniffing on its open ports, and both feed a unified report engine.

This is a **defensive / educational** tool intended to run against a **lab the user owns**. It is not an attack framework.

---

## NON-NEGOTIABLE design rules

These come from a design review and are the whole point of the project. Do not violate them.

### 1. Implement the logic ourselves — NO binary wrappers
- **DO NOT** use `python-nmap`, `pyshark`, `tshark`, or any wrapper that shells out to the real `nmap`/`tshark` binaries for core functionality.
- The scanner must use raw `socket` calls (and `scapy` for SYN scans) so the TCP handshake logic is *ours*.
- The sniffer must use `scapy` for capture/decode, not a tshark subprocess.
- **Exception (encouraged):** an *optional* test module that runs real `nmap` and diffs its output against ours, clearly labeled as validation only. This shows rigor, not dependence.

### 2. Be honest about OS detection
- We do **not** do real OS fingerprinting (that needs dozens of probes + a signature DB).
- Implement an **OS family heuristic** only: guess Linux/Windows/network-gear from TTL and TCP window size.
- Label it everywhere as a *heuristic / best guess*, in code, output, and README. Never call it "OS detection."

### 3. One coherent concurrency model
- **Scanner:** a `ThreadPoolExecutor` for parallel port probes. Threads, not asyncio.
- **Sniffer:** scapy's `sniff()` is blocking — run it in its own dedicated thread with a stop event.
- **DO NOT** introduce `asyncio`. Mixing asyncio + threads + blocking scapy is a code-review red flag.

### 4. Handle privileges gracefully
- Raw sockets / SYN scans / packet capture need root (Linux/macOS) or admin (Windows).
- On startup, detect privilege level.
- If unprivileged: **warn clearly** and **degrade** — fall back to a TCP connect scan (`socket.connect_ex`) and disable raw capture with an explanatory message. Never crash with a bare `PermissionError`.

### 5. Legal / safety framing is part of the deliverable
- The README must open with an **"Authorized use only"** notice: run only against systems you own or have explicit permission to test.
- Ship a `lab/` setup (docker-compose with a couple of deliberately-open containers, or docs for VirtualBox + Metasploitable) so users have a legal target out of the box.
- Default target in any example/help text is `127.0.0.1` or the lab network, never a public IP.

---

## Architecture

```
netsleuth/
├── README.md                # Authorized-use notice first, then usage + demo.gif
├── requirements.txt
├── pyproject.toml           # or setup.cfg; make it pip-installable
├── main.py                  # CLI entry (argparse), wires modules together
├── netsleuth/
│   ├── __init__.py
│   ├── scanner.py           # raw-socket + scapy SYN scan, banner grab, OS heuristic
│   ├── sniffer.py           # scapy sniff() in a thread, protocol decode
│   ├── analyzer.py          # traffic stats + simple anomaly flags
│   ├── reporter.py          # JSON + HTML (jinja2) output
│   ├── privileges.py        # privilege detection + degrade logic
│   └── ui.py                # rich-based CLI dashboard
├── templates/
│   └── report.html          # jinja2 template
├── lab/
│   ├── docker-compose.yml   # legal practice targets
│   └── README.md
├── tests/
│   ├── test_scanner.py
│   ├── test_analyzer.py
│   └── test_nmap_parity.py  # OPTIONAL validation vs real nmap, skipped if absent
└── docs/
    └── demo.gif
```

## Tech stack

| Concern | Choice | Notes |
|---|---|---|
| Language | Python 3.10+ | type hints throughout |
| Port scan | `socket` + `scapy` | connect scan (unpriv) + SYN scan (priv) |
| Capture | `scapy` | `sniff()` in a dedicated thread |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` | scanner only |
| CLI UI | `rich` | tables, live dashboard, progress bars |
| Reports | `jinja2` + stdlib `json` | HTML + machine-readable JSON |
| Tests | `pytest` | unit tests + optional nmap parity |

---

## Build order (ship Phase 1–3, treat 4 as stretch)

**Phase 1 — Scanner (raw)**
- [ ] `privileges.py`: detect root/admin; expose `can_raw_socket()` helper.
- [ ] TCP connect scan via `socket.connect_ex` (works unprivileged).
- [ ] SYN scan via scapy when privileged.
- [ ] `ThreadPoolExecutor` for parallel ports; configurable worker count + timeout.
- [ ] Banner grabbing for HTTP / FTP / SSH.
- [ ] OS *family heuristic* from TTL + window size (clearly labeled).

**Phase 2 — Sniffer**
- [ ] scapy capture in a dedicated thread + `threading.Event` stop flag.
- [ ] Decode TCP/UDP/ICMP/ARP/DNS; per-packet summary + optional hex dump.
- [ ] Per-IP traffic volume stats.

**Phase 3 — Integration + reporting**
- [ ] `--scan-then-sniff`: scan target, then sniff only its open ports.
- [ ] `analyzer.py` anomaly flags: port-scan pattern, SYN flood, ARP spoof signs.
- [ ] `rich` live dashboard showing scan results + traffic.
- [ ] `reporter.py`: JSON + HTML export.

**Phase 4 — Stretch (only after v1 ships)**
- [ ] PCAP import (analyze saved captures).
- [ ] `--honeypot-mode` to forward alerts to the user's existing honeypot.
- [ ] CVE lookup for detected service versions via an API.

---

## Conventions

- Type-hint everything; run `ruff` + `mypy` clean.
- Each module is independently runnable and unit-tested.
- No bare `except:` — catch specific exceptions, especially `PermissionError`/`OSError` around sockets.
- All user-facing claims must match what the code actually does (the honesty rule applies to docstrings and help text too).
- Commit per phase with clear messages; the git history should read as a build story for a portfolio reviewer.

## Definition of done for v1

A reviewer can clone the repo, `pip install -e .`, spin up `lab/` with docker-compose, run `python main.py --scan-then-sniff <lab-ip>`, and get a live dashboard plus a JSON + HTML report — all without the real nmap/tshark binaries installed, and with a clear warning (not a crash) if run unprivileged.
