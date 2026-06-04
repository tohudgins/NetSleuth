# Learning networking fundamentals with NetSleuth

> A study guide for using this project to build the **packet-level networking
> skills** cybersecurity **engineer** and **analyst** roles screen for —
> anchored to the real tools (`nmap`, Wireshark/`tshark`) it reimplements.

NetSleuth is built from raw `socket` + `scapy` (no nmap/tshark wrappers), so every
feature corresponds to something the industry-standard tools do. That makes it an
ideal lab: run the **real** tool and NetSleuth side by side, and the abstraction
disappears — you see *why* the packets look the way they do.

## Setup

```bash
brew install nmap wireshark          # Wireshark installs the GUI + tshark CLI
docker compose -f lab/docker-compose.yml up -d   # deliberately-open lab targets
python lab/generate_samples.py       # crafted attack pcaps for analysis practice
```

---

## Loop A — `nmap` ↔ NetSleuth (active scanning)

Scan the same target with both. Because you understand your own implementation,
each nmap flag stops being magic.

| Concept (networking fundamental) | nmap | NetSleuth | What it teaches |
|---|---|---|---|
| TCP **connect** scan | `nmap -sT -p1-1024 <ip>` | `netsleuth <ip> -p1-1024 --connect` | full 3-way handshake; `connect()` semantics |
| **Half-open SYN** scan | `sudo nmap -sS -p1-1024 <ip>` | `sudo netsleuth <ip> -p1-1024` | SYN → SYN-ACK(open)/RST(closed); RST teardown |
| **UDP** scan | `sudo nmap -sU -p53,123 <ip>` | `netsleuth <ip> -p53,123 --udp` | connectionless; ICMP port-unreachable = closed |
| Host **discovery** | `nmap -sn 192.168.1.0/24` | `netsleuth 192.168.1.0/24 --discover` | ARP on local L2; why a ping sweep ≠ ARP sweep |
| **Version**/banner | `nmap -sV -p80,22 <ip>` | banner grab (HTTP/TLS/SSH) | service identification from the wire |
| **OS** detection | `nmap -O <ip>` | TTL *heuristic* | real fingerprinting = dozens of probes + a signature DB |
| **Timing** | `nmap -T0`…`-T5` | `netsleuth -T0`…`-T5` | the stealth/speed tradeoff (workers, timeout, spacing) |

**Do this:** run `nmap -sS --reason -p22,80 <ip>`. The `--reason` column shows
`syn-ack` for open and `reset` for closed — *that is exactly the reply your
`_syn_probe()` inspects.* Then `sudo netsleuth <ip> -p22,80 -vv` and compare.

The project ships an automated version of this comparison:
[`tests/test_nmap_parity.py`](../tests/test_nmap_parity.py) runs `nmap -sT -oX`,
parses the XML, and asserts the real tool and NetSleuth agree on the open set
(`pytest tests/test_nmap_parity.py` — skips if nmap isn't installed).

---

## Loop B — Wireshark *watching* a scan (capture + the handshake)

Start a capture, run a scan, watch the packets. This makes the handshake real.

```
# GUI: start capture on the interface, or:  tshark -i lo0 -f "tcp port 22"
Display filter:  tcp.flags.syn==1 && tcp.flags.ack==0     ← the lone SYNs you send
                 tcp.flags.syn==1 && tcp.flags.ack==1     ← SYN-ACK = port open
                 tcp.flags.reset==1                        ← your half-open RST teardown
```

**The single most important Wireshark concept:** *capture filters ≠ display
filters.*

- **Capture filter = BPF** (`tcp port 80`, `host 1.2.3.4`, `arp`) — decides what
  gets recorded. **This is exactly what NetSleuth's `--filter` takes.**
- **Display filter = Wireshark's own syntax** (`tcp.port == 80`, `ip.addr ==
  1.2.3.4`, `arp.opcode == 1`) — filters what's already captured.

Mixing them up is the #1 beginner mistake; building NetSleuth's BPF-based capture
means you already understand the capture side.

---

## Loop C — Wireshark *reading* NetSleuth's pcaps (traffic analysis)

The best loop for an **analyst**: NetSleuth tells you *what* it flagged, then you
reproduce it in Wireshark to learn *why*. Open each `lab/samples/*.pcap`:

| Sample (NetSleuth flag) | Wireshark display filter / view | What you see |
|---|---|---|
| `port_scan.pcap` (`port-scan`) | `tcp.flags.syn==1 && tcp.flags.ack==0` | one src → many distinct dst ports |
| `syn_flood.pcap` (`syn-flood`) | `tcp.flags.syn==1` + **Statistics → Endpoints** | SYN volume toward one dst |
| `arp_spoof.pcap` (`arp-spoof`) | `arp.opcode==2` | a gateway IP with **two MACs** — Wireshark's **Expert Info** even raises *"duplicate IP address configured"* |
| `dns_tunnel.pcap` (`dns-tunnel`) | `dns` | abnormally long query labels (encoded data) |
| `beacon.pcap` (`beacon`) | **Statistics → Conversations**, **IO Graph** | the regular ~30s call-home interval |
| `icmp_flood.pcap` (`icmp-flood`) | `icmp` | echo volume toward one dst |

Then explore the menus that make Wireshark powerful — each maps to something
NetSleuth's analyzer/traffic-stats already computes, so you'll *recognize* it:

- **Statistics → Protocol Hierarchy** ↔ your per-protocol breakdown / donut
- **Statistics → Conversations / Endpoints** ↔ your top-talkers table
- **Statistics → I/O Graph** ↔ your windowed rate detection (`--stream`)
- **Analyze → Follow → TCP Stream** ↔ reassembling a session (next-level skill)
- **Analyze → Expert Information** ↔ retransmissions, dup-ACKs, the ARP warning

`tshark` is the same engine on the CLI (great for scripting/grep):
```bash
tshark -r lab/samples/port_scan.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
       -T fields -e ip.src -e tcp.dstport
```

---

## Networking fundamentals this project demonstrates

Use this as your interview crib sheet — every row is something you *built*, so you
can speak to it from implementation, not memorization.

| Layer | Concept | Where it lives in NetSleuth |
|---|---|---|
| L2 | **ARP** (who-has / is-at), MAC/OUI, poisoning | discovery ARP sweep; MITM detector (`defense.py`) |
| L2/L3 | **IPv6 NDP / ICMPv6** neighbor discovery | `ndp_sweep` (multicast `ff02::1`) |
| L3 | IP **TTL** (and OS-family inference), **CIDR**/subnetting | TTL heuristic; `subnet_of`, host expansion |
| L4 | **TCP** handshake, flags, half-open scanning, RST | `scanner.py` SYN/connect probes |
| L4 | **UDP** + ICMP port-unreachable semantics | UDP scan |
| L7 | **DNS** query structure, banners/TLS | DNS decode, banner grab, tunneling heuristic |
| — | **BPF** capture filters | `--filter`, scan-then-sniff |
| — | Rate vs. count detection over a **time window** | streaming analyzer (`--stream`) |

## How this maps to the roles

- **Security Analyst / SOC:** Loop C is your day job in miniature — read a capture,
  recognize the pattern, explain it. You can demo "NetSleuth flagged a beacon →
  here it is in Wireshark's IO Graph." Talk to detection logic, false positives,
  and triage.
- **Security / Network Engineer:** Loops A & B + the codebase. You implemented the
  TCP/ARP/NDP mechanics, a concurrency model, privilege degradation, and DNS-
  rebinding/CSRF hardening. Talk to *how* and *why* you built it, and the
  honest-limits design decisions.

**Practice prompt to be ready for:** "Walk me through what happens on the wire
during a SYN scan, and how you'd detect one." You can answer it from both sides —
you wrote the scanner *and* the detector.
