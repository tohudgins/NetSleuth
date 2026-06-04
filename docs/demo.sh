#!/usr/bin/env bash
# NetSleuth demo — a reproducible end-to-end walkthrough you can record as a GIF.
#
# Run from the repo root:   bash docs/demo.sh
# Record it (one option):   asciinema rec -c "bash docs/demo.sh" demo.cast \
#                             && agg demo.cast docs/demo.gif
#   or with vhs / terminalizer / your screen recorder of choice.
#
# Everything here is offline and unprivileged (no sudo, no real network) — it
# analyses crafted sample captures, so it's safe to run and record anywhere.
set -euo pipefail

PY="${PYTHON:-python}"
step() { printf '\n\033[1;36m$ %s\033[0m\n' "$*"; sleep "${DEMO_PAUSE:-1.5}"; }

step "python lab/generate_samples.py        # craft attack sample pcaps (sends nothing)"
"$PY" lab/generate_samples.py

step "netsleuth --pcap lab/samples/port_scan.pcap        # detect a port scan"
"$PY" main.py --pcap lab/samples/port_scan.pcap

step "netsleuth --pcap lab/samples/slow_scan.pcap --stream   # windowed: low-and-slow"
"$PY" main.py --pcap lab/samples/slow_scan.pcap --stream

step "netsleuth --pcap lab/samples/arp_spoof.pcap --gateway 10.0.0.1   # MITM → critical"
"$PY" main.py --pcap lab/samples/arp_spoof.pcap --gateway 10.0.0.1

step "netsleuth 127.0.0.1 -p 1-1024 --diff --db /tmp/netsleuth-demo.db   # baseline"
"$PY" main.py 127.0.0.1 -p 1-1024 --diff --db /tmp/netsleuth-demo.db

step "netsleuth 127.0.0.1 -p 1-1024 --diff --db /tmp/netsleuth-demo.db   # what changed?"
"$PY" main.py 127.0.0.1 -p 1-1024 --diff --db /tmp/netsleuth-demo.db

step "netsleuth --history --db /tmp/netsleuth-demo.db        # run history"
"$PY" main.py --history --db /tmp/netsleuth-demo.db

rm -f /tmp/netsleuth-demo.db
printf '\n\033[1;32mDone. Tip: netsleuth-web opens the browser dashboard.\033[0m\n'
