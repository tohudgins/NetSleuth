#!/usr/bin/env python3
"""Generate the lab's sample malicious captures.

These are detection test fixtures — crafted packets written to .pcap files, not
sent on the wire. Analyze them with NetSleuth (no privileges needed):

    python lab/generate_samples.py
    python main.py --pcap lab/samples/port_scan.pcap

Then try the real thing on a legal public dataset (see lab/README.md).
"""

from __future__ import annotations

from netsleuth.samples import write_samples


def main() -> int:
    paths = write_samples("lab/samples")
    print("Wrote sample captures:")
    for name, path in paths.items():
        print(f"  {name:<10} {path}")
    print("\nAnalyze one with:")
    print("  python main.py --pcap lab/samples/port_scan.pcap")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
