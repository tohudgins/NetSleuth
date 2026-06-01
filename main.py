"""NetSleuth CLI entry point.

Wires the modules together behind an argparse interface. Defaults to a safe
local target (127.0.0.1) per CLAUDE.md rule #5 — authorized use only.

Currently exposes Phase 1 scanning; --scan-then-sniff and reporting flags are
declared but land in later phases.
"""

from __future__ import annotations

import argparse

from netsleuth.privileges import privilege_notice
from netsleuth.scanner import scan


def _parse_ports(spec: str) -> list[int]:
    """Parse a port spec like '22,80,443' or '1-1024' into a sorted list."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p <= 65535)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netsleuth",
        description="NetSleuth — defensive port scanner + packet sniffer. "
        "Authorized use only: scan systems you own or are permitted to test.",
    )
    p.add_argument("target", nargs="?", default="127.0.0.1",
                   help="target host (default: 127.0.0.1)")
    p.add_argument("-p", "--ports", default="1-1024",
                   help="ports, e.g. '22,80,443' or '1-1024' (default: 1-1024)")
    p.add_argument("--timeout", type=float, default=1.0, help="per-port timeout (s)")
    p.add_argument("--workers", type=int, default=100, help="thread pool size")
    p.add_argument("--connect", action="store_true",
                   help="force unprivileged connect scan even if privileged")
    # Declared for the build story; implemented in later phases.
    p.add_argument("--scan-then-sniff", action="store_true",
                   help="(Phase 3) sniff the target's open ports after scanning")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(privilege_notice())

    report = scan(
        args.target,
        _parse_ports(args.ports),
        timeout=args.timeout,
        max_workers=args.workers,
        force_connect=args.connect,
    )

    print(f"\n{report.scan_type} scan of {report.target}")
    if report.os_family_guess:
        print(f"OS family (heuristic, best guess): {report.os_family_guess}")
    for r in report.ports:
        if r.state.value == "open":
            extra = f"  {r.service_hint or ''} {r.banner or ''}".rstrip()
            print(f"  {r.port}/tcp  open{extra}")
    if not report.open_ports:
        print("  no open ports found")

    if args.scan_then_sniff:
        print("\n[--scan-then-sniff is a Phase 3 feature — not yet implemented]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
