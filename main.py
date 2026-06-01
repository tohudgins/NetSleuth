"""NetSleuth CLI entry point.

Wires the modules together behind an argparse interface. Defaults to a safe
local target (127.0.0.1) per CLAUDE.md rule #5 — authorized use only.

Currently exposes Phase 1 scanning; --scan-then-sniff and reporting flags are
declared but land in later phases.
"""

from __future__ import annotations

import argparse

from netsleuth import ui
from netsleuth.privileges import privilege_notice
from netsleuth.scanner import Protocol, scan


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
    p.add_argument("--udp", action="store_true",
                   help="UDP scan instead of TCP (best-effort when unprivileged)")
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
    ui.print_privilege_notice(privilege_notice())

    ports = _parse_ports(args.ports)
    proto = Protocol.UDP if args.udp else Protocol.TCP

    progress = ui.make_scan_progress()
    with progress:
        task = progress.add_task(f"scanning {args.target}", total=len(ports))
        report = scan(
            args.target,
            ports,
            proto=proto,
            timeout=args.timeout,
            max_workers=args.workers,
            force_connect=args.connect,
            on_result=lambda _r: progress.advance(task),
        )

    if report.os_family_guess:
        ui.console.print(
            f"OS family (heuristic, best guess): {report.os_family_guess}",
            style="magenta",
        )
    ui.console.print(ui.render_scan_table(report))
    if not report.open_ports:
        ui.console.print("  no open ports found", style="dim")

    if args.scan_then_sniff:
        ui.console.print(
            "\n[--scan-then-sniff is a Phase 3 feature — not yet implemented]",
            style="dim",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
