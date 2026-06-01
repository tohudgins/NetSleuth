"""NetSleuth CLI entry point.

Wires the modules together behind an argparse interface. Defaults to a safe
local target (127.0.0.1) per CLAUDE.md rule #5 — authorized use only.

Exposes Phase 1 scanning and Phase 2 sniffing; --scan-then-sniff (integration)
lands in Phase 3.
"""

from __future__ import annotations

import argparse
import time
from typing import Any

from netsleuth import ui
from netsleuth.privileges import privilege_notice
from netsleuth.scanner import Protocol, scan
from netsleuth.sniffer import PacketSummary, Sniffer, capture_available, hexdump


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

    sniff_grp = p.add_argument_group("sniffer (Phase 2 — needs root/Administrator)")
    sniff_grp.add_argument("--sniff", action="store_true",
                           help="live packet capture instead of scanning")
    sniff_grp.add_argument("--iface", default=None, help="capture interface")
    sniff_grp.add_argument("--filter", dest="bpf", default=None,
                           help="BPF capture filter, e.g. 'tcp port 80'")
    sniff_grp.add_argument("--count", type=int, default=0,
                           help="stop after N packets (0 = until duration)")
    sniff_grp.add_argument("--duration", type=float, default=10.0,
                           help="capture seconds when --count is 0 (default: 10)")
    sniff_grp.add_argument("--hex", action="store_true",
                           help="hex-dump each captured packet")

    # Declared for the build story; implemented in Phase 3.
    p.add_argument("--scan-then-sniff", action="store_true",
                   help="(Phase 3) sniff the target's open ports after scanning")
    return p


def run_scan(args: argparse.Namespace) -> int:
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
    return 0


def run_sniff(args: argparse.Namespace) -> int:
    if not capture_available():
        ui.console.print(
            "Live capture needs raw-socket privileges (scapy + root/Administrator). "
            "Re-run with sudo to sniff; skipping capture.",
            style="bold yellow",
        )
        return 0

    def _on_packet(summary: PacketSummary, raw_pkt: Any) -> None:
        ui.print_packet(summary)
        if args.hex:
            ui.console.print(hexdump(bytes(raw_pkt)), style="dim")

    sniffer = Sniffer(
        iface=args.iface,
        bpf_filter=args.bpf,
        count=args.count,
        on_packet=_on_packet,
    )
    limit = f"{args.count} packets" if args.count else f"{args.duration:g}s"
    ui.console.print(f"Capturing ({limit}) — Ctrl-C to stop early…", style="cyan")

    sniffer.start()
    deadline = time.monotonic() + args.duration
    try:
        while sniffer.running and (args.count or time.monotonic() < deadline):
            time.sleep(0.2)
    except KeyboardInterrupt:
        ui.console.print("\nstopping…", style="dim")
    finally:
        sniffer.stop()

    ui.console.print(ui.render_traffic_table(sniffer.stats))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ui.print_privilege_notice(privilege_notice())

    if args.sniff:
        return run_sniff(args)

    rc = run_scan(args)
    if args.scan_then_sniff:
        ui.console.print(
            "\n[--scan-then-sniff is a Phase 3 feature — not yet implemented]",
            style="dim",
        )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
