"""NetSleuth CLI entry point.

Wires the modules together behind an argparse interface. Defaults to a safe
local target (127.0.0.1) per CLAUDE.md rule #5 — authorized use only.

Phase 1 scanning, Phase 2 sniffing, and Phase 3 integration: --scan-then-sniff
runs a scan, then sniffs the target's open ports behind a live dashboard, with
anomaly analysis and JSON/HTML reporting.
"""

from __future__ import annotations

import argparse
import time
from dataclasses import asdict
from typing import Any

from rich.live import Live

from netsleuth import ui
from netsleuth.alerts import emit_alerts
from netsleuth.analyzer import AnomalyFlag, analyze
from netsleuth.cve import enrich_scan
from netsleuth.pcap import analyze_pcap
from netsleuth.privileges import privilege_notice
from netsleuth.reporter import build_report, write_report
from netsleuth.scanner import Protocol, ScanReport, scan
from netsleuth.sniffer import (
    PacketSummary,
    Sniffer,
    TrafficStats,
    capture_available,
    hexdump,
)


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
    p.add_argument("--show-closed", action="store_true",
                   help="list closed/filtered ports too (default: only open)")

    sniff_grp = p.add_argument_group("sniffer (needs root/Administrator)")
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

    intg_grp = p.add_argument_group("integration + reporting")
    intg_grp.add_argument("--scan-then-sniff", action="store_true",
                          help="scan, then sniff the target's open ports (live dashboard)")
    intg_grp.add_argument("--pcap", default=None, metavar="FILE",
                          help="analyze a saved capture file offline (no privileges)")
    intg_grp.add_argument("--report-dir", default=None,
                          help="write JSON + HTML report into this directory")
    intg_grp.add_argument("--cve", action="store_true",
                          help="look up candidate CVEs for detected service versions (NVD)")

    alert_grp = p.add_argument_group("alert forwarding (anomaly flags)")
    alert_grp.add_argument("--alert-jsonl", default=None, metavar="FILE",
                           help="append anomaly flags as JSON-lines to FILE")
    alert_grp.add_argument("--alert-webhook", default=None, metavar="URL",
                           help="HTTP POST anomaly flags as JSON to URL")
    alert_grp.add_argument("--alert-syslog", nargs="?", const="localhost:514",
                           default=None, metavar="HOST:PORT",
                           help="send anomaly flags to syslog (default localhost:514)")
    return p


# --- shared helpers -------------------------------------------------------- #

def _scan(args: argparse.Namespace, proto: Protocol, *, show_progress: bool) -> ScanReport:
    ports = _parse_ports(args.ports)
    if not show_progress:
        return scan(args.target, ports, proto=proto, timeout=args.timeout,
                    max_workers=args.workers, force_connect=args.connect)
    progress = ui.make_scan_progress()
    with progress:
        task = progress.add_task(f"scanning {args.target}", total=len(ports))
        return scan(
            args.target, ports, proto=proto, timeout=args.timeout,
            max_workers=args.workers, force_connect=args.connect,
            on_result=lambda _r: progress.advance(task),
        )


def _write_reports(
    args: argparse.Namespace,
    *,
    scan_report: ScanReport | None = None,
    stats: TrafficStats | None = None,
    anomalies: list[AnomalyFlag] | None = None,
    cves: dict[int, list[dict[str, Any]]] | None = None,
    default_dir: str | None = None,
) -> None:
    out = args.report_dir or default_dir
    if not out:
        return
    report = build_report(scan=scan_report, stats=stats, anomalies=anomalies, cves=cves)
    paths = write_report(out, report)
    ui.console.print(
        f"Reports written: {paths['json']} and {paths['html']}", style="green"
    )


def _forward_alerts(args: argparse.Namespace, anomalies: list[AnomalyFlag]) -> None:
    """Emit anomaly flags to any configured sinks (jsonl/webhook/syslog)."""
    syslog = None
    if args.alert_syslog:
        host, _, port = args.alert_syslog.partition(":")
        syslog = (host or "localhost", int(port) if port else 514)
    results = emit_alerts(
        anomalies,
        jsonl_path=args.alert_jsonl,
        webhook=args.alert_webhook,
        syslog=syslog,
    )
    for line in results:
        ui.console.print(f"alert: {line}", style="dim")


def _cve_enrich(
    args: argparse.Namespace, report: ScanReport
) -> dict[int, list[dict[str, Any]]]:
    """Look up candidate CVEs for open ports; print a table; return serialised."""
    if not args.cve:
        return {}
    try:
        by_port = enrich_scan(report)
    except (OSError, ValueError) as exc:  # offline / API / bad-JSON — fail soft
        ui.console.print(f"CVE lookup skipped ({exc})", style="yellow")
        return {}
    if by_port:
        ui.console.print(ui.render_cve_table(by_port))
    return {port: [asdict(e) for e in entries] for port, entries in by_port.items()}


# --- modes ----------------------------------------------------------------- #

def run_scan(args: argparse.Namespace) -> int:
    proto = Protocol.UDP if args.udp else Protocol.TCP
    report = _scan(args, proto, show_progress=True)

    if report.os_family_guess:
        ui.console.print(
            f"OS family (heuristic, best guess): {report.os_family_guess}",
            style="magenta",
        )
    ui.console.print(ui.render_scan_table(report, show_closed=args.show_closed))
    if not report.open_ports:
        ui.console.print("  no open ports found", style="dim")

    cves = _cve_enrich(args, report)
    _write_reports(args, scan_report=report, cves=cves)
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

    sniffer = Sniffer(iface=args.iface, bpf_filter=args.bpf, count=args.count,
                      on_packet=_on_packet)
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

    anomalies = analyze(list(sniffer.packets))
    ui.console.print(ui.render_traffic_table(sniffer.stats))
    ui.console.print(ui.render_anomalies(anomalies))
    _forward_alerts(args, anomalies)
    _write_reports(args, stats=sniffer.stats, anomalies=anomalies)
    return 0


def run_pcap(args: argparse.Namespace) -> int:
    ui.console.print(f"Analyzing capture file: {args.pcap}", style="cyan")
    try:
        result = analyze_pcap(args.pcap)
    except (OSError, ValueError, RuntimeError) as exc:
        ui.console.print(f"Could not read capture: {exc}", style="bold red")
        return 1
    ui.console.print(ui.render_traffic_table(result.stats))
    ui.console.print(ui.render_anomalies(result.anomalies))
    _forward_alerts(args, result.anomalies)
    _write_reports(args, stats=result.stats, anomalies=result.anomalies)
    return 0


def run_scan_then_sniff(args: argparse.Namespace) -> int:
    # Always TCP for the scan stage so we have ports to focus the capture on.
    report = _scan(args, Protocol.TCP, show_progress=True)
    open_ports = report.open_ports
    ui.console.print(ui.render_scan_table(report, show_closed=args.show_closed))
    cves = _cve_enrich(args, report)

    if not open_ports:
        ui.console.print("No open ports — nothing to sniff.", style="dim")
        _write_reports(args, scan_report=report, cves=cves, default_dir="reports")
        return 0

    if not capture_available():
        ui.console.print(
            "Open ports found, but live capture needs root/Administrator. "
            "Re-run with sudo to sniff them; writing scan-only report.",
            style="bold yellow",
        )
        _write_reports(args, scan_report=report, cves=cves, default_dir="reports")
        return 0

    ports_clause = " or ".join(f"tcp port {p}" for p in open_ports)
    bpf = f"host {args.target} and ({ports_clause})"
    # The sniffer collects into its own list from the capture thread; we only
    # read atomic snapshots here, so we don't share a mutable buffer across
    # threads (list(x) over a list is atomic under the GIL).
    sniffer = Sniffer(iface=args.iface, bpf_filter=bpf)

    ui.console.print(
        f"Sniffing {args.target} ports {open_ports} for {args.duration:g}s "
        "— Ctrl-C to stop early…", style="cyan",
    )
    anomalies: list[AnomalyFlag] = []

    def _frame() -> Any:
        nonlocal anomalies
        snapshot = list(sniffer.packets)  # atomic copy of the capture buffer
        anomalies = analyze(snapshot)
        return ui.render_dashboard(report, sniffer.stats, anomalies, snapshot[-12:],
                                   show_closed=args.show_closed)

    sniffer.start()
    deadline = time.monotonic() + args.duration
    with Live(_frame(), console=ui.console, refresh_per_second=4) as live:
        try:
            while sniffer.running and time.monotonic() < deadline:
                time.sleep(0.25)
                live.update(_frame())
        except KeyboardInterrupt:
            pass
        finally:
            sniffer.stop()
            live.update(_frame())

    _forward_alerts(args, anomalies)
    _write_reports(args, scan_report=report, stats=sniffer.stats,
                   anomalies=anomalies, cves=cves, default_dir="reports")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # PCAP analysis is offline and needs no privileges, so skip the notice.
    if args.pcap:
        return run_pcap(args)

    ui.print_privilege_notice(privilege_notice())
    if args.scan_then_sniff:
        return run_scan_then_sniff(args)
    if args.sniff:
        return run_sniff(args)
    return run_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
