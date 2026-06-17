"""NetSleuth CLI entry point.

Wires the modules together behind an argparse interface. Defaults to a safe
local target (127.0.0.1) per CLAUDE.md rule #5 — authorized use only.

Phase 1 scanning, Phase 2 sniffing, and Phase 3 integration: --scan-then-sniff
runs a scan, then sniffs the target's open ports behind a live dashboard, with
anomaly analysis and JSON/HTML reporting.
"""

from __future__ import annotations

import argparse
import logging
import time
from dataclasses import asdict
from typing import Any

from rich.live import Live
from rich.logging import RichHandler

from netsleuth import geoip, store, ui
from netsleuth.alerts import emit_alerts
from netsleuth.geoip import GeoInfo
from netsleuth.analyzer import (
    AnalysisConfig,
    AnomalyFlag,
    WindowAnalyzer,
    analyze,
    analyze_stream,
    load_config,
)
from netsleuth.cve import DEFAULT_CVE_CACHE, enrich_scan
from netsleuth.defense import DefenseAlert, DefenseConfig, detect_spoofing
from netsleuth.diff import DiscoveryDiff, ScanDiff, diff_run
from netsleuth.diff import to_dict as diff_to_dict
from netsleuth.discovery import (
    DiscoveryReport,
    default_gateway,
    discover,
    discovery_available,
    resolve_mac,
    subnet_of,
)
from netsleuth.pcap import analyze_pcap
from netsleuth.privileges import privilege_notice
from netsleuth.reporter import build_report, write_report
from netsleuth.scanner import (
    TIMING_TEMPLATES,
    PortState,
    Protocol,
    ScanReport,
    scan,
)
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


# Cap CIDR expansion so a typo like /8 can't launch millions of probes.
_MAX_SCAN_HOSTS = 1024


def _expand_targets(spec: str) -> list[str]:
    """Expand a target spec into concrete hosts.

    Accepts a single host, a comma-separated list, and/or CIDR blocks
    (``10.0.0.0/29``, ``2001:db8::/126``). Plain hostnames pass through
    untouched. Raises ``ValueError`` if a CIDR would exceed ``_MAX_SCAN_HOSTS``.
    """
    import ipaddress

    out: list[str] = []
    seen: set[str] = set()
    for part in (p.strip() for p in spec.split(",")):
        if not part:
            continue
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            hosts = list(net.hosts()) or [net.network_address]
            if len(hosts) > _MAX_SCAN_HOSTS:
                raise ValueError(
                    f"{part} expands to {len(hosts)} hosts (max {_MAX_SCAN_HOSTS})")
            candidates = [str(h) for h in hosts]
        else:
            candidates = [part]
        for host in candidates:
            if host not in seen:
                seen.add(host)
                out.append(host)
    return out


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
    p.add_argument("--timeout", type=float, default=None,
                   help="per-port timeout (s); overrides the -T template (default 1.0)")
    p.add_argument("--workers", type=int, default=None,
                   help="thread pool size; overrides the -T template (default 100)")
    p.add_argument("-T", "--timing", type=int, choices=range(6), default=None,
                   metavar="0-5",
                   help="nmap-style timing template: 0 paranoid … 3 normal … 5 insane")
    p.add_argument("--connect", action="store_true",
                   help="force unprivileged connect scan even if privileged")
    p.add_argument("--scan-type", choices=("fin", "null", "xmas"), default=None,
                   metavar="TYPE",
                   help="TCP stealth scan (needs root): fin, null, or xmas; "
                        "falls back to connect scan when unprivileged")
    p.add_argument("--show-closed", action="store_true",
                   help="list closed/filtered ports too (default: only open)")
    p.add_argument("--grep", action="store_true",
                   help="greppable one-line-per-open-port output (pipe-friendly)")
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="verbose diagnostics: -v INFO, -vv DEBUG")

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
    sniff_grp.add_argument("--write-pcap", default=None, metavar="FILE",
                           help="save the live capture to a .pcap (Wireshark / --pcap)")

    intg_grp = p.add_argument_group("integration + reporting")
    intg_grp.add_argument("--discover", action="store_true",
                          help="map live hosts on a subnet (target may be a CIDR, "
                          "e.g. 192.168.1.0/24); ARP sweep if privileged else TCP ping")
    intg_grp.add_argument("--scan-then-sniff", action="store_true",
                          help="scan, then sniff the target's open ports (live dashboard)")
    intg_grp.add_argument("--pcap", default=None, metavar="FILE",
                          help="analyze a saved capture file offline (no privileges)")
    intg_grp.add_argument("--stream", action="store_true",
                          help="use the windowed/rate analyzer (catches low-and-slow "
                          "scans + flood rates) instead of whole-capture counting")
    intg_grp.add_argument("--window", type=float, default=None, metavar="SECONDS",
                          help="streaming window size for rate detection (default: 10)")
    intg_grp.add_argument("--config", default=None, metavar="FILE",
                          help="JSON file of analyzer thresholds (AnalysisConfig fields)")
    intg_grp.add_argument("--geoip-db", default=None, metavar="FILE",
                          help="MaxMind GeoLite2-City .mmdb — adds country to "
                          "external talkers (needs `pip install geoip2`)")
    intg_grp.add_argument("--geoip-asn", default=None, metavar="FILE",
                          help="MaxMind GeoLite2-ASN .mmdb — adds ASN/org to "
                          "external talkers")
    intg_grp.add_argument("--report-dir", default=None,
                          help="write JSON + HTML report into this directory")
    intg_grp.add_argument("--cve", action="store_true",
                          help="look up candidate CVEs for detected service versions (NVD)")
    intg_grp.add_argument("--gateway", default=None, metavar="IP",
                          help="gateway IP for ARP-spoof detection: its MAC is "
                          "learned before live capture so a change alerts as "
                          "critical (auto-detected from the route table if omitted)")
    intg_grp.add_argument("--known-hosts", default=None, metavar="IP,…|auto",
                          help="baseline of known hosts; sources not listed are "
                          "flagged as new devices. 'auto' sweeps the local subnet "
                          "to build the baseline (live capture only)")

    hist_grp = p.add_argument_group("run history (scan / discovery)")
    hist_grp.add_argument("--save", action="store_true",
                          help="save this scan/discovery run to the history DB")
    hist_grp.add_argument("--diff", action="store_true",
                          help="compare to the previous saved run of this target "
                          "(then save). Re-run the same target+ports to compare "
                          "like-for-like")
    hist_grp.add_argument("--history", action="store_true",
                          help="list stored runs and exit")
    hist_grp.add_argument("--db", default=str(store.DEFAULT_DB), metavar="PATH",
                          help="history DB path (default: ~/.netsleuth/history.db)")

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

def _setup_logging(verbosity: int) -> None:
    """Configure the `netsleuth` logger; quiet (WARNING) unless -v/-vv given."""
    level = {0: logging.WARNING, 1: logging.INFO}.get(verbosity, logging.DEBUG)
    logger = logging.getLogger("netsleuth")
    logger.setLevel(level)
    if not logger.handlers:
        handler = RichHandler(console=ui.console, show_path=False,
                              show_time=False, rich_tracebacks=True)
        handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
        logger.addHandler(handler)


def _timing(args: argparse.Namespace) -> tuple[int, float, float]:
    """Resolve (workers, timeout, delay) from a -T template + explicit overrides.

    Explicit --workers / --timeout always win over the template; with neither a
    template nor a flag, fall back to the built-in normal defaults (100, 1.0).
    """
    tmpl = TIMING_TEMPLATES.get(args.timing) if args.timing is not None else None
    workers = args.workers if args.workers is not None else (tmpl[0] if tmpl else 100)
    timeout = args.timeout if args.timeout is not None else (tmpl[1] if tmpl else 1.0)
    delay = tmpl[2] if tmpl else 0.0
    return workers, timeout, delay


def _scan(args: argparse.Namespace, proto: Protocol, *, show_progress: bool,
          target: str | None = None) -> ScanReport:
    host = target if target is not None else args.target
    ports = _parse_ports(args.ports)
    workers, timeout, delay = _timing(args)
    stealth = getattr(args, "scan_type", None)
    if not show_progress:
        return scan(host, ports, proto=proto, timeout=timeout,
                    max_workers=workers, delay=delay, force_connect=args.connect,
                    stealth=stealth)
    progress = ui.make_scan_progress()
    with progress:
        task = progress.add_task(f"scanning {host}", total=len(ports))
        return scan(
            host, ports, proto=proto, timeout=timeout,
            max_workers=workers, delay=delay, force_connect=args.connect,
            stealth=stealth, on_result=lambda _r: progress.advance(task),
        )


def _print_greppable(report: ScanReport) -> None:
    """One pipe-friendly line per open port: ``host port/proto state service``."""
    for p in report.ports:
        if p.state in (PortState.OPEN, PortState.OPEN_FILTERED):
            ui.console.print(
                f"{report.target} {p.port}/{p.proto.value} {p.state.value} "
                f"{p.service_hint or '-'}",
                highlight=False, soft_wrap=True)


def _write_reports(
    args: argparse.Namespace,
    *,
    scan_report: ScanReport | None = None,
    stats: TrafficStats | None = None,
    anomalies: list[AnomalyFlag] | None = None,
    cves: dict[int, list[dict[str, Any]]] | None = None,
    discovery: DiscoveryReport | None = None,
    defense: list[DefenseAlert] | None = None,
    geo: dict[str, GeoInfo] | None = None,
    default_dir: str | None = None,
) -> None:
    out = args.report_dir or default_dir
    if not out:
        return
    report = build_report(scan=scan_report, stats=stats, anomalies=anomalies,
                          cves=cves, discovery=discovery, defense=defense, geo=geo)
    paths = write_report(out, report)
    ui.console.print(
        f"Reports written: {paths['json']} and {paths['html']}", style="green"
    )


def _write_report_dict(
    args: argparse.Namespace, report: dict[str, Any], *, default_dir: str | None = None
) -> None:
    """Write a prebuilt report dict to JSON + HTML if an output dir is set."""
    out = args.report_dir or default_dir
    if not out:
        return
    paths = write_report(out, report)
    ui.console.print(
        f"Reports written: {paths['json']} and {paths['html']}", style="green"
    )


def _persist_and_diff(
    args: argparse.Namespace, kind: str, target: str, report: dict[str, Any]
) -> ScanDiff | DiscoveryDiff | None:
    """Save the run and/or diff it against the previous one (when requested).

    Returns the diff to render (None when --diff wasn't asked, there's no prior
    run, or only --save was given). The run is stored *without* the diff — the
    delta is always derived from two stored snapshots.
    """
    if not (args.save or args.diff):
        return None
    conn = store.connect(args.db)
    try:
        delta: ScanDiff | DiscoveryDiff | None = None
        if args.diff:
            prev = store.previous_run(conn, kind, target)
            if prev is None:
                ui.console.print(
                    "No prior run for this target — saving it as the baseline.",
                    style="dim")
            else:
                delta = diff_run(kind, prev, report)
        store.save_run(conn, kind, target, report)
    finally:
        conn.close()
    return delta


def _geoip(args: argparse.Namespace, stats: TrafficStats) -> dict[str, GeoInfo]:
    """Enrich the top talkers with country/ASN when a GeoIP DB was supplied."""
    if not (args.geoip_db or args.geoip_asn):
        return {}
    ips = [ip for ip, _ in stats.top(50)]
    return geoip.enrich(ips, city_db=args.geoip_db, asn_db=args.geoip_asn)


def _analysis_config(args: argparse.Namespace) -> AnalysisConfig | None:
    """Resolve an AnalysisConfig from --config and/or --window (None if neither).

    The --config file is loaded once in ``main`` and stashed on ``args._config``;
    here we just apply the --window override on top.
    """
    cfg = getattr(args, "_config", None)
    if cfg is None and not getattr(args, "window", None):
        return None
    cfg = cfg if cfg is not None else AnalysisConfig()
    if getattr(args, "window", None):
        cfg.window = args.window
    return cfg


def _warn_history_ignored(args: argparse.Namespace) -> None:
    if args.save or args.diff:
        ui.console.print(
            "--save/--diff apply to scan and --discover only; ignored here",
            style="yellow")


def _forward_alerts(
    args: argparse.Namespace,
    anomalies: list[AnomalyFlag],
    defense: list[DefenseAlert] | None = None,
) -> None:
    """Emit anomaly + spoofing alerts to any configured sinks (jsonl/webhook/syslog)."""
    syslog = None
    if args.alert_syslog:
        host, _, port = args.alert_syslog.partition(":")
        syslog = (host or "localhost", int(port) if port else 514)
    results = emit_alerts(
        [*anomalies, *(defense or [])],
        jsonl_path=args.alert_jsonl,
        webhook=args.alert_webhook,
        syslog=syslog,
    )
    for line in results:
        ui.console.print(f"alert: {line}", style="dim")


def _defense_setup(
    args: argparse.Namespace, *, live: bool
) -> tuple[dict[str, str] | None, DefenseConfig]:
    """Build the (baseline, config) the spoofing detector needs.

    On live capture of a network we control, resolve the gateway's real MAC
    (explicit --gateway, else the OS default route) so a later arp-mac-change
    against it fires as *critical*. Offline pcap can't ARP, so we only honour
    --gateway as a critical tag. Baseline learning is trust-on-first-use.
    """
    gateway = args.gateway
    if live and gateway is None:
        gateway = default_gateway(args.iface)  # route table only, no privilege
    config = DefenseConfig(critical_ips={gateway} if gateway else set())

    baseline: dict[str, str] = {}
    if live and gateway and discovery_available():
        try:
            mac = resolve_mac(gateway, iface=args.iface)
        except (OSError, RuntimeError):
            mac = None
        if mac:
            baseline[gateway] = mac
            ui.console.print(
                f"Baseline: gateway {gateway} is-at {mac} — ARP changes against "
                "it will alert as critical",
                style="dim",
            )
    return (baseline or None), config


def _known_hosts(
    args: argparse.Namespace, *, allow_auto: bool = True
) -> set[str] | None:
    """Resolve --known-hosts into a baseline set, or None when unset.

    ``auto`` runs a discovery sweep of the local subnet and uses the responders
    as the baseline, so new devices appearing in capture get flagged without
    listing IPs by hand. ``auto`` only makes sense for live capture; offline pcap
    analysis (``allow_auto=False``) ignores it with a note.
    """
    spec = args.known_hosts
    if not spec:
        return None
    if spec.strip().lower() == "auto":
        if not allow_auto:
            ui.console.print(
                "--known-hosts auto needs a live network; ignoring for --pcap",
                style="yellow")
            return None
        return _autodiscover_known_hosts(args)
    return {h.strip() for h in spec.split(",") if h.strip()}


def _autodiscover_known_hosts(args: argparse.Namespace) -> set[str] | None:
    """Sweep the gateway's subnet to seed the known-host baseline."""
    gateway = args.gateway or default_gateway(args.iface)
    if not gateway:
        ui.console.print(
            "--known-hosts auto: couldn't determine the local subnet; "
            "skipping new-host detection", style="yellow")
        return None
    network = subnet_of(gateway)
    ui.console.print(f"--known-hosts auto: discovering {network}…", style="dim")
    try:
        report = discover(network, iface=args.iface)
    except (OSError, ValueError, RuntimeError) as exc:
        ui.console.print(f"--known-hosts auto failed ({exc}); skipping", style="yellow")
        return None
    hosts = {h.ip for h in report.hosts}
    if hosts:
        ui.console.print(
            f"--known-hosts auto: baseline of {len(hosts)} host(s) on {network}",
            style="dim")
    return hosts or None


def _cve_enrich(
    args: argparse.Namespace, report: ScanReport
) -> dict[int, list[dict[str, Any]]]:
    """Look up candidate CVEs for open ports; print a table; return serialised."""
    if not args.cve:
        return {}
    try:
        by_port = enrich_scan(report, cache_path=DEFAULT_CVE_CACHE)
    except (OSError, ValueError) as exc:  # offline / API / bad-JSON — fail soft
        ui.console.print(f"CVE lookup skipped ({exc})", style="yellow")
        return {}
    if by_port:
        ui.console.print(ui.render_cve_table(by_port))
    return {port: [asdict(e) for e in entries] for port, entries in by_port.items()}


# --- modes ----------------------------------------------------------------- #

def run_scan(args: argparse.Namespace) -> int:
    try:
        targets = _expand_targets(args.target)
    except ValueError as exc:
        ui.console.print(f"Bad target: {exc}", style="bold red")
        return 2
    if len(targets) == 1:
        return _run_scan_one(args, targets[0])
    ui.console.print(f"Scanning {len(targets)} hosts…", style="cyan")
    rc = 0
    for host in targets:
        ui.console.print(f"\n[bold cyan]── {host} ──[/bold cyan]")
        rc |= _run_scan_one(args, host)
    return rc


def _run_scan_one(args: argparse.Namespace, target: str) -> int:
    proto = Protocol.UDP if args.udp else Protocol.TCP
    report = _scan(args, proto, show_progress=not args.grep, target=target)

    if args.grep:
        _print_greppable(report)
    else:
        if report.os_family_guess:
            ui.console.print(
                f"OS family (heuristic, best guess): {report.os_family_guess}",
                style="magenta",
            )
        ui.console.print(ui.render_scan_table(report, show_closed=args.show_closed))
        if not report.open_ports:
            ui.console.print("  no open ports found", style="dim")

    cves = _cve_enrich(args, report)
    report_dict = build_report(scan=report, cves=cves)
    delta = _persist_and_diff(args, "scan", report.target, report_dict)
    if delta is not None:
        ui.console.print(ui.render_scan_diff(delta))  # type: ignore[arg-type]
        report_dict["diff"] = diff_to_dict(delta)
    _write_report_dict(args, report_dict)
    return 0


def run_discover(args: argparse.Namespace) -> int:
    ui.console.print(f"Discovering hosts on {args.target}…", style="cyan")
    try:
        report = discover(args.target, iface=args.iface)
    except (OSError, ValueError, RuntimeError) as exc:
        ui.console.print(f"Discovery failed: {exc}", style="bold red")
        return 1
    ui.console.print(ui.render_discovery_table(report))
    if report.method == "ndp-needs-root":
        ui.console.print(
            "  IPv6 discovery needs raw sockets — re-run with sudo for an NDP sweep",
            style="bold yellow")
    elif not report.hosts:
        ui.console.print("  no hosts responded", style="dim")

    report_dict = build_report(discovery=report)
    delta = _persist_and_diff(args, "discovery", report.network, report_dict)
    if delta is not None:
        ui.console.print(ui.render_discovery_diff(delta))  # type: ignore[arg-type]
        report_dict["diff"] = diff_to_dict(delta)
    _write_report_dict(args, report_dict)
    return 0


def run_history(args: argparse.Namespace) -> int:
    conn = store.connect(args.db)
    try:
        rows = store.list_runs(conn)
    finally:
        conn.close()
    ui.console.print(ui.render_history_table(rows))
    if not rows:
        ui.console.print("  no runs stored yet — use --save or --diff", style="dim")
    return 0


def _save_pcap(args: argparse.Namespace, sniffer: Sniffer) -> None:
    """Write the capture to --write-pcap if requested; fail soft on errors."""
    if not args.write_pcap:
        return
    try:
        n = sniffer.write_pcap(args.write_pcap)
        ui.console.print(f"Wrote {n} packets to {args.write_pcap}", style="green")
    except (RuntimeError, OSError) as exc:
        ui.console.print(f"Could not write pcap: {exc}", style="yellow")


def run_sniff(args: argparse.Namespace) -> int:
    _warn_history_ignored(args)
    if not capture_available():
        ui.console.print(
            "Live capture needs raw-socket privileges (scapy + root/Administrator). "
            "Re-run with sudo to sniff; skipping capture.",
            style="bold yellow",
        )
        return 0

    # Learn the trust-on-first-use baselines *before* capturing, so the gateway
    # MAC and host inventory reflect a clean network and the probe traffic those
    # lookups generate stays out of the capture we analyse.
    baseline, defense_cfg = _defense_setup(args, live=True)
    known = _known_hosts(args)

    def _on_packet(summary: PacketSummary, raw_pkt: Any) -> None:
        ui.print_packet(summary)
        if args.hex:
            ui.console.print(hexdump(bytes(raw_pkt)), style="dim")

    sniffer = Sniffer(iface=args.iface, bpf_filter=args.bpf, count=args.count,
                      keep_raw=bool(args.write_pcap), on_packet=_on_packet)
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

    if sniffer.error is not None:
        ui.console.print(f"Capture failed: {sniffer.error}", style="bold red")
        return 1

    _save_pcap(args, sniffer)
    packets = list(sniffer.packets)
    # A finished live capture → windowed/rate verdict (time-aware).
    anomalies = analyze_stream(packets, _analysis_config(args), known_hosts=known)
    spoofing = detect_spoofing(packets, baseline=baseline, config=defense_cfg)
    geo = _geoip(args, sniffer.stats)
    ui.console.print(ui.render_traffic_table(sniffer.stats, geo=geo))
    ui.console.print(ui.render_defense(spoofing))
    ui.console.print(ui.render_anomalies(anomalies))
    _forward_alerts(args, anomalies, spoofing)
    _write_reports(args, stats=sniffer.stats, anomalies=anomalies, defense=spoofing,
                   geo=geo)
    return 0


def run_pcap(args: argparse.Namespace) -> int:
    _warn_history_ignored(args)
    mode = "windowed" if args.stream else "batch"
    ui.console.print(f"Analyzing capture file ({mode}): {args.pcap}", style="cyan")
    cfg = _analysis_config(args)
    try:
        result = analyze_pcap(args.pcap, cfg, stream=args.stream)
    except (OSError, ValueError, RuntimeError) as exc:
        ui.console.print(f"Could not read capture: {exc}", style="bold red")
        return 1
    baseline, defense_cfg = _defense_setup(args, live=False)
    spoofing = detect_spoofing(result.packets, baseline=baseline, config=defense_cfg)
    detect = analyze_stream if args.stream else analyze
    anomalies = detect(result.packets, cfg,
                       known_hosts=_known_hosts(args, allow_auto=False))
    geo = _geoip(args, result.stats)
    ui.console.print(ui.render_traffic_table(result.stats, geo=geo))
    ui.console.print(ui.render_defense(spoofing))
    ui.console.print(ui.render_anomalies(anomalies))
    _forward_alerts(args, anomalies, spoofing)
    _write_reports(args, stats=result.stats, anomalies=anomalies,
                   defense=spoofing, geo=geo)
    return 0


def run_scan_then_sniff(args: argparse.Namespace) -> int:
    _warn_history_ignored(args)
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
    sniffer = Sniffer(iface=args.iface, bpf_filter=bpf,
                      keep_raw=bool(args.write_pcap))

    ui.console.print(
        f"Sniffing {args.target} ports {open_ports} for {args.duration:g}s "
        "— Ctrl-C to stop early…", style="cyan",
    )
    anomalies: list[AnomalyFlag] = []
    spoofing: list[DefenseAlert] = []

    baseline, defense_cfg = _defense_setup(args, live=True)
    known = _known_hosts(args)
    # Persistent windowed analyzer fed only new packets each frame — O(new) per
    # tick instead of re-scanning the whole buffer (kills the old O(n²)).
    wa = WindowAnalyzer(mode="window", config=_analysis_config(args), known_hosts=known)
    fed = 0

    def _frame() -> Any:
        nonlocal anomalies, spoofing, fed
        snapshot = list(sniffer.packets)  # atomic copy of the capture buffer
        anomalies += wa.update(snapshot[fed:])
        fed = len(snapshot)
        spoofing = detect_spoofing(snapshot, baseline=baseline, config=defense_cfg)
        return ui.render_dashboard(report, sniffer.stats, anomalies, snapshot[-12:],
                                   defense=spoofing, show_closed=args.show_closed)

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

    if sniffer.error is not None:
        ui.console.print(f"Capture failed: {sniffer.error}", style="bold red")

    _save_pcap(args, sniffer)
    _forward_alerts(args, anomalies, spoofing)
    _write_reports(args, scan_report=report, stats=sniffer.stats,
                   anomalies=anomalies, cves=cves, defense=spoofing,
                   geo=_geoip(args, sniffer.stats), default_dir="reports")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)

    args._config = None  # loaded once here; _analysis_config reuses it
    if args.config:
        try:
            args._config = load_config(args.config)
        except (OSError, ValueError) as exc:
            ui.console.print(f"Bad --config: {exc}", style="bold red")
            return 2

    # History listing is an offline DB read — no target, no privileges.
    if args.history:
        return run_history(args)

    # PCAP analysis is offline and needs no privileges, so skip the notice.
    if args.pcap:
        return run_pcap(args)

    ui.print_privilege_notice(privilege_notice())
    if args.discover:
        return run_discover(args)
    if args.scan_then_sniff:
        return run_scan_then_sniff(args)
    if args.sniff:
        return run_sniff(args)
    return run_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
