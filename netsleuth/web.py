"""NetSleuth web dashboard — Flask (synchronous, threaded).

No asyncio (CLAUDE.md rule #3): Flask serves each request in a thread, the
``Sniffer`` owns its own capture thread, and live updates are pushed with a
*synchronous* Server-Sent-Events generator. The whole stack stays threads-only.

This is a thin presentation layer: every endpoint composes the existing logic
(``scanner.scan``, ``pcap.analyze_pcap``, the ``Sniffer``, ``analyzer.analyze``)
and returns ``reporter.build_report(...)`` as JSON for the browser to render.

Security: binds to 127.0.0.1 only — this server runs scans/captures and must
never be exposed on the network. Live capture needs root; capture endpoints
return 403 (not a crash) when unprivileged.
"""

from __future__ import annotations

import argparse
import json
import tempfile
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from collections import OrderedDict

from flask import Flask, Response, jsonify, render_template, request

from . import store
from .analyzer import AnomalyFlag, WindowAnalyzer, analyze_stream
from .cli import _parse_ports
from .cve import enrich_scan
from .defense import DefenseConfig, detect_spoofing
from .diff import diff_run, to_dict
from .discovery import default_gateway, discover, discovery_available, resolve_mac
from .pcap import analyze_pcap
from .reporter import build_report
from .scanner import Protocol, scan
from .sniffer import PacketSummary, Sniffer, capture_available, hexdump

_WEB_DIR = Path(__file__).resolve().parent / "web"

# One capture session for the single local user, guarded by a lock.
_capture_lock = threading.Lock()
_sniffer: Sniffer | None = None

# Spoofing-detector inputs learned at capture start (gateway MAC baseline +
# critical-IP config), so the live feed can raise a critical arp-mac-change.
_live_baseline: dict[str, str] | None = None
_live_defense_cfg = DefenseConfig()

# Per-session streaming anomaly engine: fed only new packets each SSE tick (so
# detection is O(new), not a re-scan of the whole buffer), with the rising-edge
# flags it raises accumulated for display.
_live_analyzer: WindowAnalyzer | None = None
_live_flags: list[AnomalyFlag] = []

# Bounded store of recent raw frames so the UI can drill into any packet's
# hexdump on demand without streaming every byte over SSE. Keyed by the packet's
# absolute index in the capture (which matches its position in snf.packets), so
# the browser can request /api/capture/frame/<i> for the row it clicked. Capped
# to keep memory flat on long captures; older frames expire.
_RAW_CAP = 2000
_raw_frames: "OrderedDict[int, bytes]" = OrderedDict()
_raw_next = 0  # next absolute index; matches the packet's position in snf.packets
_frames_lock = threading.Lock()


def _learn_baseline(
    gateway: str | None, iface: str | None
) -> tuple[dict[str, str] | None, DefenseConfig]:
    """Trust-on-first-use gateway MAC + critical-IP config for live capture.

    Mirrors the CLI's ``_defense_setup``: resolve the gateway (explicit or the
    OS default route) and learn its MAC so a later change alerts as critical.
    """
    gw = gateway or default_gateway(iface)
    config = DefenseConfig(critical_ips={gw} if gw else set())
    baseline: dict[str, str] = {}
    if gw and discovery_available():
        try:
            mac = resolve_mac(gw, iface=iface)
        except (OSError, RuntimeError):
            mac = None
        if mac:
            baseline[gw] = mac
    return (baseline or None), config


def _store_raw(summary: PacketSummary, raw_pkt: Any) -> None:
    """Capture-thread callback: retain a bounded window of raw frames."""
    global _raw_next
    with _frames_lock:
        _raw_frames[_raw_next] = bytes(raw_pkt)
        _raw_next += 1
        while len(_raw_frames) > _RAW_CAP:
            _raw_frames.popitem(last=False)


def _capture_payload(
    snf: Sniffer, new: list[PacketSummary], start: int
) -> dict[str, Any]:
    packets = list(snf.packets)
    if _live_analyzer is not None:
        _live_flags.extend(_live_analyzer.update(new))  # O(new) streaming
    spoofing = detect_spoofing(packets, baseline=_live_baseline,
                               config=_live_defense_cfg)
    return {
        "running": snf.running,
        "error": str(snf.error) if snf.error else None,
        "packets": [{**asdict(p), "i": start + n} for n, p in enumerate(new)],
        "stats": {
            "packets": snf.stats.packets,
            "bytes": snf.stats.bytes,
            "by_proto": snf.stats.by_proto,
            "by_ip": [
                {"ip": ip, "packets": c.packets, "bytes": c.bytes}
                for ip, c in snf.stats.top(10)
            ],
        },
        "anomalies": [asdict(a) for a in _live_flags],
        "defense": [asdict(a) for a in spoofing],
    }


def _maybe_persist(
    app: Flask, data: dict[str, Any], kind: str, target: str, report: dict[str, Any]
) -> None:
    """Save and/or diff a scan/discovery run when the request asks for it.

    Saves the *base* report (no diff), then attaches a `diff` to the response so
    the browser can render "what changed" without a second round-trip. Uses a
    fresh sqlite connection — they aren't safe to share across Flask threads.
    """
    if not (data.get("save") or data.get("diff")):
        return
    conn = store.connect(app.config["NS_DB"])
    try:
        delta = None
        if data.get("diff"):
            prev = store.previous_run(conn, kind, target)
            if prev is not None:
                delta = diff_run(kind, prev, report)
        store.save_run(conn, kind, target, report)
    finally:
        conn.close()
    if delta is not None:
        report["diff"] = to_dict(delta)


def _run_identity(report: dict[str, Any]) -> tuple[str, str] | None:
    """(kind, target) for a stored run, or None if it isn't diffable."""
    if "scan" in report:
        return "scan", str(report["scan"]["target"])
    if "discovery" in report:
        return "discovery", str(report["discovery"]["network"])
    return None


def create_app(db_path: str | Path | None = None) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(_WEB_DIR / "templates"),
        static_folder=str(_WEB_DIR / "static"),
    )
    app.config["NS_DB"] = str(db_path or store.DEFAULT_DB)

    @app.get("/")
    def index() -> str:
        return render_template("dashboard.html")

    @app.post("/api/scan")
    def api_scan() -> Any:
        data = request.get_json(silent=True) or {}
        target = str(data.get("target") or "127.0.0.1")
        ports = _parse_ports(str(data.get("ports") or "1-1024"))
        proto = Protocol.UDP if data.get("udp") else Protocol.TCP
        report = scan(
            target, ports, proto=proto,
            timeout=float(data.get("timeout") or 1.0),
            force_connect=bool(data.get("connect")),
        )
        cves: dict[int, list[dict[str, Any]]] = {}
        if data.get("cve"):
            try:
                by_port = enrich_scan(report)
                cves = {p: [asdict(e) for e in es] for p, es in by_port.items()}
            except (OSError, ValueError):
                cves = {}
        report_dict = build_report(scan=report, cves=cves)
        _maybe_persist(app, data, "scan", target, report_dict)
        return jsonify(report_dict)

    @app.post("/api/pcap")
    def api_pcap() -> Any:
        upload = request.files.get("file")
        if upload is None:
            return jsonify({"error": "no capture file uploaded"}), 400
        stream = str(request.form.get("stream", "")).lower() in ("1", "true", "on")
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            upload.save(tmp.name)
            tmp_path = tmp.name
        try:
            result = analyze_pcap(tmp_path, stream=stream)
        except (OSError, ValueError, RuntimeError) as exc:
            return jsonify({"error": str(exc)}), 400
        finally:
            Path(tmp_path).unlink(missing_ok=True)
        return jsonify(build_report(
            stats=result.stats, anomalies=result.anomalies,
            defense=detect_spoofing(result.packets),
        ))

    @app.post("/api/discover")
    def api_discover() -> Any:
        data = request.get_json(silent=True) or {}
        network = str(data.get("network") or "127.0.0.1")
        try:
            report = discover(network, iface=data.get("iface") or None)
        except (OSError, ValueError, RuntimeError) as exc:
            return jsonify({"error": str(exc)}), 400
        report_dict = build_report(discovery=report)
        _maybe_persist(app, data, "discovery", network, report_dict)
        return jsonify(report_dict)

    @app.get("/api/history")
    def api_history() -> Any:
        conn = store.connect(app.config["NS_DB"])
        try:
            rows = store.list_runs(
                conn, kind=request.args.get("kind") or None,
                target=request.args.get("target") or None)
        finally:
            conn.close()
        return jsonify({"runs": [dict(r) for r in rows]})

    @app.get("/api/history/<int:run_id>")
    def api_history_run(run_id: int) -> Any:
        conn = store.connect(app.config["NS_DB"])
        try:
            report = store.get_run(conn, run_id)
        finally:
            conn.close()
        if report is None:
            return jsonify({"error": "run not found"}), 404
        return jsonify(report)

    @app.get("/api/history/<int:run_id>/diff")
    def api_history_diff(run_id: int) -> Any:
        conn = store.connect(app.config["NS_DB"])
        try:
            report = store.get_run(conn, run_id)
            if report is None:
                return jsonify({"error": "run not found"}), 404
            identity = _run_identity(report)
            if identity is None:
                return jsonify({"diff": None})
            kind, target = identity
            prev = store.previous_run(conn, kind, target, before_id=run_id)
        finally:
            conn.close()
        if prev is None:
            return jsonify({"diff": None})
        delta = diff_run(kind, prev, report)
        return jsonify({"diff": to_dict(delta) if delta is not None else None})

    @app.post("/api/capture/start")
    def api_capture_start() -> Any:
        global _sniffer
        if not capture_available():
            return jsonify({
                "error": "live capture requires root/Administrator privileges "
                         "(re-run the server with sudo)"
            }), 403
        global _raw_next, _live_baseline, _live_defense_cfg
        global _live_analyzer, _live_flags
        data = request.get_json(silent=True) or {}
        iface = data.get("iface") or None
        with _capture_lock:
            if _sniffer is not None and _sniffer.running:
                return jsonify({"error": "a capture is already running"}), 409
            with _frames_lock:  # fresh frame window per capture session
                _raw_frames.clear()
                _raw_next = 0
            _live_analyzer = WindowAnalyzer(mode="window")  # fresh streaming engine
            _live_flags = []
            _live_baseline, _live_defense_cfg = _learn_baseline(
                data.get("gateway") or None, iface)
            _sniffer = Sniffer(
                iface=iface,
                bpf_filter=data.get("filter") or None,
                on_packet=_store_raw,
            )
            _sniffer.start()
        return jsonify({"status": "started", "baseline": _live_baseline or {}})

    @app.get("/api/capture/events")
    def api_capture_events() -> Response:
        def stream() -> Any:
            last = 0
            while True:
                snf = _sniffer
                if snf is None:
                    break
                packets = list(snf.packets)  # atomic snapshot of the buffer
                new, start, last = packets[last:], last, len(packets)
                yield f"data: {json.dumps(_capture_payload(snf, new, start))}\n\n"
                if not snf.running:
                    break
                time.sleep(0.5)

        return Response(stream(), mimetype="text/event-stream")

    @app.get("/api/capture/frame/<int:idx>")
    def api_capture_frame(idx: int) -> Any:
        """Return our own hexdump of one captured frame for the drill-down view."""
        with _frames_lock:
            raw = _raw_frames.get(idx)
        if raw is None:
            return jsonify({"error": "frame not retained (expired or out of range)"}), 404
        return jsonify({"index": idx, "length": len(raw), "hex": hexdump(raw)})

    @app.post("/api/capture/stop")
    def api_capture_stop() -> Any:
        global _sniffer
        with _capture_lock:
            if _sniffer is None:
                return jsonify({"error": "no capture running"}), 409
            _sniffer.stop()
            packets = list(_sniffer.packets)
            payload = build_report(
                stats=_sniffer.stats,
                anomalies=analyze_stream(packets),  # complete windowed verdict
                defense=detect_spoofing(packets, baseline=_live_baseline,
                                        config=_live_defense_cfg),
            )
        return jsonify(payload)

    return app


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netsleuth-web",
        description="NetSleuth web dashboard. Binds to localhost only; "
        "run with sudo to enable live capture.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--db", default=str(store.DEFAULT_DB), metavar="PATH",
                        help="history DB path (default: ~/.netsleuth/history.db)")
    args = parser.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        parser.error(
            "refusing to bind to a non-loopback host — this server runs scans "
            "and captures and must not be network-exposed"
        )

    app = create_app(db_path=args.db)
    print(f"NetSleuth dashboard → http://{args.host}:{args.port}  (Ctrl-C to stop)")
    app.run(host=args.host, port=args.port, threaded=True, debug=args.debug)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
