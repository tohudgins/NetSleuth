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

from flask import Flask, Response, jsonify, render_template, request

from .analyzer import analyze
from .cli import _parse_ports
from .cve import enrich_scan
from .pcap import analyze_pcap
from .reporter import build_report
from .scanner import Protocol, scan
from .sniffer import Sniffer, capture_available

_WEB_DIR = Path(__file__).resolve().parent / "web"

# One capture session for the single local user, guarded by a lock.
_capture_lock = threading.Lock()
_sniffer: Sniffer | None = None


def _capture_payload(snf: Sniffer, new: list[Any]) -> dict[str, Any]:
    anomalies = analyze(list(snf.packets))
    return {
        "running": snf.running,
        "error": str(snf.error) if snf.error else None,
        "packets": [asdict(p) for p in new],
        "stats": {
            "packets": snf.stats.packets,
            "bytes": snf.stats.bytes,
            "by_proto": snf.stats.by_proto,
            "by_ip": [
                {"ip": ip, "packets": c.packets, "bytes": c.bytes}
                for ip, c in snf.stats.top(10)
            ],
        },
        "anomalies": [asdict(a) for a in anomalies],
    }


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(_WEB_DIR / "templates"),
        static_folder=str(_WEB_DIR / "static"),
    )

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
        return jsonify(build_report(scan=report, cves=cves))

    @app.post("/api/pcap")
    def api_pcap() -> Any:
        upload = request.files.get("file")
        if upload is None:
            return jsonify({"error": "no capture file uploaded"}), 400
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            upload.save(tmp.name)
            tmp_path = tmp.name
        try:
            result = analyze_pcap(tmp_path)
        except (OSError, ValueError, RuntimeError) as exc:
            return jsonify({"error": str(exc)}), 400
        finally:
            Path(tmp_path).unlink(missing_ok=True)
        return jsonify(build_report(stats=result.stats, anomalies=result.anomalies))

    @app.post("/api/capture/start")
    def api_capture_start() -> Any:
        global _sniffer
        if not capture_available():
            return jsonify({
                "error": "live capture requires root/Administrator privileges "
                         "(re-run the server with sudo)"
            }), 403
        data = request.get_json(silent=True) or {}
        with _capture_lock:
            if _sniffer is not None and _sniffer.running:
                return jsonify({"error": "a capture is already running"}), 409
            _sniffer = Sniffer(
                iface=data.get("iface") or None,
                bpf_filter=data.get("filter") or None,
            )
            _sniffer.start()
        return jsonify({"status": "started"})

    @app.get("/api/capture/events")
    def api_capture_events() -> Response:
        def stream() -> Any:
            last = 0
            while True:
                snf = _sniffer
                if snf is None:
                    break
                packets = list(snf.packets)  # atomic snapshot of the buffer
                new, last = packets[last:], len(packets)
                yield f"data: {json.dumps(_capture_payload(snf, new))}\n\n"
                if not snf.running:
                    break
                time.sleep(0.5)

        return Response(stream(), mimetype="text/event-stream")

    @app.post("/api/capture/stop")
    def api_capture_stop() -> Any:
        global _sniffer
        with _capture_lock:
            if _sniffer is None:
                return jsonify({"error": "no capture running"}), 409
            _sniffer.stop()
            anomalies = analyze(list(_sniffer.packets))
            payload = build_report(stats=_sniffer.stats, anomalies=anomalies)
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
    args = parser.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        parser.error(
            "refusing to bind to a non-loopback host — this server runs scans "
            "and captures and must not be network-exposed"
        )

    app = create_app()
    print(f"NetSleuth dashboard → http://{args.host}:{args.port}  (Ctrl-C to stop)")
    app.run(host=args.host, port=args.port, threaded=True, debug=args.debug)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
