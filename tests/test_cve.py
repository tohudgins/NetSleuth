"""Unit tests for CVE lookup — Phase 4. Network is mocked via injected fetch."""

from __future__ import annotations

from netsleuth.cve import enrich_scan, lookup_cves, parse_version
from netsleuth.scanner import PortResult, PortState, Protocol, ScanReport

# Minimal NVD-shaped response.
_FAKE_NVD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-23017",
                "descriptions": [
                    {"lang": "en", "value": "nginx resolver off-by-one heap write"},
                    {"lang": "es", "value": "..."},
                ],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 8.1}}],
                },
            }
        }
    ]
}


def test_parse_version_nginx():
    sv = parse_version("HTTP/1.1 200 OK\r\nServer: nginx/1.31.1")
    assert sv is not None
    assert sv.product == "nginx" and sv.version == "1.31.1"


def test_parse_version_openssh():
    sv = parse_version("SSH-2.0-OpenSSH_9.0p1 Debian")
    assert sv is not None
    assert sv.product == "openssh" and sv.version == "9.0"


def test_parse_version_generic_server_header():
    sv = parse_version("Server: lighttpd/1.4.59")
    assert sv is not None
    assert sv.product == "lighttpd" and sv.version == "1.4.59"


def test_parse_version_none_when_no_match():
    assert parse_version("220 some banner with no version") is None
    assert parse_version(None) is None


def test_lookup_cves_parses_entries():
    from netsleuth.cve import ServiceVersion

    entries = lookup_cves(ServiceVersion("nginx", "1.31.1"), fetch=lambda _url: _FAKE_NVD)
    assert len(entries) == 1
    assert entries[0].id == "CVE-2021-23017"
    assert entries[0].cvss == "8.1"
    assert "nginx" in entries[0].summary


def test_enrich_scan_maps_open_ports():
    report = ScanReport(
        target="127.0.0.1", scan_type="connect", proto=Protocol.TCP,
        ports=[
            PortResult(80, PortState.OPEN, Protocol.TCP,
                       "Server: nginx/1.31.1", "http"),
            PortResult(81, PortState.CLOSED, Protocol.TCP),
        ],
    )
    out = enrich_scan(report, fetch=lambda _url: _FAKE_NVD)
    assert set(out) == {80}
    assert out[80][0].id == "CVE-2021-23017"


def test_enrich_scan_caches_duplicate_versions():
    # Two open ports running the same nginx version -> only one NVD call.
    calls = {"n": 0}

    def _counting_fetch(_url):
        calls["n"] += 1
        return _FAKE_NVD

    report = ScanReport(
        target="127.0.0.1", scan_type="connect", proto=Protocol.TCP,
        ports=[
            PortResult(80, PortState.OPEN, Protocol.TCP, "Server: nginx/1.31.1", "http"),
            PortResult(8080, PortState.OPEN, Protocol.TCP, "Server: nginx/1.31.1", "http"),
        ],
    )
    out = enrich_scan(report, fetch=_counting_fetch)
    assert set(out) == {80, 8080}
    assert calls["n"] == 1  # cached, not queried twice
