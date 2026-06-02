"""CVE lookup — Phase 4 (opt-in).

Maps a service banner to a product + version, then queries the NVD CVE API for
known vulnerabilities. This is the one feature that reaches an external service,
so it is **opt-in** (``--cve``), fails soft when offline, and takes an injectable
``fetch`` callable so the logic is fully unit-testable without the network.

Honesty note: version parsing is best-effort and a keyword CVE search returns
*candidates*, not a confirmed-vulnerable verdict. Output is labelled as such.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .scanner import PortState, ScanReport

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# (regex, product) — product=None means group(1)=product, group(2)=version.
_VERSION_PATTERNS: list[tuple[re.Pattern[str], str | None]] = [
    (re.compile(r"OpenSSH[_/](\d+\.\d+(?:\.\d+)?)", re.I), "openssh"),
    (re.compile(r"nginx/(\d[\w.]*)", re.I), "nginx"),
    (re.compile(r"Apache/(\d[\w.]*)", re.I), "apache"),
    (re.compile(r"vsftpd[ /](\d[\w.]*)", re.I), "vsftpd"),
    (re.compile(r"\bServer:\s*([A-Za-z0-9_\-]+)/(\d[\w.]*)", re.I), None),
]


@dataclass
class ServiceVersion:
    product: str
    version: str


@dataclass
class CVEEntry:
    id: str
    summary: str
    cvss: str | None = None


Fetch = Callable[[str], dict[str, Any]]


def parse_version(banner: str | None, service_hint: str | None = None) -> ServiceVersion | None:
    """Best-effort extraction of a product + version from a banner."""
    if not banner:
        return None
    for pattern, product in _VERSION_PATTERNS:
        m = pattern.search(banner)
        if not m:
            continue
        if product is None:
            return ServiceVersion(m.group(1).lower(), m.group(2))
        return ServiceVersion(product, m.group(1))
    return None


def _default_fetch(url: str, *, timeout: float = 10.0) -> dict[str, Any]:  # pragma: no cover - network
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (fixed NVD host)
        return json.loads(resp.read().decode())


def _extract_cvss(metrics: dict[str, Any]) -> str | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key)
        if items:
            data = items[0].get("cvssData", {})
            score = data.get("baseScore")
            if score is not None:
                return str(score)
    return None


def lookup_cves(
    sv: ServiceVersion,
    *,
    fetch: Fetch = _default_fetch,
    max_results: int = 5,
) -> list[CVEEntry]:
    """Query NVD for CVEs matching a product/version keyword search."""
    query = f"{sv.product} {sv.version}"
    url = (f"{_NVD_URL}?keywordSearch={urllib.parse.quote(query)}"
           f"&resultsPerPage={max_results}")
    data = fetch(url)
    entries: list[CVEEntry] = []
    for item in data.get("vulnerabilities", [])[:max_results]:
        cve = item.get("cve", {})
        descs = cve.get("descriptions", [])
        summary = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
        entries.append(CVEEntry(
            id=cve.get("id", ""),
            summary=summary,
            cvss=_extract_cvss(cve.get("metrics", {})),
        ))
    return entries


def enrich_scan(
    report: ScanReport,
    *,
    fetch: Fetch = _default_fetch,
    max_results: int = 5,
) -> dict[int, list[CVEEntry]]:
    """For each open port with a parseable banner, look up candidate CVEs."""
    out: dict[int, list[CVEEntry]] = {}
    cache: dict[tuple[str, str], list[CVEEntry]] = {}
    for p in report.ports:
        if p.state is not PortState.OPEN or not p.banner:
            continue
        sv = parse_version(p.banner, p.service_hint)
        if sv is None:
            continue
        key = (sv.product, sv.version)
        if key not in cache:  # avoid duplicate NVD calls for the same version
            cache[key] = lookup_cves(sv, fetch=fetch, max_results=max_results)
        if cache[key]:
            out[p.port] = cache[key]
    return out
