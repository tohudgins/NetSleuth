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
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .scanner import PortState, ScanReport

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Persistent CVE cache (reuses the ~/.netsleuth dir the history DB lives in), so
# repeat lookups are instant and work offline. Opt-in: only the CLI/web pass a
# cache_path; library calls default to None (no disk touched).
DEFAULT_CVE_CACHE = Path.home() / ".netsleuth" / "cve-cache.json"
_CACHE_TTL = 7 * 24 * 3600.0  # 7 days

# (regex, product) — product=None means group(1)=product, group(2)=version.
_VERSION_PATTERNS: list[tuple[re.Pattern[str], str | None]] = [
    (re.compile(r"OpenSSH[_/](\d+\.\d+(?:\.\d+)?)", re.I), "openssh"),
    (re.compile(r"nginx/(\d[\w.]*)", re.I), "nginx"),
    (re.compile(r"Apache/(\d[\w.]*)", re.I), "apache"),
    (re.compile(r"vsftpd[ /](\d[\w.]*)", re.I), "vsftpd"),
    (re.compile(r"\bServer:\s*([A-Za-z0-9_\-]+)/(\d[\w.]*)", re.I), None),
]

# product -> (cpe vendor, cpe product) for an exact, version-aware NVD CPE match.
# Best-effort and partial (labeled): unknown products fall back to keyword search.
_CPE_MAP: dict[str, tuple[str, str]] = {
    "openssh": ("openbsd", "openssh"),
    "nginx": ("nginx", "nginx"),
    "apache": ("apache", "http_server"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
}


@dataclass
class ServiceVersion:
    product: str
    version: str


@dataclass
class CVEEntry:
    id: str
    summary: str
    cvss: str | None = None
    match: str = "keyword"  # "cpe" (precise) | "keyword" (candidate)


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


def _query_url(sv: ServiceVersion, max_results: int) -> tuple[str, str]:
    """Build the NVD URL + match kind: precise CPE when we can, else keyword."""
    cpe = _CPE_MAP.get(sv.product)
    if cpe is not None:
        vendor, product = cpe
        cpe_str = f"cpe:2.3:a:{vendor}:{product}:{sv.version}:*:*:*:*:*:*:*"
        url = (f"{_NVD_URL}?virtualMatchString={urllib.parse.quote(cpe_str)}"
               f"&resultsPerPage={max_results}")
        return url, "cpe"
    query = f"{sv.product} {sv.version}"
    url = (f"{_NVD_URL}?keywordSearch={urllib.parse.quote(query)}"
           f"&resultsPerPage={max_results}")
    return url, "keyword"


# --- persistent cache (fail-soft) ------------------------------------------ #

def _cache_load(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}  # missing or corrupt — treat as empty


def _cache_get(cache: dict[str, Any], key: str, ttl: float) -> list[CVEEntry] | None:
    rec = cache.get(key)
    if not isinstance(rec, dict):
        return None
    try:
        fetched = datetime.fromisoformat(rec["fetched"])
        age = (datetime.now(timezone.utc) - fetched).total_seconds()
    except (KeyError, ValueError, TypeError):
        return None
    if age > ttl:
        return None
    return [CVEEntry(**e) for e in rec.get("entries", [])]


def _cache_put(path: Path, cache: dict[str, Any], key: str,
               entries: list[CVEEntry]) -> None:
    cache[key] = {
        "fetched": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "entries": [asdict(e) for e in entries],
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache), encoding="utf-8")
    except OSError:
        pass  # cache is a best-effort optimisation, never fatal


def lookup_cves(
    sv: ServiceVersion,
    *,
    fetch: Fetch = _default_fetch,
    max_results: int = 5,
    cache_path: str | Path | None = None,
    ttl: float = _CACHE_TTL,
) -> list[CVEEntry]:
    """Query NVD for CVEs matching a service version (precise CPE when known).

    With ``cache_path`` set, results are served from / written to a JSON cache so
    repeat lookups are offline and instant.
    """
    url, match = _query_url(sv, max_results)
    key = f"{match}|{sv.product}|{sv.version}"
    cache: dict[str, Any] = {}
    if cache_path is not None:
        cache = _cache_load(Path(cache_path))
        hit = _cache_get(cache, key, ttl)
        if hit is not None:
            return hit

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
            match=match,
        ))

    if cache_path is not None:
        _cache_put(Path(cache_path), cache, key, entries)
    return entries


def enrich_scan(
    report: ScanReport,
    *,
    fetch: Fetch = _default_fetch,
    max_results: int = 5,
    cache_path: str | Path | None = None,
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
            cache[key] = lookup_cves(sv, fetch=fetch, max_results=max_results,
                                     cache_path=cache_path)
        if cache[key]:
            out[p.port] = cache[key]
    return out
