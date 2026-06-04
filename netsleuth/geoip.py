"""GeoIP / ASN enrichment for external IPs — opt-in, offline.

Adds country + ASN context to the *public* IPs a capture talks to (private and
loopback addresses are skipped). This is the one place we'd use a third-party
geo database, so it's strictly opt-in and degrades to nothing:

  * ``geoip2`` is an **optional** dependency (guarded import, like scapy).
  * the MaxMind GeoLite2 ``.mmdb`` files are **user-supplied** (licensed — we
    can't bundle them); pass their paths via ``--geoip-db`` / ``--geoip-asn``.

When either is missing, ``enrich`` returns ``{}`` and the rest of the tool is
unchanged. The per-IP ``lookup`` takes injectable readers so it is unit-testable
without a real database.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import geoip2.database

    _GEOIP_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    _GEOIP_AVAILABLE = False


@dataclass
class GeoInfo:
    country: str | None = None
    asn: str | None = None
    org: str | None = None


def _is_public(ip: str) -> bool:
    """True for a globally-routable address (skip private/loopback/link-local)."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def lookup(
    ip: str, *, city_reader: Any = None, asn_reader: Any = None
) -> GeoInfo | None:
    """Country/ASN for one public IP, or None (private, or nothing found).

    Each reader is a MaxMind ``geoip2.database.Reader`` (or a compatible fake);
    a per-IP miss in either DB is tolerated, not fatal.
    """
    if not _is_public(ip):
        return None
    country = asn = org = None
    if city_reader is not None:
        try:
            country = city_reader.city(ip).country.iso_code
        except Exception:  # AddressNotFound / bad DB — best effort
            pass
    if asn_reader is not None:
        try:
            resp = asn_reader.asn(ip)
            asn = f"AS{resp.autonomous_system_number}"
            org = resp.autonomous_system_organization
        except Exception:
            pass
    if country or asn:
        return GeoInfo(country=country, asn=asn, org=org)
    return None


def enrich(
    ips: list[str],
    *,
    city_db: str | Path | None = None,
    asn_db: str | Path | None = None,
) -> dict[str, GeoInfo]:
    """Map public IPs → GeoInfo using the supplied MaxMind DBs.

    Returns ``{}`` (no-op) when ``geoip2`` isn't installed or no DB was given.
    """
    if not _GEOIP_AVAILABLE or not (city_db or asn_db):
        return {}
    city_reader = asn_reader = None
    try:
        # Reader() construction is inside the try: a missing/corrupt .mmdb raises
        # (FileNotFoundError or maxminddb.InvalidDatabaseError) and must degrade,
        # never crash the scan/capture that asked for enrichment.
        if city_db:
            city_reader = geoip2.database.Reader(str(city_db))
        if asn_db:
            asn_reader = geoip2.database.Reader(str(asn_db))
        out: dict[str, GeoInfo] = {}
        for ip in ips:
            info = lookup(ip, city_reader=city_reader, asn_reader=asn_reader)
            if info is not None:
                out[ip] = info
        logger.debug("geoip: enriched %d/%d IPs", len(out), len(ips))
        return out
    except Exception as exc:  # bad/missing DB — best-effort, never fatal
        logger.warning("geoip: disabled (%s)", exc)
        return {}
    finally:
        if city_reader is not None:
            city_reader.close()
        if asn_reader is not None:
            asn_reader.close()
