"""Unit tests for GeoIP enrichment. No real MaxMind DB — readers are faked."""

from __future__ import annotations

from netsleuth import geoip
from netsleuth.geoip import GeoInfo, enrich, lookup


class _FakeCity:
    """Mimics geoip2's reader.city(ip).country.iso_code shape."""

    class _Resp:
        class country:  # noqa: N801 - mirrors geoip2's attribute path
            iso_code = "US"

    def city(self, ip):
        if ip == "8.8.8.8":
            return self._Resp()
        raise KeyError("not found")  # geoip2 raises AddressNotFound; any Exception


class _FakeAsn:
    class _Resp:
        autonomous_system_number = 15169
        autonomous_system_organization = "GOOGLE"

    def asn(self, ip):
        if ip == "8.8.8.8":
            return self._Resp()
        raise KeyError("not found")


def test_lookup_public_ip_with_both_readers():
    info = lookup("8.8.8.8", city_reader=_FakeCity(), asn_reader=_FakeAsn())
    assert info == GeoInfo(country="US", asn="AS15169", org="GOOGLE")


def test_lookup_skips_private_ip():
    assert lookup("10.0.0.5", city_reader=_FakeCity(), asn_reader=_FakeAsn()) is None
    assert lookup("127.0.0.1", city_reader=_FakeCity()) is None


def test_lookup_returns_none_when_not_found():
    # Public IP, but the DB has no record → tolerated, returns None.
    assert lookup("1.2.3.4", city_reader=_FakeCity(), asn_reader=_FakeAsn()) is None


def test_lookup_partial_city_only():
    info = lookup("8.8.8.8", city_reader=_FakeCity())
    assert info is not None and info.country == "US" and info.asn is None


def test_enrich_noop_without_geoip(monkeypatch):
    # geoip2 not installed (or no DB) → empty map, never touches a reader.
    monkeypatch.setattr(geoip, "_GEOIP_AVAILABLE", False)
    assert enrich(["8.8.8.8"], city_db="x.mmdb") == {}


def test_enrich_noop_without_db():
    assert enrich(["8.8.8.8"]) == {}  # no DB paths given


def test_enrich_degrades_when_reader_fails(monkeypatch):
    # geoip2 "available" but opening the DB fails (here it isn't importable, so
    # Reader() raises inside enrich) — must degrade to {}, never propagate.
    monkeypatch.setattr(geoip, "_GEOIP_AVAILABLE", True)
    assert enrich(["8.8.8.8"], city_db="/no/such/file.mmdb") == {}
