"""
MTGroup VPN Ultimate — Geo-Adaptive SNI Camouflage Test Suite
Tests backend/app/geo_camouflage.py's IP-to-country detection (private-range
short-circuit, MaxMind and reverse-DNS fallback strategies, both mocked)
and the deterministic SNI selection/rotation logic.
"""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

from backend.app.geo_camouflage import (
    GEO_SNI_MAP,
    CamouflageResult,
    _is_private,
    _ip_to_int,
    detect_country,
    get_available_countries,
    get_camouflage_for_ip,
)


class TestIpToInt:
    def test_converts_valid_ipv4(self):
        assert _ip_to_int("0.0.0.1") == 1
        assert _ip_to_int("255.255.255.255") == 0xFFFFFFFF

    def test_invalid_ip_returns_zero(self):
        assert _ip_to_int("not-an-ip") == 0


class TestIsPrivate:
    def test_10_range_is_private(self):
        assert _is_private("10.1.2.3") is True

    def test_172_16_range_is_private(self):
        assert _is_private("172.16.5.5") is True

    def test_192_168_range_is_private(self):
        assert _is_private("192.168.1.1") is True

    def test_loopback_is_private(self):
        assert _is_private("127.0.0.1") is True

    def test_public_ip_is_not_private(self):
        assert _is_private("8.8.8.8") is False


class TestDetectCountry:
    def test_private_ip_short_circuits_to_global(self):
        # No mocking needed — this must never even attempt a DNS/MaxMind lookup.
        assert detect_country("192.168.1.1") == "GLOBAL"

    def test_maxmind_lookup_used_when_available(self):
        fake_geoip2 = MagicMock()
        fake_response = MagicMock()
        fake_response.country.iso_code = "CN"
        fake_geoip2.database.Reader.return_value.country.return_value = fake_response

        with patch.dict("sys.modules", {"geoip2": fake_geoip2, "geoip2.database": fake_geoip2.database}):
            assert detect_country("8.8.8.8") == "CN"

    def test_maxmind_result_outside_map_falls_back_to_global(self):
        fake_geoip2 = MagicMock()
        fake_response = MagicMock()
        fake_response.country.iso_code = "ZZ"  # not in GEO_SNI_MAP
        fake_geoip2.database.Reader.return_value.country.return_value = fake_response

        with patch.dict("sys.modules", {"geoip2": fake_geoip2, "geoip2.database": fake_geoip2.database}):
            assert detect_country("8.8.8.8") == "GLOBAL"

    def test_reverse_dns_iran_hostname(self):
        with patch("backend.app.geo_camouflage.socket.gethostbyaddr", return_value=("host.example.ir", [], [])):
            assert detect_country("1.2.3.4") == "IR"

    def test_reverse_dns_china_hostname(self):
        with patch("backend.app.geo_camouflage.socket.gethostbyaddr", return_value=("host.example.cn", [], [])):
            assert detect_country("1.2.3.4") == "CN"

    def test_reverse_dns_russia_hostname(self):
        with patch("backend.app.geo_camouflage.socket.gethostbyaddr", return_value=("host.example.ru", [], [])):
            assert detect_country("1.2.3.4") == "RU"

    def test_reverse_dns_turkey_hostname(self):
        with patch("backend.app.geo_camouflage.socket.gethostbyaddr", return_value=("host.example.tr", [], [])):
            assert detect_country("1.2.3.4") == "TR"

    def test_reverse_dns_unrecognised_hostname_falls_back_to_global(self):
        with patch("backend.app.geo_camouflage.socket.gethostbyaddr", return_value=("host.example.com", [], [])):
            assert detect_country("1.2.3.4") == "GLOBAL"

    def test_reverse_dns_failure_falls_back_to_global(self):
        with patch(
            "backend.app.geo_camouflage.socket.gethostbyaddr",
            side_effect=socket.herror("no reverse record"),
        ):
            assert detect_country("1.2.3.4") == "GLOBAL"


class TestGetCamouflageForIp:
    def test_returns_a_camouflage_result(self):
        result = get_camouflage_for_ip("8.8.8.8", preferred_country="CN")
        assert isinstance(result, CamouflageResult)
        assert result.country == "CN"
        assert result.sni in {p["sni"] for p in GEO_SNI_MAP["CN"]}

    def test_same_ip_always_gets_same_sni(self):
        a = get_camouflage_for_ip("203.0.113.5", preferred_country="IR")
        b = get_camouflage_for_ip("203.0.113.5", preferred_country="IR")
        assert a.sni == b.sni
        assert a.server_names == b.server_names

    def test_server_names_starts_with_selected_sni(self):
        result = get_camouflage_for_ip("203.0.113.9", preferred_country="RU")
        assert result.server_names[0] == result.sni

    def test_server_names_has_at_most_three_entries(self):
        result = get_camouflage_for_ip("203.0.113.9", preferred_country="GLOBAL")
        assert len(result.server_names) <= 3

    def test_unknown_preferred_country_falls_back_to_global_profiles(self):
        result = get_camouflage_for_ip("203.0.113.9", preferred_country="ZZ")
        assert result.sni in {p["sni"] for p in GEO_SNI_MAP["GLOBAL"]}

    def test_detects_country_when_not_preferred(self):
        with patch("backend.app.geo_camouflage.detect_country", return_value="TR"):
            result = get_camouflage_for_ip("8.8.8.8")
            assert result.country == "TR"


class TestGetAvailableCountries:
    def test_lists_all_countries_with_counts(self):
        countries = get_available_countries()
        codes = {c["country"] for c in countries}
        assert codes == set(GEO_SNI_MAP.keys())
        for entry in countries:
            assert entry["profiles"] == len(GEO_SNI_MAP[entry["country"]])
            assert entry["example_sni"] == GEO_SNI_MAP[entry["country"]][0]["sni"]
