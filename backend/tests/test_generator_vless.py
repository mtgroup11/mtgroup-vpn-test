"""
MTGroup VPN Ultimate — VLESS/Trojan URI Generator Test Suite
Covers backend/app/generators/generator_vless.py: the REALITY, WebSocket,
gRPC, and Trojan URI builders (including uTLS fingerprint randomisation,
TLS fragmentation, padding, multi-port, host spoofing, and geo-camouflage
SNI override) plus the round-trip parser.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from backend.app.generators.generator_vless import (
    _get_fingerprint,
    generate_trojan_reality_link,
    generate_vless_grpc_link,
    generate_vless_reality_link,
    generate_vless_ws_link,
    parse_vless_link,
)
from backend.app.models import HostSpoofMode


def _params(uri: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlparse(uri).query, keep_blank_values=True).items()}


class TestGetFingerprint:
    def test_passthrough_for_concrete_fingerprint(self):
        assert _get_fingerprint("firefox") == "firefox"

    def test_randomized_is_passed_through_for_the_client_core_to_resolve(self):
        # Xray and sing-box both implement "randomized" themselves; picking
        # one server-side made every refetch return a different link.
        assert _get_fingerprint("randomized") == "randomized"

    def test_unknown_fingerprint_falls_back_to_chrome(self):
        assert _get_fingerprint("netscape") == "chrome"
        assert _get_fingerprint("") == "chrome"


class TestGenerateVlessRealityLink:
    def test_basic_uri_shape(self):
        uri = generate_vless_reality_link(
            address="1.2.3.4", user_uuid="abcd-uuid", public_key="PBK123"
        )
        assert uri.startswith("vless://abcd-uuid@1.2.3.4:443?")
        assert uri.endswith("#MTGroup-REALITY")

    def test_reality_params_present(self):
        p = _params(generate_vless_reality_link(address="1.2.3.4", public_key="PBK123"))
        assert p["security"] == "reality"
        assert p["pbk"] == "PBK123"
        assert p["type"] == "tcp"
        assert p["encryption"] == "none"

    def test_missing_short_id_is_empty_not_invented(self):
        # A random short ID is one the node's Reality inbound doesn't list,
        # so the link could never authenticate. "" is the conventional
        # always-allowed entry.
        uri = generate_vless_reality_link(address="1.2.3.4", public_key="PBK")
        p = _params(uri)
        assert p["sid"] == ""
        assert uri.split("://")[1].split("@")[0]  # a uuid was filled in

    def test_spider_x_is_encoded_exactly_once(self):
        p = _params(generate_vless_reality_link(address="1.2.3.4", public_key="PBK", spider_x="/a b"))
        assert p["spx"] == "/a b"

    def test_ipv6_address_is_bracketed(self):
        uri = generate_vless_reality_link(address="2001:db8::1", user_uuid="u", public_key="PBK")
        assert uri.startswith("vless://u@[2001:db8::1]:443?")
        assert urlparse(uri).hostname == "2001:db8::1"
        assert urlparse(uri).port == 443

    def test_fragment_param_included_when_enabled(self):
        p = _params(
            generate_vless_reality_link(
                address="1.2.3.4",
                public_key="PBK",
                tls_fragment_enabled=True,
                tls_fragment_size_min=10,
                tls_fragment_size_max=20,
                tls_fragment_interval_min=1,
                tls_fragment_interval_max=2,
            )
        )
        assert p["fragment"] == "10-20,1-2"

    def test_fragment_param_omitted_when_disabled(self):
        p = _params(
            generate_vless_reality_link(address="1.2.3.4", public_key="PBK", tls_fragment_enabled=False)
        )
        assert "fragment" not in p

    def test_no_invented_padding_param(self):
        # "padding" is not a VLESS share-link parameter any client reads.
        assert "padding" not in _params(generate_vless_reality_link(address="1.2.3.4", public_key="PBK"))

    def test_multi_port_list_included(self):
        p = _params(
            generate_vless_reality_link(address="1.2.3.4", public_key="PBK", port_list=[443, 8443, 2053])
        )
        assert p["ports"] == "443,8443,2053"

    def test_single_port_list_is_not_emitted(self):
        p = _params(generate_vless_reality_link(address="1.2.3.4", public_key="PBK", port_list=[443]))
        assert "ports" not in p

    def test_client_ip_overrides_sni_via_geo_camouflage(self, monkeypatch):
        from types import SimpleNamespace

        monkeypatch.setattr(
            "backend.app.generators.generator_vless.get_camouflage_for_ip",
            lambda ip: SimpleNamespace(sni="www.digikala.com"),
        )
        p = _params(
            generate_vless_reality_link(
                address="1.2.3.4", public_key="PBK", sni="www.google.com", client_ip="5.6.7.8"
            )
        )
        assert p["sni"] == "www.digikala.com"

    def test_label_is_url_encoded(self):
        uri = generate_vless_reality_link(address="1.2.3.4", public_key="PBK", label="My Node #1")
        assert uri.endswith("#My%20Node%20%231")


class TestGenerateVlessWsLink:
    def test_basic_ws_params(self):
        p = _params(generate_vless_ws_link(address="1.2.3.4", user_uuid="u"))
        assert p["type"] == "ws"
        assert p["security"] == "tls"

    def test_tls_disabled_switches_security_to_none(self):
        p = _params(generate_vless_ws_link(address="1.2.3.4", tls_enabled=False))
        assert p["security"] == "none"

    def test_ws_host_is_used_when_no_spoofing(self):
        p = _params(generate_vless_ws_link(address="1.2.3.4", ws_host="cdn.example.com"))
        assert p["host"] == "cdn.example.com"

    def test_host_spoofing_overrides_ws_host(self):
        p = _params(
            generate_vless_ws_link(
                address="1.2.3.4",
                ws_host="cdn.example.com",
                host_spoof_mode=HostSpoofMode.CDN_FRONT,
                spoofed_host="chat.deepseek.com",
            )
        )
        assert p["host"] == "chat.deepseek.com"

    def test_bug_injection_rewrites_the_path(self):
        p = _params(
            generate_vless_ws_link(
                address="1.2.3.4",
                ws_path="/ws",
                host_spoof_mode=HostSpoofMode.BUG_INJECTION,
                spoofed_host="bug.example.com",
            )
        )
        assert "bug.example.com" in p["path"]

    def test_fragment_requires_both_flags(self):
        with_tls = _params(
            generate_vless_ws_link(address="1.2.3.4", tls_enabled=True, tls_fragment_enabled=True)
        )
        assert "fragment" in with_tls

        without_tls = _params(
            generate_vless_ws_link(address="1.2.3.4", tls_enabled=False, tls_fragment_enabled=True)
        )
        assert "fragment" not in without_tls


class TestGenerateVlessGrpcLink:
    def test_grpc_type_and_service_name(self):
        p = _params(generate_vless_grpc_link(address="1.2.3.4", service_name="svc"))
        assert p["type"] == "grpc"
        assert p["serviceName"] == "svc"

    def test_reality_when_public_key_given(self):
        p = _params(generate_vless_grpc_link(address="1.2.3.4", public_key="PBK", short_id="ffff"))
        assert p["security"] == "reality"
        assert p["pbk"] == "PBK"
        assert p["sid"] == "ffff"

    def test_empty_short_id_when_reality_without_one(self):
        p = _params(generate_vless_grpc_link(address="1.2.3.4", public_key="PBK"))
        assert p["sid"] == ""

    def test_plain_tls_when_no_public_key(self):
        p = _params(generate_vless_grpc_link(address="1.2.3.4"))
        assert p["security"] == "tls"
        assert "pbk" not in p


class TestGenerateTrojanRealityLink:
    def test_scheme_and_password(self):
        uri = generate_trojan_reality_link(address="1.2.3.4", password="p@ss word", public_key="PBK")
        assert uri.startswith("trojan://p%40ss%20word@1.2.3.4:443?")

    def test_reality_params(self):
        p = _params(generate_trojan_reality_link(address="1.2.3.4", password="pw", public_key="PBK"))
        assert p["security"] == "reality"
        assert p["pbk"] == "PBK"
        assert p["sid"] == ""
        # XTLS Vision is VLESS-only; Trojan has no flow.
        assert "flow" not in p

    def test_fragment_toggle(self):
        on = _params(
            generate_trojan_reality_link(
                address="1.2.3.4", password="pw", public_key="PBK", tls_fragment_enabled=True
            )
        )
        assert "fragment" in on

        off = _params(
            generate_trojan_reality_link(
                address="1.2.3.4", password="pw", public_key="PBK", tls_fragment_enabled=False
            )
        )
        assert "fragment" not in off

    def test_client_ip_overrides_sni(self, monkeypatch):
        from types import SimpleNamespace

        monkeypatch.setattr(
            "backend.app.generators.generator_vless.get_camouflage_for_ip",
            lambda ip: SimpleNamespace(sni="www.baidu.com"),
        )
        p = _params(
            generate_trojan_reality_link(
                address="1.2.3.4", password="pw", public_key="PBK", client_ip="5.6.7.8"
            )
        )
        assert p["sni"] == "www.baidu.com"


class TestParseVlessLink:
    def test_round_trips_a_generated_reality_link(self):
        uri = generate_vless_reality_link(
            address="1.2.3.4", port=8443, user_uuid="my-uuid", public_key="PBK", label="Node A"
        )
        parsed = parse_vless_link(uri)
        assert parsed["uuid"] == "my-uuid"
        assert parsed["address"] == "1.2.3.4"
        assert parsed["port"] == 8443
        assert parsed["label"] == "Node A"
        assert parsed["pbk"] == "PBK"

    def test_rejects_non_vless_uri(self):
        with pytest.raises(ValueError, match="Not a valid VLESS URI"):
            parse_vless_link("trojan://pw@1.2.3.4:443?security=reality")

    def test_handles_missing_label_fragment(self):
        parsed = parse_vless_link("vless://uuid@1.2.3.4:443?type=tcp")
        assert parsed["label"] == ""
        assert parsed["type"] == "tcp"
