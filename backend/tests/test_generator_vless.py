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
    return {k: v[0] for k, v in parse_qs(urlparse(uri).query).items()}


class TestGetFingerprint:
    def test_passthrough_for_concrete_fingerprint(self):
        assert _get_fingerprint("firefox") == "firefox"

    def test_randomized_picks_from_the_known_set(self):
        picked = {_get_fingerprint("randomized") for _ in range(50)}
        assert picked <= {"chrome", "firefox", "safari", "edge", "ios", "android"}
        assert picked  # non-empty


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

    def test_generates_uuid_and_short_id_when_omitted(self):
        uri = generate_vless_reality_link(address="1.2.3.4", public_key="PBK")
        p = _params(uri)
        assert len(p["sid"]) == 8  # secrets.token_hex(4)
        assert uri.split("://")[1].split("@")[0]  # a uuid was filled in

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

    def test_padding_param_included_when_enabled(self):
        p = _params(
            generate_vless_reality_link(
                address="1.2.3.4", public_key="PBK", padding_enabled=True, padding_min=8, padding_max=16
            )
        )
        assert p["padding"] == "8-16"

    def test_padding_param_omitted_when_disabled(self):
        p = _params(generate_vless_reality_link(address="1.2.3.4", public_key="PBK", padding_enabled=False))
        assert "padding" not in p

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

    def test_generates_short_id_when_reality_without_one(self):
        p = _params(generate_vless_grpc_link(address="1.2.3.4", public_key="PBK"))
        assert len(p["sid"]) == 8

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
        assert len(p["sid"]) == 8

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
