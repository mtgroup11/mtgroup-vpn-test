"""
MTGroup VPN Ultimate — Hysteria2 & TUIC v5 Generator Test Suite
Covers backend/app/generators/generator_hysteria2.py and generator_tuic.py:
the client URI builders (obfuscation, bandwidth hints, port hopping,
SNI-less mode) and the Sing-box / server-side JSON config builders.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from backend.app.generators.generator_hysteria2 import (
    generate_hysteria2_json_config,
    generate_hysteria2_link,
    generate_hysteria2_server_config,
)
from backend.app.generators.generator_tuic import (
    generate_tuic_link,
    generate_tuic_server_config,
    generate_tuic_singbox_config,
)


def _params(uri: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlparse(uri).query).items()}


# ---------------------------------------------------------------------------
# Hysteria2 URI
# ---------------------------------------------------------------------------

class TestHysteria2Link:
    def test_basic_uri_shape(self):
        uri = generate_hysteria2_link(address="1.2.3.4", password="pw")
        assert uri.startswith("hysteria2://pw@1.2.3.4:443?")
        assert uri.endswith("#MTGroup-Hysteria2")

    def test_password_is_url_encoded(self):
        uri = generate_hysteria2_link(address="1.2.3.4", password="p@ss/word")
        assert uri.startswith("hysteria2://p%40ss%2Fword@")

    def test_bandwidth_hints_always_present(self):
        p = _params(generate_hysteria2_link(address="1.2.3.4", password="pw", up_mbps=20, down_mbps=80))
        assert p["up"] == "20"
        assert p["down"] == "80"

    def test_sni_included_when_given(self):
        p = _params(generate_hysteria2_link(address="1.2.3.4", password="pw", sni="www.bing.com"))
        assert p["sni"] == "www.bing.com"

    def test_sni_omitted_when_none(self):
        # Hysteria2's headline feature is SNI-less operation — the param
        # must genuinely be absent, not empty.
        p = _params(generate_hysteria2_link(address="1.2.3.4", password="pw", sni=None))
        assert "sni" not in p

    def test_insecure_flag(self):
        p = _params(generate_hysteria2_link(address="1.2.3.4", password="pw", insecure=True))
        assert p["insecure"] == "1"

    def test_obfs_requires_both_type_and_password(self):
        both = _params(
            generate_hysteria2_link(
                address="1.2.3.4", password="pw", obfs_type="salamander", obfs_password="secret"
            )
        )
        assert both["obfs"] == "salamander"
        assert both["obfs-password"] == "secret"

        type_only = _params(
            generate_hysteria2_link(address="1.2.3.4", password="pw", obfs_type="salamander", obfs_password=None)
        )
        assert "obfs" not in type_only

    def test_mtu_discovery_toggle(self):
        on = _params(generate_hysteria2_link(address="1.2.3.4", password="pw", disable_mtu_discovery=True))
        assert on["disable_mtu_discovery"] == "1"

        off = _params(generate_hysteria2_link(address="1.2.3.4", password="pw", disable_mtu_discovery=False))
        assert "disable_mtu_discovery" not in off

    def test_port_hopping_params(self):
        p = _params(
            generate_hysteria2_link(
                address="1.2.3.4", password="pw", hop_interval=30, port_list=[443, 8443, 2053]
            )
        )
        assert p["hop-interval"] == "30"
        assert p["mport"] == "443,8443,2053"

    def test_single_port_list_is_not_emitted(self):
        p = _params(generate_hysteria2_link(address="1.2.3.4", password="pw", port_list=[443]))
        assert "mport" not in p


class TestHysteria2JsonConfig:
    def test_core_fields(self):
        cfg = generate_hysteria2_json_config(address="1.2.3.4", port=8443, password="pw")
        assert cfg["type"] == "hysteria2"
        assert cfg["server"] == "1.2.3.4"
        assert cfg["server_port"] == 8443
        assert cfg["password"] == "pw"

    def test_sni_sets_server_name_and_clears_disable_sni(self):
        cfg = generate_hysteria2_json_config(address="1.2.3.4", password="pw", sni="www.bing.com")
        assert cfg["tls"]["server_name"] == "www.bing.com"
        assert cfg["tls"]["disable_sni"] is False

    def test_no_sni_enables_disable_sni(self):
        cfg = generate_hysteria2_json_config(address="1.2.3.4", password="pw", sni=None)
        assert cfg["tls"]["disable_sni"] is True
        assert "server_name" not in cfg["tls"]

    def test_alpn_is_h3(self):
        cfg = generate_hysteria2_json_config(address="1.2.3.4", password="pw")
        assert cfg["tls"]["alpn"] == ["h3"]

    def test_obfs_block_requires_both_values(self):
        with_obfs = generate_hysteria2_json_config(
            address="1.2.3.4", password="pw", obfs_type="salamander", obfs_password="s"
        )
        assert with_obfs["obfs"]["type"] == "salamander"

        without = generate_hysteria2_json_config(address="1.2.3.4", password="pw", obfs_password=None)
        assert "obfs" not in without

    def test_lazy_start_flag(self):
        assert generate_hysteria2_json_config(address="1.2.3.4", password="pw", lazy_start=True)["lazy"] is True
        assert "lazy" not in generate_hysteria2_json_config(address="1.2.3.4", password="pw", lazy_start=False)


class TestHysteria2ServerConfig:
    def test_listen_and_auth(self):
        cfg = generate_hysteria2_server_config(listen_port=8443, password="pw")
        assert cfg["listen"] == ":8443"
        assert cfg["auth"] == {"type": "password", "password": "pw"}

    def test_masquerade_proxies_to_decoy_url(self):
        cfg = generate_hysteria2_server_config(password="pw", masquerade_url="https://www.apple.com")
        assert cfg["masquerade"] == {"type": "proxy", "url": "https://www.apple.com"}

    def test_bandwidth_strings(self):
        cfg = generate_hysteria2_server_config(password="pw", up_mbps=500, down_mbps=900)
        assert cfg["bandwidth"] == {"up": "500 mbps", "down": "900 mbps"}

    def test_quic_block_only_when_mtu_discovery_disabled(self):
        assert generate_hysteria2_server_config(password="pw", disable_mtu_discovery=True)["quic"] == {
            "disablePathMTUDiscovery": True
        }
        assert "quic" not in generate_hysteria2_server_config(password="pw", disable_mtu_discovery=False)


# ---------------------------------------------------------------------------
# TUIC v5
# ---------------------------------------------------------------------------

class TestTuicLink:
    def test_basic_uri_shape(self):
        uri = generate_tuic_link(address="1.2.3.4", user_uuid="my-uuid", password="pw")
        assert uri.startswith("tuic://my-uuid:pw@1.2.3.4:443?")
        assert uri.endswith("#MTGroup-TUIC")

    def test_generates_uuid_when_omitted(self):
        uri = generate_tuic_link(address="1.2.3.4", password="pw")
        user_part = uri.split("://", 1)[1].split(":", 1)[0]
        assert len(user_part) == 36  # str(uuid4())

    def test_password_is_url_encoded(self):
        uri = generate_tuic_link(address="1.2.3.4", user_uuid="u", password="p@ss/word")
        assert "p%40ss%2Fword" in uri

    def test_default_params(self):
        p = _params(generate_tuic_link(address="1.2.3.4", password="pw"))
        assert p["congestion_control"] == "bbr"
        assert p["udp_relay_mode"] == "native"
        assert p["alpn"] == "h3"

    def test_optional_flags(self):
        p = _params(
            generate_tuic_link(
                address="1.2.3.4",
                password="pw",
                sni="www.bing.com",
                insecure=True,
                zero_rtt_handshake=True,
                disable_sni=True,
            )
        )
        assert p["sni"] == "www.bing.com"
        assert p["allow_insecure"] == "1"
        assert p["zero_rtt_handshake"] == "1"
        assert p["disable_sni"] == "1"

    def test_flags_absent_when_disabled(self):
        p = _params(
            generate_tuic_link(
                address="1.2.3.4", password="pw", insecure=False, zero_rtt_handshake=False, disable_sni=False
            )
        )
        assert "allow_insecure" not in p
        assert "zero_rtt_handshake" not in p
        assert "disable_sni" not in p
        assert "sni" not in p


class TestTuicSingboxConfig:
    def test_core_fields(self):
        cfg = generate_tuic_singbox_config(address="1.2.3.4", port=8443, user_uuid="u", password="pw")
        assert cfg["type"] == "tuic"
        assert cfg["server"] == "1.2.3.4"
        assert cfg["server_port"] == 8443
        assert cfg["uuid"] == "u"
        assert cfg["password"] == "pw"

    def test_heartbeat_is_seconds_suffixed(self):
        cfg = generate_tuic_singbox_config(address="1.2.3.4", password="pw", heartbeat_interval_sec=25)
        assert cfg["heartbeat"] == "25s"

    def test_sni_sets_server_name(self):
        cfg = generate_tuic_singbox_config(address="1.2.3.4", password="pw", sni="www.bing.com")
        assert cfg["tls"]["server_name"] == "www.bing.com"
        assert "disable_sni" not in cfg["tls"]

    def test_no_sni_disables_sni(self):
        cfg = generate_tuic_singbox_config(address="1.2.3.4", password="pw", sni=None)
        assert cfg["tls"]["disable_sni"] is True

    def test_generates_uuid_when_omitted(self):
        cfg = generate_tuic_singbox_config(address="1.2.3.4", password="pw")
        assert len(cfg["uuid"]) == 36


class TestTuicServerConfig:
    def test_builds_uuid_to_password_map(self):
        cfg = generate_tuic_server_config(
            users=[{"uuid": "u1", "password": "p1"}, {"uuid": "u2", "password": "p2"}]
        )
        assert cfg["users"] == {"u1": "p1", "u2": "p2"}

    def test_listens_on_all_v6_and_v4(self):
        cfg = generate_tuic_server_config(listen_port=8443, users=[])
        assert "8443" in cfg["server"]

    def test_timing_values_carry_units(self):
        cfg = generate_tuic_server_config(
            users=[], max_idle_time_ms=20000, authentication_timeout_ms=2000
        )
        assert cfg["max_idle_time"] == "20000ms"
        assert cfg["authentication_timeout"] == "2000ms"

    def test_cert_paths_and_alpn(self):
        cfg = generate_tuic_server_config(users=[], cert_path="/c.crt", key_path="/k.key")
        assert cfg["certificate"] == "/c.crt"
        assert cfg["private_key"] == "/k.key"
        assert cfg["alpn"] == ["h3"]
