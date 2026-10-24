"""
Client-compatibility tests for the subscription generators.

sing-box decodes configs strictly and mihomo refuses configs with missing
geodata codes or empty groups — in both cases the *whole* subscription
fails to import, not just one server. Before this suite existed the
generated sing-box profile was rejected by every stable sing-box line
(1.12: unknown `experimental.tls_fragment`; 1.13: removed `block`/`dns`
special outbounds; 1.14: removed legacy DNS servers), and every Clash
profile with Iran bypass was rejected by mihomo (`GEOIP,ir` against a
geoip-lite.dat that has no "ir"). These were confirmed against real
sing-box 1.12.25 / 1.13.21 / 1.14.4 and mihomo 1.19.33 binaries; CI can't
run those, so the constraints are pinned down structurally here.
"""

from __future__ import annotations

import base64
import ipaddress

import pytest
import yaml

from backend.app.generators.generator_amnezia import (
    calculate_optimal_amnezia_params,
    generate_amnezia_conf,
    random_amnezia_headers,
    validate_amnezia_params,
)
from backend.app.generators.generator_clash import (
    generate_clash_config,
    generate_clash_hysteria2_proxy,
    generate_clash_tuic_proxy,
    generate_clash_vless_proxy,
)
from backend.app.generators.generator_hysteria2 import generate_hysteria2_json_config, generate_hysteria2_link
from backend.app.generators.generator_singbox import generate_singbox_config
from backend.app.generators.generator_tuic import generate_tuic_link, generate_tuic_singbox_config
from backend.tests.conftest import get_admin_token

UUID = "3edd10db-c75f-4c02-981f-dcf2379df17f"


def _vless():
    return {
        "type": "vless", "tag": "vless-n1", "server": "203.0.113.10", "server_port": 443, "uuid": UUID,
        "flow": "xtls-rprx-vision",
        "tls": {"enabled": True, "server_name": "www.microsoft.com",
                "reality": {"enabled": True, "public_key": "PBK", "short_id": ""}},
        "packet_encoding": "xudp",
    }


def _hy2():
    ob = generate_hysteria2_json_config(address="203.0.113.11", port=8443, password=UUID, sni="hy.example.com")
    ob["tag"] = "hy2-n2"
    return ob


def _tuic():
    ob = generate_tuic_singbox_config(address="203.0.113.12", port=8444, user_uuid=UUID, password=UUID[:16],
                                      sni="tuic.example.com")
    ob["tag"] = "tuic-n3"
    return ob


def _full_config(**kw):
    return generate_singbox_config(outbounds=[_vless(), _hy2(), _tuic()], **kw)


# Keys sing-box removed between 1.11 and 1.14 (or never had). Any of them
# anywhere in the config makes at least one supported version refuse it.
_REMOVED_KEYS = {
    "geoip", "geosite", "inet4_address", "inet6_address", "sniff", "sniff_override_destination",
    "domain_strategy", "tls_fragment", "address_resolver", "independent_cache",
}


def _walk(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield f"{path}.{k}", k, v
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]")


ALL_VARIANTS = [
    {},
    {"iran_bypass": False},
    {"iran_bypass": True, "gamer_mode": True, "battery_saver": True, "warp_bypass": True,
     "split_bypass_domains": ["mybank.com", "bad,entry"], "split_bypass_ips": ["10.1.0.0/16", "junk"],
     "split_force_domains": ["chat.openai.com"], "split_force_ips": ["8.8.8.8"]},
]


class TestSingboxCompat:
    @pytest.mark.parametrize("kw", ALL_VARIANTS)
    def test_no_removed_or_unknown_legacy_fields(self, kw):
        offenders = [p for p, k, _ in _walk(_full_config(**kw)) if k in _REMOVED_KEYS]
        assert offenders == []

    @pytest.mark.parametrize("kw", ALL_VARIANTS)
    def test_top_level_sections(self, kw):
        assert set(_full_config(**kw)) <= {"log", "dns", "inbounds", "outbounds", "route", "experimental"}

    def test_no_special_outbounds(self):
        types = {ob["type"] for ob in _full_config()["outbounds"]}
        assert not types & {"block", "dns"}

    def test_dns_servers_use_typed_format(self):
        for server in _full_config()["dns"]["servers"]:
            assert "type" in server
            assert "address" not in server

    def test_route_rules_use_actions_not_special_outbounds(self):
        rules = _full_config()["route"]["rules"]
        assert {"action": "sniff"} in rules
        assert {"protocol": "dns", "action": "hijack-dns"} in rules
        for rule in rules:
            assert ("action" in rule) != ("outbound" in rule)

    def test_every_referenced_outbound_exists(self):
        cfg = _full_config(gamer_mode=True, split_force_domains=["a.com"])
        tags = {ob["tag"] for ob in cfg["outbounds"]}
        for rule in cfg["route"]["rules"]:
            if "outbound" in rule:
                assert rule["outbound"] in tags
        assert cfg["route"]["final"] in tags
        for group in (ob for ob in cfg["outbounds"] if ob["type"] in ("selector", "urltest")):
            assert set(group["outbounds"]) <= tags
            assert group["outbounds"]
        dns_tags = {s["tag"] for s in cfg["dns"]["servers"]}
        assert cfg["dns"]["final"] in dns_tags
        assert {s["detour"] for s in cfg["dns"]["servers"] if "detour" in s} <= tags

    def test_utls_only_on_tcp_tls_protocols(self):
        by_type = {ob["type"]: ob for ob in _full_config()["outbounds"]}
        assert by_type["vless"]["tls"]["utls"]["enabled"] is True
        assert "utls" not in by_type["hysteria2"]["tls"]
        assert "utls" not in by_type["tuic"]["tls"]

    def test_no_multiplex_anywhere(self):
        assert all("multiplex" not in ob for ob in _full_config()["outbounds"])

    def test_warp_placeholder_never_emitted(self):
        cfg = _full_config(warp_bypass=True)
        assert "YOUR_WARP_PRIVATE_KEY" not in str(cfg)
        assert all(ob["type"] != "wireguard" for ob in cfg["outbounds"])

    def test_iran_bypass_has_full_cidr_list_and_ir_suffix(self):
        from backend.app.generators.generator_singbox import IRAN_BYPASS_IP_CIDR
        rules = _full_config()["route"]["rules"]
        cidr_rules = [r for r in rules if r.get("ip_cidr") == list(IRAN_BYPASS_IP_CIDR)]
        assert cidr_rules and cidr_rules[0]["outbound"] == "direct"
        assert any("ir" in r.get("domain_suffix", []) for r in rules)
        for cidr in IRAN_BYPASS_IP_CIDR:
            ipaddress.ip_network(cidr)

    def test_xray_style_domain_specs_are_converted(self):
        cfg = _full_config(gamer_mode=True)
        flat = str(cfg)
        assert "domain:" not in flat and "full:" not in flat

    def test_force_rules_come_before_bypass_rules(self):
        rules = _full_config(split_force_domains=["force.ir"])["route"]["rules"]
        force_at = next(i for i, r in enumerate(rules) if r.get("outbound") == "proxy")
        iran_at = next(i for i, r in enumerate(rules) if "ir" in r.get("domain_suffix", []))
        assert force_at < iran_at

    def test_split_entries_are_sanitised(self):
        rules = _full_config(**ALL_VARIANTS[2])["route"]["rules"]
        flat = str(rules)
        assert "bad,entry" not in flat and "junk" not in flat
        assert {"domain_suffix": ["mybank.com"], "outbound": "direct"} in rules

    def test_empty_outbounds_still_loadable(self):
        cfg = generate_singbox_config(outbounds=[])
        proxy = next(ob for ob in cfg["outbounds"] if ob["tag"] == "proxy")
        assert proxy["outbounds"] == ["direct"]

    def test_hysteria2_and_tuic_outbounds_only_known_fields(self):
        assert set(_hy2()) <= {"type", "tag", "server", "server_port", "password", "up_mbps", "down_mbps",
                               "obfs", "tls", "server_ports", "hop_interval"}
        assert set(_tuic()) <= {"type", "tag", "server", "server_port", "uuid", "password",
                                "congestion_control", "udp_relay_mode", "zero_rtt_handshake",
                                "heartbeat", "tls"}


def _clash(proxies=None, **kw):
    if proxies is None:
        proxies = [
            generate_clash_vless_proxy(name="n1", server="203.0.113.10", port=443, uuid=UUID,
                                       reality_public_key="PBK"),
            generate_clash_hysteria2_proxy(name="n2", server="203.0.113.11", port=8443, password=UUID),
            generate_clash_tuic_proxy(name="n3", server="203.0.113.12", port=8444, uuid=UUID, password="p"),
        ]
    return yaml.safe_load(generate_clash_config(proxies=proxies, **kw))


class TestClashCompat:
    def test_uses_full_geoip_database(self):
        # geoip-lite.dat has no "ir" -> `GEOIP,ir` made mihomo reject the file.
        assert "geoip-lite" not in str(_clash()["geox-url"])

    def test_suffix_rules_have_no_leading_dot(self):
        rules = _clash()["rules"]
        assert "DOMAIN-SUFFIX,ir,DIRECT" in rules
        assert not any(r.startswith("DOMAIN-SUFFIX,.") for r in rules)

    def test_groups_never_empty(self):
        for group in _clash(proxies=[])["proxy-groups"]:
            assert group["proxies"]

    def test_every_group_member_exists(self):
        cfg = _clash()
        names = {p["name"] for p in cfg["proxies"]} | {g["name"] for g in cfg["proxy-groups"]} | {"DIRECT", "REJECT"}
        for group in cfg["proxy-groups"]:
            assert set(group["proxies"]) <= names
        for rule in cfg["rules"]:
            target = rule.split(",")[2] if rule.count(",") >= 2 else rule.split(",")[1]
            assert target in names

    def test_split_entries_cannot_inject_rule_fields(self):
        rules = _clash(split_bypass_domains=["ok.com", "evil.com,REJECT"],
                       split_force_domains=["x.com\nMATCH,DIRECT"])["rules"]
        assert "DOMAIN-SUFFIX,ok.com,DIRECT" in rules
        assert not any("evil.com" in r or "x.com" in r for r in rules)

    def test_dns_listens_on_loopback_only(self):
        assert _clash()["dns"]["listen"].startswith("127.0.0.1:")

    def test_hysteria2_proxy_has_no_utls_fingerprint(self):
        hy2 = next(p for p in _clash()["proxies"] if p["type"] == "hysteria2")
        assert "client-fingerprint" not in hy2


class TestShareLinksIpv6:
    def test_hysteria2_link_brackets_ipv6(self):
        assert "@[2001:db8::1]:443" in generate_hysteria2_link(address="2001:db8::1", password="p")

    def test_tuic_link_brackets_ipv6(self):
        assert "@[2001:db8::1]:443" in generate_tuic_link(address="2001:db8::1", user_uuid="u", password="p")


class TestAmneziaParams:
    def test_rejects_s1_plus_56_equal_s2(self):
        with pytest.raises(ValueError, match="s1 \\+ 56"):
            validate_amnezia_params(jc=4, jmin=40, jmax=70, s1=10, s2=66, h1=5, h2=6, h3=7, h4=8)

    def test_rejects_duplicate_headers(self):
        with pytest.raises(ValueError, match="different"):
            validate_amnezia_params(jc=4, jmin=40, jmax=70, s1=0, s2=0, h1=5, h2=5, h3=7, h4=8)

    def test_conf_refuses_invalid_params(self):
        with pytest.raises(ValueError):
            generate_amnezia_conf(server_public_key="K", server_endpoint="1.2.3.4", client_private_key="P",
                                  s1=10, s2=66)

    def test_random_headers_are_distinct_and_not_wireguard_types(self):
        for _ in range(200):
            headers = random_amnezia_headers()
            values = set(headers.values())
            assert len(values) == 4
            assert not values & {1, 2, 3, 4}

    @pytest.mark.parametrize("network", ["mobile", "broadband", "satellite"])
    @pytest.mark.parametrize("level", ["low", "medium", "high", "extreme"])
    def test_every_preset_is_valid(self, network, level):
        validate_amnezia_params(**calculate_optimal_amnezia_params(network_type=network, aggression_level=level))

    def test_ipv6_endpoint_bracketed(self):
        conf = generate_amnezia_conf(server_public_key="K", server_endpoint="2001:db8::1", client_private_key="P")
        assert "Endpoint = [2001:db8::1]:51820" in conf


class TestSubscriptionEndpoints:
    @staticmethod
    async def _user(client, protocols):
        tok = await get_admin_token(client)
        resp = await client.post("/api/users/", json={
            "username": "compat-user", "password": "Password123!", "protocols": protocols,
        }, headers={"Authorization": f"Bearer {tok}"})
        assert resp.status_code == 201, resp.text
        return resp.json()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path,ua", [
        ("/sub/{t}/singbox", ""), ("/sub/{t}/clash", ""), ("/sub/{t}/v2ray", ""),
        ("/sub/{t}", "HiddifyNext"), ("/sub/{t}", "clash-verge"), ("/sub/{t}", "Shadowrocket"),
    ])
    async def test_503_when_no_server_matches_the_subscription_protocols(self, client, path, ua):
        # The seeded node is VLESS-Reality; a TUIC-only subscription has
        # nothing to render. This used to emit a config with an empty
        # url-test group that sing-box/mihomo refuse to load.
        user = await self._user(client, ["tuic_v5"])
        resp = await client.get(path.format(t=user["subscription_token"]), headers={"User-Agent": ua})
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_unicode_label_does_not_500(self, client, db_engine):
        from sqlalchemy import update

        from backend.app.models import Subscription, create_session_factory
        user = await self._user(client, ["vless_reality"])
        factory = create_session_factory(db_engine)
        async with factory() as s:
            await s.execute(update(Subscription).where(Subscription.token == user["subscription_token"])
                            .values(label="🚀 تهران VPN"))
            await s.commit()
        for fmt in ("singbox", "clash"):
            resp = await client.get(f"/sub/{user['subscription_token']}/{fmt}")
            assert resp.status_code == 200, fmt
            assert "filename*=UTF-8''" in resp.headers["content-disposition"]

    @pytest.mark.asyncio
    async def test_v2ray_links_are_parseable_and_use_the_subscription_credential(self, client):
        from urllib.parse import urlparse

        from backend.app.core.security import derive_proxy_uuid
        user = await self._user(client, ["vless_reality"])
        resp = await client.get(f"/sub/{user['subscription_token']}/v2ray")
        link = base64.b64decode(resp.text).decode().splitlines()[0]
        parsed = urlparse(link)
        assert parsed.scheme == "vless"
        assert parsed.username == derive_proxy_uuid(user["subscription_token"], 1)
        assert parsed.port == 443
