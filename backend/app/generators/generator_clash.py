"""
MTGroup VPN Ultimate — Clash Meta (Mihomo) Configuration Generator
YAML config output compatible with Clash Meta, Stash, and similar clients.
"""

from __future__ import annotations

from typing import Any, Optional

import yaml


# ---------------------------------------------------------------------------
# Iran Bypass Constants (shared with singbox generator)
# ---------------------------------------------------------------------------

IRAN_RULES = [
    "GEOSITE,category-ir,DIRECT",
    "GEOSITE,category-bank-ir,DIRECT",
    "GEOSITE,category-bourse-ir,DIRECT",
    "GEOSITE,category-gov-ir,DIRECT",
    "GEOIP,ir,DIRECT",
    "DOMAIN-SUFFIX,.ir,DIRECT",
]

GAMER_RULES = [
    "DOMAIN-SUFFIX,riotgames.com,DIRECT",
    "DOMAIN-SUFFIX,leagueoflegends.com,DIRECT",
    "DOMAIN-SUFFIX,steampowered.com,DIRECT",
    "DOMAIN-SUFFIX,valvesoftware.com,DIRECT",
    "DOMAIN-SUFFIX,blizzard.com,DIRECT",
    "DOMAIN-SUFFIX,battle.net,DIRECT",
    "DOMAIN-SUFFIX,epicgames.com,DIRECT",
    "DOMAIN-SUFFIX,ea.com,DIRECT",
    "IP-CIDR,104.160.128.0/17,DIRECT,no-resolve",
    "IP-CIDR,208.64.200.0/22,DIRECT,no-resolve",
    "IP-CIDR,137.221.0.0/16,DIRECT,no-resolve",
]


def generate_clash_config(
    *,
    proxies: list[dict[str, Any]],
    iran_bypass: bool = True,
    gamer_mode: bool = False,
    split_bypass_domains: Optional[list[str]] = None,
    split_force_domains: Optional[list[str]] = None,
    dns_servers: Optional[list[str]] = None,
    label: str = "MTGroup VPN",
) -> str:
    """
    Generate a Clash Meta YAML configuration.

    Args:
        proxies: List of proxy dicts (VLESS, Hysteria2, TUIC format).
    """
    if dns_servers is None:
        dns_servers = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]

    proxy_names = [p.get("name", f"Proxy-{i}") for i, p in enumerate(proxies)]

    config: dict[str, Any] = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "ipv6": False,
        "external-controller": "127.0.0.1:9090",
        "unified-delay": True,
        "tcp-concurrent": True,
        "geodata-mode": True,
        "geox-url": {
            "geoip": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat",
            "geosite": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
            "mmdb": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.metadb",
        },
        "find-process-mode": "strict",
        "global-client-fingerprint": "chrome",
        "dns": _build_clash_dns(dns_servers, iran_bypass),
        "proxies": proxies,
        "proxy-groups": _build_proxy_groups(proxy_names),
        "rules": _build_clash_rules(
            iran_bypass=iran_bypass,
            gamer_mode=gamer_mode,
            split_bypass_domains=split_bypass_domains or [],
            split_force_domains=split_force_domains or [],
        ),
    }

    return yaml.dump(
        config,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=120,
    )


def _build_clash_dns(
    dns_servers: list[str],
    iran_bypass: bool,
) -> dict[str, Any]:
    """Build Clash DNS configuration."""
    dns_config: dict[str, Any] = {
        "enable": True,
        "listen": "0.0.0.0:1053",
        "ipv6": False,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": [
            "*.lan",
            "*.local",
            "*.localhost",
            "time.*.com",
            "ntp.*.com",
            "+.pool.ntp.org",
        ],
        "default-nameserver": ["1.1.1.1", "8.8.8.8"],
        "nameserver": dns_servers,
    }

    if iran_bypass:
        dns_config["nameserver-policy"] = {
            "geosite:category-ir": ["https://dns.403.online/dns-query", "https://dns.shecan.ir/dns-query"],
            "+.ir": ["https://dns.403.online/dns-query", "https://dns.shecan.ir/dns-query"],
        }

    return dns_config


def _build_proxy_groups(proxy_names: list[str]) -> list[dict[str, Any]]:
    """Build proxy groups with auto-select and fallback."""
    return [
        {
            "name": "🚀 Proxy",
            "type": "select",
            "proxies": ["♻️ Auto", "DIRECT"] + proxy_names,
        },
        {
            "name": "♻️ Auto",
            "type": "url-test",
            "proxies": proxy_names,
            "url": "https://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
        },
        {
            "name": "📺 Streaming",
            "type": "select",
            "proxies": ["🚀 Proxy"] + proxy_names,
        },
        {
            "name": "🎮 Gaming",
            "type": "select",
            "proxies": ["DIRECT", "🚀 Proxy"] + proxy_names,
        },
        {
            "name": "🛡️ Fallback",
            "type": "fallback",
            "proxies": proxy_names,
            "url": "https://www.gstatic.com/generate_204",
            "interval": 300,
        },
    ]


def _build_clash_rules(
    iran_bypass: bool,
    gamer_mode: bool,
    split_bypass_domains: list[str],
    split_force_domains: list[str],
) -> list[str]:
    """Build Clash routing rules."""
    rules: list[str] = []

    # Iran bypass
    if iran_bypass:
        rules.extend(IRAN_RULES)

    # Gamer mode
    if gamer_mode:
        rules.extend(GAMER_RULES)

    # Custom split tunnel bypass
    for domain in split_bypass_domains:
        rules.append(f"DOMAIN-SUFFIX,{domain},DIRECT")

    # Custom split tunnel force
    for domain in split_force_domains:
        rules.append(f"DOMAIN-SUFFIX,{domain},🚀 Proxy")

    # Streaming services through proxy
    rules.extend([
        "GEOSITE,youtube,📺 Streaming",
        "GEOSITE,google,🚀 Proxy",
        "GEOSITE,twitter,🚀 Proxy",
        "GEOSITE,facebook,🚀 Proxy",
        "GEOSITE,instagram,🚀 Proxy",
        "GEOSITE,telegram,🚀 Proxy",
        "GEOSITE,whatsapp,🚀 Proxy",
    ])

    # Private / LAN
    rules.extend([
        "GEOIP,private,DIRECT,no-resolve",
        "GEOSITE,category-ads-all,REJECT",
    ])

    # Default
    rules.append("MATCH,🚀 Proxy")

    return rules


def generate_clash_vless_proxy(
    *,
    name: str,
    server: str,
    port: int,
    uuid: str,
    flow: str = "xtls-rprx-vision",
    sni: str = "www.google.com",
    fingerprint: str = "chrome",
    reality_public_key: Optional[str] = None,
    reality_short_id: Optional[str] = None,
    network: str = "tcp",
) -> dict[str, Any]:
    """Generate a Clash Meta VLESS proxy dict."""
    proxy: dict[str, Any] = {
        "name": name,
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid,
        "network": network,
        "udp": True,
        "tls": True,
        "flow": flow,
        "servername": sni,
        "client-fingerprint": fingerprint,
    }

    if reality_public_key:
        proxy["reality-opts"] = {
            "public-key": reality_public_key,
            "short-id": reality_short_id or "",
        }

    return proxy


def generate_clash_hysteria2_proxy(
    *,
    name: str,
    server: str,
    port: int,
    password: str,
    sni: Optional[str] = None,
    obfs: Optional[str] = None,
    obfs_password: Optional[str] = None,
    up_mbps: int = 50,
    down_mbps: int = 100,
    fingerprint: str = "chrome",
) -> dict[str, Any]:
    """Generate a Clash Meta Hysteria2 proxy dict."""
    proxy: dict[str, Any] = {
        "name": name,
        "type": "hysteria2",
        "server": server,
        "port": port,
        "password": password,
        "up": f"{up_mbps} Mbps",
        "down": f"{down_mbps} Mbps",
        "client-fingerprint": fingerprint,
    }

    if sni:
        proxy["sni"] = sni

    if obfs and obfs_password:
        proxy["obfs"] = obfs
        proxy["obfs-password"] = obfs_password

    return proxy


def generate_clash_tuic_proxy(
    *,
    name: str,
    server: str,
    port: int,
    uuid: str,
    password: str,
    sni: Optional[str] = None,
    congestion_controller: str = "bbr",
    udp_relay_mode: str = "native",
    reduce_rtt: bool = True,
) -> dict[str, Any]:
    """Generate a Clash Meta TUIC v5 proxy dict."""
    proxy: dict[str, Any] = {
        "name": name,
        "type": "tuic",
        "server": server,
        "port": port,
        "uuid": uuid,
        "password": password,
        "alpn": ["h3"],
        "congestion-controller": congestion_controller,
        "udp-relay-mode": udp_relay_mode,
        "reduce-rtt": reduce_rtt,
    }

    if sni:
        proxy["sni"] = sni

    return proxy
