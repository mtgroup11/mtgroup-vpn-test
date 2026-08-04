"""
MTGroup VPN Ultimate — Sing-box Configuration Generator
Complete JSON config with Iran bypass, gamer mode routing,
split tunneling, battery optimization, and TLS fragmentation.
This is the primary config format for Streisand and Nekobox.
"""

from __future__ import annotations

import json
import random
from typing import Any, Optional

from backend.app.models import HostSpoofMode, ShapingMode
from backend.app.generators.traffic_shaper import TrafficShaper


def _get_fingerprint(fp: str) -> str:
    if fp == "randomized":
        return random.choice(["chrome", "firefox", "safari", "edge", "ios", "android"])
    return fp


# ---------------------------------------------------------------------------
# Iran Bypass Constants
# ---------------------------------------------------------------------------

IRAN_BYPASS_GEOSITE = [
    "category-ir",
    "category-bank-ir",
    "category-bourse-ir",
    "category-education-ir",
    "category-gov-ir",
    "category-media-ir",
    "category-payment-ir",
    "category-tech-ir",
    "category-shopping-ir",
]

IRAN_BYPASS_DOMAINS = [
    "domain:.ir",
    "domain:digikala.com",
    "domain:snapp.ir",
    "domain:tapsi.ir",
    "domain:shaparak.ir",
    "domain:saman.ir",
    "domain:bmi.ir",
    "domain:parsian-bank.ir",
    "domain:bankmellat.ir",
    "domain:bpi.ir",
    "domain:aparat.com",
    "domain:filimo.com",
]

IRAN_BYPASS_IP_CIDR = [
    # Major Iranian ISP ranges
    "2.144.0.0/14",
    "2.176.0.0/12",
    "5.22.0.0/17",
    "5.52.0.0/15",
    "5.160.0.0/16",
    "5.200.64.0/18",
    "5.213.0.0/16",
    "31.40.0.0/16",
    "37.32.0.0/14",
    "37.114.192.0/18",
    "37.130.200.0/21",
    "37.137.0.0/16",
    "37.148.0.0/17",
    "37.202.128.0/17",
    "37.228.131.0/24",
    "46.18.248.0/21",
    "46.21.80.0/20",
    "46.34.96.0/19",
    "46.51.0.0/17",
    "46.62.128.0/17",
    "46.100.0.0/16",
    "46.143.0.0/17",
    "46.164.0.0/16",
    "46.182.32.0/19",
    "46.209.0.0/16",
    "46.224.0.0/15",
    "46.235.76.0/23",
    "46.245.0.0/17",
    "46.249.96.0/24",
    "62.133.36.0/22",
    "62.220.96.0/19",
    "66.79.96.0/19",
    "69.194.64.0/18",
    "77.36.128.0/17",
    "77.81.76.0/24",
    "77.104.64.0/18",
    "78.38.0.0/15",
    "78.109.192.0/20",
    "78.157.0.0/17",
    "80.66.176.0/20",
    "80.71.112.0/20",
    "80.75.0.0/20",
    "80.191.0.0/16",
    "80.210.0.0/16",
    "80.242.0.0/20",
    "80.249.112.0/20",
    "80.253.128.0/19",
    "81.12.0.0/17",
    "81.16.112.0/20",
    "81.28.32.0/19",
    "81.29.240.0/20",
    "81.31.224.0/21",
    "81.90.144.0/20",
    "81.91.64.0/18",
    "81.92.216.0/24",
    "82.99.192.0/18",
    "82.138.140.0/25",
    "83.147.192.0/18",
    "83.149.208.0/21",
    "84.47.192.0/18",
    "84.241.0.0/18",
    "85.9.64.0/18",
    "85.15.0.0/18",
    "85.133.0.0/16",
    "85.185.0.0/16",
    "85.204.76.0/23",
    "85.208.252.0/22",
    "85.239.192.0/19",
    "86.55.0.0/16",
    "86.104.32.0/20",
    "86.106.142.0/24",
    "86.107.0.0/20",
    "86.109.32.0/19",
    "87.107.0.0/16",
    "87.236.208.0/22",
    "87.247.168.0/21",
    "87.248.128.0/18",
    "89.32.0.0/18",
    "89.34.20.0/23",
    "89.34.88.0/21",
    "89.35.132.0/22",
    "89.37.0.0/20",
    "89.38.80.0/20",
    "89.39.208.0/24",
    "89.42.32.0/21",
    "89.42.208.0/22",
    "89.43.0.0/21",
    "89.45.48.0/20",
    "89.144.128.0/18",
    "89.165.0.0/17",
    "89.196.0.0/16",
    "89.219.64.0/18",
    "89.235.64.0/18",
    "91.92.104.0/21",
    "91.92.114.0/24",
    "91.98.0.0/16",
    "91.99.0.0/16",
    "91.106.64.0/19",
    "91.107.128.0/21",
    "91.108.128.0/17",
    "91.109.104.0/21",
    "91.133.128.0/17",
    "91.184.64.0/19",
    "91.185.128.0/19",
    "91.186.192.0/23",
    "91.190.88.0/21",
    "91.198.228.0/24",
    "91.209.96.0/24",
    "91.220.79.0/24",
    "91.220.113.0/24",
    "91.220.243.0/24",
    "91.227.84.0/22",
    "91.228.22.0/23",
    "91.228.132.0/23",
    "91.229.46.0/23",
    "91.229.214.0/23",
    "91.230.32.0/24",
    "91.232.64.0/22",
    "91.233.56.0/22",
    "91.236.168.0/23",
    "91.237.254.0/23",
    "91.238.0.0/21",
    "91.239.14.0/24",
    "91.240.60.0/22",
    "91.240.180.0/22",
    "91.241.20.0/22",
    "91.242.44.0/23",
    "91.243.126.0/24",
    "91.244.120.0/22",
    "91.245.228.0/22",
    "91.247.171.0/24",
    "91.247.174.0/24",
    "91.248.0.0/21",
    "91.250.224.0/20",
    "91.251.0.0/16",
    "92.42.48.0/21",
    "92.43.160.0/22",
    "92.61.176.0/20",
    "92.114.16.0/20",
    "92.119.57.0/24",
    "92.119.68.0/22",
    "93.88.64.0/21",
    "93.110.0.0/16",
    "93.113.224.0/20",
    "93.114.16.0/20",
    "93.115.216.0/21",
    "93.117.0.0/16",
    "93.118.96.0/19",
    "93.119.32.0/19",
    "93.126.0.0/18",
    "93.190.24.0/21",
    "94.24.0.0/16",
    "94.74.128.0/18",
    "94.101.128.0/20",
    "94.139.160.0/19",
    "94.176.8.0/21",
    "94.177.64.0/18",
    "94.182.0.0/15",
    "94.199.136.0/22",
    "94.232.168.0/21",
    "94.241.164.0/22",
    "95.38.0.0/16",
    "95.64.0.0/17",
    "95.80.128.0/18",
    "95.81.64.0/18",
    "95.130.56.0/21",
    "95.142.224.0/20",
    "95.156.220.0/22",
    "95.156.252.0/22",
    "95.162.0.0/16",
    "109.70.237.0/24",
    "109.72.192.0/20",
    "109.94.164.0/22",
    "109.108.128.0/17",
    "109.110.160.0/19",
    "109.122.192.0/18",
    "109.125.128.0/18",
    "109.162.128.0/17",
    "109.201.0.0/19",
    "109.203.128.0/19",
    "109.206.192.0/19",
    "109.225.128.0/18",
    "109.230.64.0/19",
    "109.232.0.0/21",
    "109.238.176.0/20",
    "113.203.0.0/17",
    "130.244.71.0/24",
    "130.255.192.0/18",
    "151.232.0.0/14",
    "151.238.0.0/15",
    "151.240.0.0/13",
    "152.89.12.0/22",
    "152.89.44.0/22",
    "157.119.188.0/22",
    "158.58.0.0/17",
    "158.255.74.0/24",
    "159.20.96.0/20",
    "164.138.16.0/21",
    "164.138.128.0/18",
    "164.215.56.0/21",
    "171.22.24.0/22",
    "172.80.128.0/17",
    "176.12.64.0/20",
    "176.56.144.0/20",
    "176.62.144.0/21",
    "176.65.160.0/19",
    "176.65.192.0/18",
    "176.101.32.0/21",
    "176.102.224.0/21",
    "176.116.0.0/15",
    "176.122.168.0/21",
    "176.124.64.0/22",
    "176.126.120.0/21",
    "178.21.40.0/21",
    "178.21.160.0/21",
    "178.22.72.0/21",
    "178.131.0.0/16",
    "178.157.0.0/17",
    "178.169.0.0/19",
    "178.173.128.0/18",
    "178.211.145.0/24",
    "178.215.0.0/18",
    "178.216.248.0/21",
    "178.219.224.0/20",
    "178.236.32.0/22",
    "178.238.192.0/20",
    "178.239.144.0/20",
    "178.248.40.0/21",
    "178.251.208.0/21",
    "178.252.128.0/18",
    "185.1.77.0/24",
    "185.2.12.0/22",
]

# ---------------------------------------------------------------------------
# Gamer Mode Constants
# ---------------------------------------------------------------------------

GAMER_DIRECT_DOMAINS = [
    "full:riotgames.com",
    "full:leagueoflegends.com",
    "domain:riotcdn.net",
    "domain:riotgames.com",
    "full:steampowered.com",
    "domain:steamcontent.com",
    "domain:valvesoftware.com",
    "full:blizzard.com",
    "domain:battle.net",
    "domain:blizzard.com",
    "full:epicgames.com",
    "domain:epicgames.com",
    "domain:unrealengine.com",
    "full:ea.com",
    "domain:ea.com",
]

GAMER_DIRECT_IP_CIDR = [
    # Riot Games
    "104.160.128.0/17",
    "104.160.0.0/14",
    # Valve / Steam
    "208.64.200.0/22",
    "205.196.6.0/24",
    "146.66.152.0/21",
    "185.25.180.0/22",
    # Activision Blizzard
    "24.105.0.0/18",
    "137.221.0.0/16",
    "117.52.35.0/24",
    # Epic Games
    "52.38.0.0/15",
    "52.40.0.0/14",
]


def generate_singbox_config(
    *,
    # Outbound configurations
    outbounds: list[dict[str, Any]],
    # Feature toggles
    iran_bypass: bool = True,
    gamer_mode: bool = False,
    battery_saver: bool = False,
    warp_bypass: bool = False,
    # Split tunnel
    split_bypass_domains: Optional[list[str]] = None,
    split_bypass_ips: Optional[list[str]] = None,
    split_force_domains: Optional[list[str]] = None,
    split_force_ips: Optional[list[str]] = None,
    # TLS fragmentation
    tls_fragment_enabled: bool = True,
    tls_fragment_size: str = "50-200",
    tls_fragment_sleep: str = "10-50",
    # DNS
    dns_servers: Optional[list[str]] = None,
    dns_strategy: str = "ipv4_only",
    # Battery
    idle_timeout: int = 300,
    connection_check_interval: int = 600,
    # Label
    label: str = "MTGroup VPN",
    # DPI Evasion
    tls_fingerprint: str = "chrome",
    shaping_mode: ShapingMode = ShapingMode.VIDEO_STREAM,
    host_spoof_mode: HostSpoofMode = HostSpoofMode.NONE,
    spoofed_host: Optional[str] = None,
) -> dict[str, Any]:
    """
    Generate a complete Sing-box JSON configuration with full routing,
    DNS, and experimental features.
    """
    if dns_servers is None:
        dns_servers = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]

    config: dict[str, Any] = {
        "log": {
            "level": "warn",
            "timestamp": True,
        },
        "experimental": {},
        "dns": _build_dns_config(
            dns_servers=dns_servers,
            dns_strategy=dns_strategy,
            iran_bypass=iran_bypass,
        ),
        "inbounds": _build_inbounds(battery_saver=battery_saver),
        "outbounds": _build_outbounds(
            user_outbounds=outbounds,
            tls_fingerprint=tls_fingerprint,
            shaping_mode=shaping_mode,
            host_spoof_mode=host_spoof_mode,
            spoofed_host=spoofed_host,
            warp_bypass=warp_bypass,
        ),
        "route": _build_route(
            iran_bypass=iran_bypass,
            gamer_mode=gamer_mode,
            warp_bypass=warp_bypass,
            split_bypass_domains=split_bypass_domains or [],
            split_bypass_ips=split_bypass_ips or [],
            split_force_domains=split_force_domains or [],
            split_force_ips=split_force_ips or [],
        ),
    }

    # TLS fragment experimental feature
    if tls_fragment_enabled:
        config["experimental"]["tls_fragment"] = {
            "enabled": True,
            "size": tls_fragment_size,
            "sleep": tls_fragment_sleep,
        }

    # Battery optimization — clash API for stats
    if battery_saver:
        config["experimental"]["clash_api"] = {
            "external_controller": "127.0.0.1:9090",
            "store_selected": True,
        }

    return config


def _build_dns_config(
    dns_servers: list[str],
    dns_strategy: str,
    iran_bypass: bool,
) -> dict[str, Any]:
    """Build the DNS configuration with Iran-specific direct resolution."""
    servers = [
        {
            "tag": "dns-remote",
            "address": dns_servers[0],
            "address_resolver": "dns-direct",
            "strategy": dns_strategy,
            "detour": "proxy",
        },
        {
            "tag": "dns-direct",
            "address": "local",
            "strategy": dns_strategy,
            "detour": "direct",
        },
        {
            "tag": "dns-block",
            "address": "rcode://success",
        },
    ]

    rules: list[dict[str, Any]] = [
        {
            "outbound": ["any"],
            "server": "dns-direct",
        },
    ]

    if iran_bypass:
        # Route .ir domains to direct DNS
        rules.append({
            "domain_suffix": [".ir"],
            "server": "dns-direct",
        })
        rules.append({
            "geosite": IRAN_BYPASS_GEOSITE,
            "server": "dns-direct",
        })

    # Block ads
    rules.append({
        "geosite": ["category-ads-all"],
        "server": "dns-block",
        "disable_cache": True,
    })

    return {
        "servers": servers,
        "rules": rules,
        "strategy": dns_strategy,
        "independent_cache": True,
    }


def _build_inbounds(battery_saver: bool) -> list[dict[str, Any]]:
    """Build inbound configurations with battery optimization."""
    tun_config: dict[str, Any] = {
        "type": "tun",
        "tag": "tun-in",
        "inet4_address": "172.19.0.1/30",
        "inet6_address": "fdfe:dcba:9876::1/126",
        "auto_route": True,
        "strict_route": True,
        "sniff": not battery_saver,  # Disable sniffing in battery saver mode
        "sniff_override_destination": not battery_saver,
    }

    if battery_saver:
        # Reduce polling for battery savings
        tun_config["endpoint_independent_nat"] = True

    return [tun_config]


def _build_outbounds(
    user_outbounds: list[dict[str, Any]],
    tls_fingerprint: str,
    shaping_mode: ShapingMode,
    host_spoof_mode: HostSpoofMode,
    spoofed_host: Optional[str],
    warp_bypass: bool = False,
) -> list[dict[str, Any]]:
    """Build outbound configurations with DPI evasion injection."""
    outbounds = []
    
    # Initialize TrafficShaper for the padding profile
    shaper = TrafficShaper(mode=shaping_mode)
    mux_config = shaper.generate_singbox_multiplex_config()
    
    # Inject DPI evasion features into each user outbound
    for ob in user_outbounds:
        # TLS uTLS injection
        if "tls" in ob:
            ob["tls"]["utls"] = {
                "enabled": True,
                "fingerprint": _get_fingerprint(tls_fingerprint)
            }
        
        # Traffic Shaping padding injection
        ob["multiplex"] = mux_config
        
        # Host Spoofing injection
        if host_spoof_mode != HostSpoofMode.NONE and spoofed_host:
            transport = ob.get("transport", {})
            if transport.get("type") in ("ws", "httpupgrade"):
                if "headers" not in transport:
                    transport["headers"] = {}
                transport["headers"]["Host"] = spoofed_host
                
                if host_spoof_mode == HostSpoofMode.BUG_INJECTION:
                    path = transport.get("path", "/")
                    transport["path"] = f"http://{spoofed_host}{path}"
            ob["transport"] = transport

    # Add selector (auto-select best)
    proxy_tags = [ob.get("tag", f"proxy-{i}") for i, ob in enumerate(user_outbounds)]

    outbounds.append({
        "type": "selector",
        "tag": "proxy",
        "outbounds": ["auto"] + proxy_tags,
        "default": "auto",
    })

    outbounds.append({
        "type": "urltest",
        "tag": "auto",
        "outbounds": proxy_tags,
        "url": "https://www.gstatic.com/generate_204",
        "interval": "5m",
        "tolerance": 50,
    })

    # Add user-defined outbounds
    outbounds.extend(user_outbounds)

    # System outbounds
    outbounds.append({"type": "direct", "tag": "direct"})
    outbounds.append({"type": "block", "tag": "block"})
    outbounds.append({"type": "dns", "tag": "dns-out"})
    
    if warp_bypass:
        outbounds.append({
            "type": "wireguard",
            "tag": "warp",
            "server": "engage.cloudflareclient.com",
            "server_port": 2408,
            "system_interface": True,
            "local_address": ["172.16.0.2/32", "2606:4700:110:8f62:eec7:7b06:a689:c339/128"],
            "private_key": "YOUR_WARP_PRIVATE_KEY", # Placeholder, would be fetched from DB
            "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            "reserved": [0, 0, 0],
            "mtu": 1280
        })

    return outbounds


def _build_route(
    iran_bypass: bool,
    gamer_mode: bool,
    split_bypass_domains: list[str],
    split_bypass_ips: list[str],
    split_force_domains: list[str],
    split_force_ips: list[str],
    warp_bypass: bool = False,
) -> dict[str, Any]:
    """Build routing rules with Iran bypass, gamer mode, and split tunneling."""
    rules: list[dict[str, Any]] = []

    # DNS hijack
    rules.append({
        "protocol": "dns",
        "outbound": "dns-out",
    })

    # Block ads
    rules.append({
        "geosite": ["category-ads-all"],
        "outbound": "block",
    })

    # WARP Bypass (Netflix / Google Captcha)
    if warp_bypass:
        rules.append({
            "geosite": ["google", "netflix", "openai", "category-ai"],
            "outbound": "warp"
        })
        rules.append({
            "domain_keyword": ["chatgpt", "openai", "google", "netflix"],
            "outbound": "warp"
        })

    # Iran bypass rules
    if iran_bypass:
        rules.append({
            "domain_suffix": [".ir"],
            "outbound": "direct",
        })
        rules.append({
            "geosite": IRAN_BYPASS_GEOSITE,
            "outbound": "direct",
        })
        rules.append({
            "geoip": ["ir", "private"],
            "outbound": "direct",
        })
        rules.append({
            "ip_cidr": IRAN_BYPASS_IP_CIDR[:50],  # First batch
            "outbound": "direct",
        })

    # Gamer mode — direct routing for game servers (lower latency)
    if gamer_mode:
        rules.append({
            "domain": GAMER_DIRECT_DOMAINS,
            "outbound": "direct",
        })
        rules.append({
            "ip_cidr": GAMER_DIRECT_IP_CIDR,
            "outbound": "direct",
        })

    # Custom split tunnel — bypass
    if split_bypass_domains:
        rules.append({
            "domain_keyword": split_bypass_domains,
            "outbound": "direct",
        })
    if split_bypass_ips:
        rules.append({
            "ip_cidr": split_bypass_ips,
            "outbound": "direct",
        })

    # Custom split tunnel — force through proxy
    if split_force_domains:
        rules.append({
            "domain_keyword": split_force_domains,
            "outbound": "proxy",
        })
    if split_force_ips:
        rules.append({
            "ip_cidr": split_force_ips,
            "outbound": "proxy",
        })

    # Private IPs direct
    rules.append({
        "geoip": ["private"],
        "outbound": "direct",
    })

    # Default: everything through proxy
    rules.append({
        "port": [80, 443],
        "outbound": "proxy",
    })

    return {
        "rules": rules,
        "auto_detect_interface": True,
        "final": "proxy",
        "geoip": {
            "download_url": "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db",
            "download_detour": "direct",
        },
        "geosite": {
            "download_url": "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db",
            "download_detour": "direct",
        },
    }


def singbox_config_to_json(config: dict[str, Any], indent: int = 2) -> str:
    """Serialize Sing-box config to formatted JSON string."""
    return json.dumps(config, indent=indent, ensure_ascii=False)
