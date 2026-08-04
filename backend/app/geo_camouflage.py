"""
MTGroup VPN Ultimate — Geo-Adaptive SNI & Camouflage Rotator
═══════════════════════════════════════════════════════════════════
Dynamically rotates VLESS-Reality serverNames, dest, and SNI fields
based on the requesting client's GeoIP location.

When a subscriber from Iran requests their config, they get
serverNames=["irancell.ir"]. A Chinese user gets ["baidu.com"].
This makes the VPN tunnel's TLS handshake indistinguishable from
legitimate local traffic in each country.

Architecture:
  - Uses IP-to-country lookup (MaxMind GeoLite2 or fallback heuristic)
  - Maintains curated whitelists of SNI domains per country
  - Integrates with generator_vless.py at config generation time
  - All generated configs are encrypted in RAM and never cached on disk
"""

from __future__ import annotations

import hashlib
import logging
import random
import socket
import struct
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("mtgroup.geo_camouflage")


# ---------------------------------------------------------------------------
# Curated SNI Domain Whitelists per Country
# ---------------------------------------------------------------------------
# These domains are chosen because:
# 1. They are whitelisted by the country's censorship system
# 2. They support TLS 1.3 (required for REALITY)
# 3. They have high traffic volume (our tunnel blends in)
# 4. They use similar certificate pinning patterns

GEO_SNI_MAP: dict[str, list[dict[str, str]]] = {
    "IR": [
        {"sni": "www.digikala.com",     "dest": "www.digikala.com:443",     "label": "Digikala"},
        {"sni": "www.shaparak.ir",      "dest": "www.shaparak.ir:443",      "label": "Shaparak"},
        {"sni": "static.cdn.asset.aparat.com", "dest": "static.cdn.asset.aparat.com:443", "label": "Aparat CDN"},
        {"sni": "www.bale.ai",          "dest": "www.bale.ai:443",          "label": "Bale"},
    ],
    "CN": [
        {"sni": "www.baidu.com",        "dest": "www.baidu.com:443",        "label": "Baidu"},
        {"sni": "www.qq.com",           "dest": "www.qq.com:443",           "label": "Tencent QQ"},
        {"sni": "www.taobao.com",       "dest": "www.taobao.com:443",       "label": "Taobao"},
        {"sni": "www.jd.com",           "dest": "www.jd.com:443",           "label": "JD.com"},
        {"sni": "www.163.com",          "dest": "www.163.com:443",          "label": "NetEase"},
    ],
    "RU": [
        {"sni": "www.yandex.ru",        "dest": "www.yandex.ru:443",        "label": "Yandex"},
        {"sni": "www.vk.com",           "dest": "www.vk.com:443",           "label": "VKontakte"},
        {"sni": "www.mail.ru",          "dest": "www.mail.ru:443",          "label": "Mail.ru"},
        {"sni": "www.ok.ru",            "dest": "www.ok.ru:443",            "label": "Odnoklassniki"},
    ],
    "TR": [
        {"sni": "www.google.com",       "dest": "www.google.com:443",       "label": "Google"},
        {"sni": "www.microsoft.com",    "dest": "www.microsoft.com:443",    "label": "Microsoft"},
        {"sni": "cdn.jsdelivr.net",     "dest": "cdn.jsdelivr.net:443",     "label": "jsDelivr CDN"},
    ],
    "GLOBAL": [
        {"sni": "www.google.com",       "dest": "www.google.com:443",       "label": "Google"},
        {"sni": "www.microsoft.com",    "dest": "www.microsoft.com:443",    "label": "Microsoft"},
        {"sni": "www.apple.com",        "dest": "www.apple.com:443",        "label": "Apple"},
        {"sni": "cdn.cloudflare.com",   "dest": "cdn.cloudflare.com:443",   "label": "Cloudflare"},
        {"sni": "www.amazon.com",       "dest": "www.amazon.com:443",       "label": "Amazon"},
    ],
}


# ---------------------------------------------------------------------------
# GeoIP Resolver (Lightweight, No External DB Required)
# ---------------------------------------------------------------------------

# Private/reserved IP ranges (for fallback detection)
_PRIVATE_RANGES = [
    (0x0A000000, 0xFF000000),  # 10.0.0.0/8
    (0xAC100000, 0xFFF00000),  # 172.16.0.0/12
    (0xC0A80000, 0xFFFF0000),  # 192.168.0.0/16
    (0x7F000000, 0xFF000000),  # 127.0.0.0/8
]


def _ip_to_int(ip_str: str) -> int:
    """Convert dotted-quad IPv4 to integer."""
    try:
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]
    except (socket.error, struct.error):
        return 0


def _is_private(ip_str: str) -> bool:
    """Check if IP is in private/reserved range."""
    ip_int = _ip_to_int(ip_str)
    for network, mask in _PRIVATE_RANGES:
        if (ip_int & mask) == network:
            return True
    return False


def detect_country(client_ip: str) -> str:
    """
    Detect the client's country from their IP address.
    
    Strategy:
    1. Try MaxMind GeoLite2 if available (most accurate)
    2. Fall back to reverse DNS heuristics
    3. Default to "GLOBAL"
    """
    if _is_private(client_ip):
        return "GLOBAL"

    # Strategy 1: MaxMind GeoLite2 (if installed)
    try:
        import geoip2.database  # type: ignore
        reader = geoip2.database.Reader("/usr/share/GeoIP/GeoLite2-Country.mmdb")
        response = reader.country(client_ip)
        country = response.country.iso_code
        reader.close()
        if country in GEO_SNI_MAP:
            return country
        return "GLOBAL"
    except Exception:
        pass

    # Strategy 2: Reverse DNS heuristic (zero dependencies)
    try:
        hostname = socket.gethostbyaddr(client_ip)[0].lower()
        if hostname.endswith(".ir"):
            return "IR"
        if hostname.endswith(".cn") or hostname.endswith(".com.cn"):
            return "CN"
        if hostname.endswith(".ru"):
            return "RU"
        if hostname.endswith(".tr"):
            return "TR"
    except (socket.herror, socket.gaierror, OSError):
        pass

    return "GLOBAL"


# ---------------------------------------------------------------------------
# Camouflage Engine
# ---------------------------------------------------------------------------

@dataclass
class CamouflageResult:
    """Result of a geo-adaptive SNI selection."""
    country: str
    sni: str
    dest: str
    label: str
    server_names: list[str]


def get_camouflage_for_ip(
    client_ip: str,
    preferred_country: Optional[str] = None,
) -> CamouflageResult:
    """
    Select the optimal SNI camouflage profile for a client IP.
    
    Uses deterministic-random selection seeded by the client IP so the same
    client always gets the same SNI (prevents config churn on reconnect).
    """
    country = preferred_country or detect_country(client_ip)
    profiles = GEO_SNI_MAP.get(country, GEO_SNI_MAP["GLOBAL"])

    # Deterministic selection based on IP hash (same IP = same SNI always)
    seed = int(hashlib.sha256(client_ip.encode()).hexdigest()[:8], 16)
    selected = profiles[seed % len(profiles)]

    # Build serverNames list (primary + 1-2 alternates for Reality)
    rng = random.Random(seed)
    alternates = [p["sni"] for p in profiles if p["sni"] != selected["sni"]]
    rng.shuffle(alternates)
    server_names = [selected["sni"]] + alternates[:2]

    logger.debug(
        "GeoCamouflage: ip=%s country=%s sni=%s",
        client_ip, country, selected["sni"],
    )

    return CamouflageResult(
        country=country,
        sni=selected["sni"],
        dest=selected["dest"],
        label=selected["label"],
        server_names=server_names,
    )


def get_available_countries() -> list[dict[str, str]]:
    """List all supported camouflage regions with SNI counts."""
    return [
        {
            "country": code,
            "profiles": len(profiles),
            "example_sni": profiles[0]["sni"],
        }
        for code, profiles in GEO_SNI_MAP.items()
    ]
