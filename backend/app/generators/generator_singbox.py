"""
MTGroup VPN Ultimate — Sing-box Configuration Generator
Complete client JSON config with Iran bypass, gamer-mode routing and
split tunneling. This is the default format for unknown clients and the
primary one for Streisand, NekoBox, Hiddify, SFA/SFI and v2box.

Targets the sing-box 1.12+ configuration format and must stay loadable on
every stable line in use (1.12, 1.13, 1.14 at the time of writing).
sing-box decodes configs strictly — one unknown or removed field makes the
client reject the whole subscription — so this module only emits fields
that exist in all of those versions. The previous generator relied on
features removed upstream (legacy `geoip`/`geosite` rules and databases,
`block`/`dns` special outbounds, inbound `sniff` fields, `inet4_address`,
legacy DNS server strings) plus an `experimental.tls_fragment` key that
never existed, and was rejected by 1.12, 1.13 and 1.14 alike.

Iran bypass uses inline `domain_suffix`/`ip_cidr` rules rather than remote
rule-sets: a rule-set that can't be downloaded (GitHub is routinely
throttled in Iran) stops the client from starting at all, which is the
worst possible failure for a censorship-circumvention config.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from typing import Any, Optional

from backend.app.generators._common import normalize_fingerprint as _get_fingerprint
from backend.app.models import HostSpoofMode, ShapingMode

logger = logging.getLogger("mtgroup.generators.singbox")


# ---------------------------------------------------------------------------
# Iran Bypass Constants
# ---------------------------------------------------------------------------

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
    # Accepted for call-site compatibility; sing-box has no portable
    # (1.12-1.14) TLS-fragment setting, and fragmenting a Reality
    # ClientHello gains nothing anyway — its SNI is a real third-party site.
    tls_fragment_enabled: bool = False,
    tls_fragment_size: str = "50-200",
    tls_fragment_sleep: str = "10-50",
    # DNS
    dns_servers: Optional[list[str]] = None,
    dns_strategy: str = "ipv4_only",
    # Label
    label: str = "MTGroup VPN",
    # DPI Evasion
    tls_fingerprint: str = "chrome",
    shaping_mode: ShapingMode = ShapingMode.VIDEO_STREAM,
    host_spoof_mode: HostSpoofMode = HostSpoofMode.NONE,
    spoofed_host: Optional[str] = None,
) -> dict[str, Any]:
    """
    Generate a complete sing-box client configuration.

    `dns_servers` entries are DoH URLs (``https://1.1.1.1/dns-query``) or
    plain IPs; only the first is used, as the remote resolver.
    """
    if warp_bypass:
        # The old WARP outbound shipped a literal "YOUR_WARP_PRIVATE_KEY"
        # placeholder, which made sing-box reject the whole config for any
        # user with this flag. There is no per-user WARP registration in
        # this panel to fill it from, so the flag is a no-op until there is.
        logger.debug("warp_bypass requested but no WARP credentials are provisioned; ignoring")

    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": _build_dns_config(
            dns_server=(dns_servers or ["https://1.1.1.1/dns-query"])[0],
            dns_strategy=dns_strategy,
            iran_bypass=iran_bypass,
        ),
        "inbounds": _build_inbounds(),
        "outbounds": _build_outbounds(
            user_outbounds=outbounds,
            tls_fingerprint=tls_fingerprint,
            host_spoof_mode=host_spoof_mode,
            spoofed_host=spoofed_host,
            battery_saver=battery_saver,
        ),
        "route": _build_route(
            iran_bypass=iran_bypass,
            gamer_mode=gamer_mode,
            split_bypass_domains=split_bypass_domains or [],
            split_bypass_ips=split_bypass_ips or [],
            split_force_domains=split_force_domains or [],
            split_force_ips=split_force_ips or [],
        ),
    }


_DNS_URL_RE = re.compile(r"^(https|tls|quic|h3|udp|tcp)://([^/:]+)(?::(\d+))?(/.*)?$")


def _dns_server_from(spec: str) -> dict[str, Any]:
    """Turn ``https://host/path`` / ``tls://host`` / ``1.2.3.4`` into a
    1.12-format typed DNS server definition."""
    match = _DNS_URL_RE.match(spec.strip())
    if not match:
        return {"type": "udp", "server": spec.strip()}
    scheme, host, port, path = match.groups()
    server: dict[str, Any] = {"type": scheme, "server": host}
    if port:
        server["server_port"] = int(port)
    if path and scheme in ("https", "h3") and path != "/dns-query":
        server["path"] = path
    return server


def _build_dns_config(dns_server: str, dns_strategy: str, iran_bypass: bool) -> dict[str, Any]:
    """Remote DNS through the tunnel; Iranian names resolved locally so
    domestic services get domestic (CDN-local, unblocked) answers."""
    remote = _dns_server_from(dns_server)
    remote.update({"tag": "dns-remote", "detour": "proxy"})
    servers = [remote, {"type": "local", "tag": "dns-local"}]

    rules: list[dict[str, Any]] = []
    if iran_bypass:
        rules.append(_domain_rule(IRAN_BYPASS_DOMAINS, server="dns-local"))

    return {
        "servers": servers,
        "rules": rules,
        "final": "dns-remote",
        "strategy": dns_strategy,
    }


def _build_inbounds() -> list[dict[str, Any]]:
    return [{
        "type": "tun",
        "tag": "tun-in",
        "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
        "auto_route": True,
        "strict_route": True,
    }]


_UTLS_CAPABLE = {"vless", "vmess", "trojan", "shadowtls", "anytls"}


def _build_outbounds(
    user_outbounds: list[dict[str, Any]],
    tls_fingerprint: str,
    host_spoof_mode: HostSpoofMode,
    spoofed_host: Optional[str],
    battery_saver: bool = False,
) -> list[dict[str, Any]]:
    """Selector + url-test over the user's servers, then the servers, then
    `direct`. No `multiplex`: it used to be injected into every outbound,
    which sing-box rejects outright on hysteria2/tuic (no such field), and
    VLESS-Vision doesn't support it either."""
    for ob in user_outbounds:
        tls = ob.get("tls")
        # uTLS only exists for TCP+TLS protocols — QUIC-based hysteria2/tuic
        # have no uTLS. Don't override a fingerprint the caller already set.
        if isinstance(tls, dict) and ob.get("type") in _UTLS_CAPABLE and "utls" not in tls:
            tls["utls"] = {"enabled": True, "fingerprint": _get_fingerprint(tls_fingerprint)}

        transport = ob.get("transport")
        if (host_spoof_mode != HostSpoofMode.NONE and spoofed_host
                and isinstance(transport, dict) and transport.get("type") in ("ws", "httpupgrade")):
            if transport["type"] == "ws":
                transport.setdefault("headers", {})["Host"] = spoofed_host
            else:
                transport["host"] = spoofed_host
            if host_spoof_mode == HostSpoofMode.BUG_INJECTION:
                transport["path"] = f"http://{spoofed_host}{transport.get('path', '/')}"

    proxy_tags = []
    for i, ob in enumerate(user_outbounds):
        ob.setdefault("tag", f"proxy-{i}")
        proxy_tags.append(ob["tag"])

    outbounds: list[dict[str, Any]] = []
    if proxy_tags:
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
            # Probing every server every few minutes keeps radios awake.
            "interval": "30m" if battery_saver else "5m",
            "tolerance": 50,
        })
    else:
        # urltest/selector with no members is a hard error. Callers should
        # refuse to render a config without servers; this just keeps the
        # output loadable if one slips through.
        outbounds.append({"type": "selector", "tag": "proxy", "outbounds": ["direct"]})

    outbounds.extend(user_outbounds)
    outbounds.append({"type": "direct", "tag": "direct"})
    return outbounds


_DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]{1,63}\.)*[a-z0-9-]{1,63}$")


def _clean_domains(values: list[str]) -> list[str]:
    """User-supplied split-tunnel domains -> valid suffixes; junk dropped."""
    out = []
    for value in values:
        if not isinstance(value, str):
            continue
        domain = value.strip().lower()
        if domain.startswith("domain:"):
            domain = domain[len("domain:"):]
        domain = domain.lstrip(".")
        if _DOMAIN_RE.match(domain):
            out.append(domain)
    return out


def _clean_cidrs(values: list[str]) -> list[str]:
    out = []
    for value in values:
        try:
            out.append(str(ipaddress.ip_network(str(value).strip(), strict=False)))
        except ValueError:
            continue
    return out


def _domain_rule(specs: list[str], **target: str) -> dict[str, Any]:
    """Xray-style `domain:`/`full:` specs -> one sing-box rule.

    The constants are written in Xray syntax and used to be passed to
    sing-box verbatim, where `"domain:battle.net"` is just a literal string
    that never matches anything.
    """
    suffixes, exact = [], []
    for spec in specs:
        if spec.startswith("full:"):
            exact.append(spec[len("full:"):])
        else:
            suffixes.append(spec.split(":", 1)[-1].lstrip("."))
    rule: dict[str, Any] = {}
    if exact:
        rule["domain"] = exact
    if suffixes:
        rule["domain_suffix"] = suffixes
    rule.update(target)
    return rule


def _build_route(
    iran_bypass: bool,
    gamer_mode: bool,
    split_bypass_domains: list[str],
    split_bypass_ips: list[str],
    split_force_domains: list[str],
    split_force_ips: list[str],
) -> dict[str, Any]:
    """Routing rules. First match wins, so the user's explicit "force
    through proxy" entries come before every bypass."""
    rules: list[dict[str, Any]] = [
        # Domain-based rules can't match in TUN mode without sniffing.
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"ip_is_private": True, "outbound": "direct"},
    ]

    force_domains = _clean_domains(split_force_domains)
    force_ips = _clean_cidrs(split_force_ips)
    if force_domains:
        rules.append({"domain_suffix": force_domains, "outbound": "proxy"})
    if force_ips:
        rules.append({"ip_cidr": force_ips, "outbound": "proxy"})

    bypass_domains = _clean_domains(split_bypass_domains)
    bypass_ips = _clean_cidrs(split_bypass_ips)
    if bypass_domains:
        # domain_suffix, not domain_keyword: a keyword "ir" matched every
        # domain containing those two letters.
        rules.append({"domain_suffix": bypass_domains, "outbound": "direct"})
    if bypass_ips:
        rules.append({"ip_cidr": bypass_ips, "outbound": "direct"})

    if iran_bypass:
        rules.append(_domain_rule(IRAN_BYPASS_DOMAINS, outbound="direct"))
        # The whole list — it used to be silently cut to the first 50 of 232.
        rules.append({"ip_cidr": list(IRAN_BYPASS_IP_CIDR), "outbound": "direct"})

    if gamer_mode:
        rules.append(_domain_rule(GAMER_DIRECT_DOMAINS, outbound="direct"))
        rules.append({"ip_cidr": list(GAMER_DIRECT_IP_CIDR), "outbound": "direct"})

    return {
        "rules": rules,
        "final": "proxy",
        "auto_detect_interface": True,
        # Resolves the proxy servers' own hostnames (when a node address is
        # a domain) without going through the tunnel they establish.
        "default_domain_resolver": {"server": "dns-local"},
    }


def singbox_config_to_json(config: dict[str, Any], indent: int = 2) -> str:
    """Serialize Sing-box config to formatted JSON string."""
    return json.dumps(config, indent=indent, ensure_ascii=False)
