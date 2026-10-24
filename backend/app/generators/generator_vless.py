"""
MTGroup VPN Ultimate — VLESS+REALITY Configuration Generator
Generates protocol URIs with uTLS fingerprinting, TLS fragmentation
and SNI camouflage for Streisand/V2Box/v2rayNG.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional
from urllib.parse import quote, urlencode

from backend.app.generators._common import normalize_fingerprint as _get_fingerprint
from backend.app.generators._common import uri_host
from backend.app.models import HostSpoofMode
from backend.app.geo_camouflage import get_camouflage_for_ip


def generate_vless_reality_link(
    *,
    address: str,
    port: int = 443,
    user_uuid: Optional[str] = None,
    sni: str = "www.google.com",
    fingerprint: str = "chrome",
    public_key: str,
    short_id: Optional[str] = None,
    spider_x: str = "/",
    flow: str = "xtls-rprx-vision",
    label: str = "MTGroup-REALITY",
    # TLS Fragmentation parameters
    tls_fragment_enabled: bool = True,
    tls_fragment_size_min: int = 50,
    tls_fragment_size_max: int = 200,
    tls_fragment_interval_min: int = 10,
    tls_fragment_interval_max: int = 50,
    # Multi-port hopping
    port_list: Optional[list[int]] = None,
    # Geo Camouflage
    client_ip: Optional[str] = None,
) -> str:
    """
    Generate a VLESS+REALITY URI compatible with v2rayNG, Streisand, V2Box, Nekobox.

    Format: vless://UUID@address:port?params#label
    """
    if user_uuid is None:
        user_uuid = str(uuid.uuid4())

    # The short ID must be one the node's Reality inbound actually lists in
    # `shortIds`. Inventing a random one (as before) produced links that
    # could never authenticate; "" is the conventional always-present entry.
    if short_id is None:
        short_id = ""

    if client_ip:
        camo = get_camouflage_for_ip(client_ip)
        sni = camo.sni

    params: dict[str, str] = {
        "type": "tcp",
        "security": "reality",
        "pbk": public_key,
        "sid": short_id,
        "sni": sni,
        "fp": _get_fingerprint(fingerprint),
        # urlencode() below does the escaping — quoting here as well made
        # clients receive "%2F" instead of "/".
        "spx": spider_x,
        "flow": flow,
        "encryption": "none",
    }

    # TLS Fragmentation — injected as custom query parameters
    # Supported by Streisand, Nekobox, and v2rayNG (with Xray core)
    if tls_fragment_enabled:
        params["fragment"] = (
            f"{tls_fragment_size_min}-{tls_fragment_size_max},"
            f"{tls_fragment_interval_min}-{tls_fragment_interval_max}"
        )

    # Multi-port support (for clients that support port arrays)
    if port_list and len(port_list) > 1:
        params["ports"] = ",".join(str(p) for p in port_list)

    query_string = urlencode(params)
    encoded_label = quote(label, safe="")

    return f"vless://{user_uuid}@{uri_host(address)}:{port}?{query_string}#{encoded_label}"


def generate_vless_ws_link(
    *,
    address: str,
    port: int = 443,
    user_uuid: Optional[str] = None,
    sni: str = "www.google.com",
    fingerprint: str = "chrome",
    ws_path: str = "/ws",
    ws_host: Optional[str] = None,
    tls_enabled: bool = True,
    label: str = "MTGroup-WS",
    host_spoof_mode: HostSpoofMode = HostSpoofMode.NONE,
    spoofed_host: Optional[str] = None,
    tls_fragment_enabled: bool = False,
    tls_fragment_size_min: int = 50,
    tls_fragment_size_max: int = 200,
    tls_fragment_interval_min: int = 10,
    tls_fragment_interval_max: int = 50,
) -> str:
    """
    Generate a VLESS+WebSocket URI for CDN-fronted tunneling.
    """
    if user_uuid is None:
        user_uuid = str(uuid.uuid4())

    params: dict[str, str] = {
        "type": "ws",
        "security": "tls" if tls_enabled else "none",
        "sni": sni,
        "fp": _get_fingerprint(fingerprint),
        "path": ws_path,  # escaped once, by urlencode()
        "encryption": "none",
    }

    # Host Spoofing injection for WS
    if host_spoof_mode != HostSpoofMode.NONE and spoofed_host:
        params["host"] = spoofed_host
        if host_spoof_mode == HostSpoofMode.BUG_INJECTION:
            params["path"] = f"http://{spoofed_host}{ws_path}"
    elif ws_host:
        params["host"] = ws_host

    # TLS Fragmentation for WS
    if tls_fragment_enabled and tls_enabled:
        params["fragment"] = (
            f"{tls_fragment_size_min}-{tls_fragment_size_max},"
            f"{tls_fragment_interval_min}-{tls_fragment_interval_max}"
        )

    query_string = urlencode(params)
    encoded_label = quote(label, safe="")

    return f"vless://{user_uuid}@{uri_host(address)}:{port}?{query_string}#{encoded_label}"


def generate_vless_grpc_link(
    *,
    address: str,
    port: int = 443,
    user_uuid: Optional[str] = None,
    sni: str = "www.google.com",
    fingerprint: str = "chrome",
    service_name: str = "mtgroup",
    label: str = "MTGroup-gRPC",
    public_key: Optional[str] = None,
    short_id: Optional[str] = None,
) -> str:
    """
    Generate a VLESS+gRPC+REALITY URI for high-performance tunneling.
    """
    if user_uuid is None:
        user_uuid = str(uuid.uuid4())

    params: dict[str, str] = {
        "type": "grpc",
        "serviceName": service_name,
        "encryption": "none",
        "fp": _get_fingerprint(fingerprint),
        "sni": sni,
    }

    if public_key:
        params["security"] = "reality"
        params["pbk"] = public_key
        params["sid"] = short_id or ""
    else:
        params["security"] = "tls"

    query_string = urlencode(params)
    encoded_label = quote(label, safe="")

    return f"vless://{user_uuid}@{uri_host(address)}:{port}?{query_string}#{encoded_label}"


def generate_trojan_reality_link(
    *,
    address: str,
    port: int = 443,
    password: str,
    sni: str = "www.google.com",
    fingerprint: str = "chrome",
    public_key: str,
    short_id: Optional[str] = None,
    label: str = "MTGroup-Trojan",
    tls_fragment_enabled: bool = True,
    tls_fragment_size_min: int = 50,
    tls_fragment_size_max: int = 200,
    tls_fragment_interval_min: int = 10,
    tls_fragment_interval_max: int = 50,
    client_ip: Optional[str] = None,
) -> str:
    """
    Generate a Trojan+REALITY URI with TLS fragmentation.

    No `flow`: XTLS Vision is VLESS-only, Trojan has no flow setting.
    """
    if short_id is None:
        short_id = ""

    if client_ip:
        camo = get_camouflage_for_ip(client_ip)
        sni = camo.sni

    params: dict[str, str] = {
        "type": "tcp",
        "security": "reality",
        "pbk": public_key,
        "sid": short_id,
        "sni": sni,
        "fp": _get_fingerprint(fingerprint),
    }

    if tls_fragment_enabled:
        params["fragment"] = (
            f"{tls_fragment_size_min}-{tls_fragment_size_max},"
            f"{tls_fragment_interval_min}-{tls_fragment_interval_max}"
        )

    query_string = urlencode(params)
    encoded_label = quote(label, safe="")

    return f"trojan://{quote(password, safe='')}@{uri_host(address)}:{port}?{query_string}#{encoded_label}"


def parse_vless_link(uri: str) -> dict[str, Any]:
    """
    Parse a VLESS URI back into its component parameters.
    Useful for editing/re-generating configs.
    """
    from urllib.parse import parse_qs, unquote

    if not uri.startswith("vless://"):
        raise ValueError("Not a valid VLESS URI")

    stripped = uri[8:]  # Remove "vless://"
    label = ""
    if "#" in stripped:
        stripped, label = stripped.rsplit("#", 1)
        label = unquote(label)

    user_part, rest = stripped.split("@", 1)
    host_part, query_part = rest.split("?", 1)
    address, port_str = host_part.rsplit(":", 1)
    address = address.strip("[]")

    params = parse_qs(query_part)
    flat_params = {k: v[0] for k, v in params.items()}

    return {
        "uuid": user_part,
        "address": address,
        "port": int(port_str),
        "label": label,
        **flat_params,
    }
