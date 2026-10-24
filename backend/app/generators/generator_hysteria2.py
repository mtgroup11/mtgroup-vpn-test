"""
MTGroup VPN Ultimate — Hysteria2 Configuration Generator
SNI-less UDP tunneling with BBRv3 congestion control and
AI-driven packet loss tolerance for hostile environments.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import quote, urlencode

from backend.app.generators._common import uri_host


def generate_hysteria2_link(
    *,
    address: str,
    port: int = 443,
    password: str,
    sni: Optional[str] = None,
    insecure: bool = False,
    obfs_type: Optional[str] = "salamander",
    obfs_password: Optional[str] = None,
    up_mbps: int = 50,
    down_mbps: int = 100,
    label: str = "MTGroup-Hysteria2",
    # Advanced parameters for hostile networks
    disable_mtu_discovery: bool = True,
    hop_interval: Optional[int] = None,
    port_list: Optional[list[int]] = None,
) -> str:
    """
    Generate a Hysteria2 URI compatible with Nekobox, Streisand, V2Box.

    Format: hysteria2://password@address:port?params#label

    The Hysteria2 protocol uses QUIC with custom congestion control
    (Brutal / BBR) and optional obfuscation to survive hostile UDP
    dropping environments common in Iran and China.
    """
    params: dict[str, str] = {}

    if sni:
        params["sni"] = sni

    if insecure:
        params["insecure"] = "1"

    if obfs_type and obfs_password:
        params["obfs"] = obfs_type
        params["obfs-password"] = obfs_password

    # Bandwidth hints for congestion control
    params["up"] = f"{up_mbps}"
    params["down"] = f"{down_mbps}"

    if disable_mtu_discovery:
        params["disable_mtu_discovery"] = "1"

    # Port hopping for DPI evasion
    if hop_interval:
        params["hop-interval"] = str(hop_interval)

    if port_list and len(port_list) > 1:
        params["mport"] = ",".join(str(p) for p in port_list)

    query_string = urlencode(params) if params else ""
    encoded_label = quote(label, safe="")
    encoded_password = quote(password, safe="")

    uri = f"hysteria2://{encoded_password}@{uri_host(address)}:{port}"
    if query_string:
        uri += f"?{query_string}"
    uri += f"#{encoded_label}"

    return uri


def generate_hysteria2_json_config(
    *,
    address: str,
    port: int = 443,
    password: str,
    sni: Optional[str] = None,
    insecure: bool = False,
    obfs_type: Optional[str] = "salamander",
    obfs_password: Optional[str] = None,
    up_mbps: int = 50,
    down_mbps: int = 100,
    # Server-side port hopping (sing-box >= 1.11): e.g. ["20000:30000"]
    server_ports: Optional[list[str]] = None,
    hop_interval: Optional[str] = None,
) -> dict:
    """
    Generate a Hysteria2 outbound for sing-box.

    Only fields sing-box's hysteria2 outbound actually defines are emitted:
    sing-box decodes configs strictly, so a single unknown key (this used
    to add `disable_mtu_discovery` and `lazy`, neither of which exists
    there) makes the client reject the *entire* subscription, not just
    this outbound.
    """
    config: dict = {
        "type": "hysteria2",
        "tag": "hysteria2-out",
        "server": address,
        "server_port": port,
        "password": password,
        "up_mbps": up_mbps,
        "down_mbps": down_mbps,
    }

    tls_config: dict = {
        "enabled": True,
        "disable_sni": sni is None,
        "insecure": insecure,
    }
    if sni:
        tls_config["server_name"] = sni

    # ALPN for Hysteria2
    tls_config["alpn"] = ["h3"]

    config["tls"] = tls_config

    if obfs_type and obfs_password:
        config["obfs"] = {
            "type": obfs_type,
            "password": obfs_password,
        }

    if server_ports:
        config["server_ports"] = server_ports
        if hop_interval:
            config["hop_interval"] = hop_interval

    return config


def generate_hysteria2_server_config(
    *,
    listen_port: int = 443,
    password: str,
    cert_path: str = "/etc/ssl/certs/server.crt",
    key_path: str = "/etc/ssl/private/server.key",
    obfs_type: Optional[str] = "salamander",
    obfs_password: Optional[str] = None,
    up_mbps: int = 1000,
    down_mbps: int = 1000,
    disable_mtu_discovery: bool = True,
    masquerade_url: str = "https://www.google.com",
) -> dict:
    """
    Generate a Hysteria2 server-side configuration.
    Useful for automated server deployment.
    """
    config: dict = {
        "listen": f":{listen_port}",
        "tls": {
            "cert": cert_path,
            "key": key_path,
        },
        "auth": {
            "type": "password",
            "password": password,
        },
        "masquerade": {
            "type": "proxy",
            "url": masquerade_url,
        },
        "bandwidth": {
            "up": f"{up_mbps} mbps",
            "down": f"{down_mbps} mbps",
        },
        "disableUDP": False,
        "udpIdleTimeout": "60s",
    }

    if obfs_type and obfs_password:
        config["obfs"] = {
            "type": obfs_type,
            "password": obfs_password,
        }

    if disable_mtu_discovery:
        config["quic"] = {
            "disablePathMTUDiscovery": True,
        }

    return config
