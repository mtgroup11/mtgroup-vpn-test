"""
MTGroup VPN Ultimate — TUIC v5 Configuration Generator
UDP relay tunneling with congestion control for hostile environments.
"""

from __future__ import annotations

import uuid as uuid_mod
from typing import Optional
from urllib.parse import quote, urlencode


def generate_tuic_link(
    *,
    address: str,
    port: int = 443,
    user_uuid: Optional[str] = None,
    password: str,
    sni: Optional[str] = None,
    insecure: bool = False,
    congestion_control: str = "bbr",
    alpn: str = "h3",
    udp_relay_mode: str = "native",
    zero_rtt_handshake: bool = True,
    label: str = "MTGroup-TUIC",
    disable_sni: bool = False,
) -> str:
    """
    Generate a TUIC v5 URI compatible with Nekobox, V2Box, Streisand.

    Format: tuic://uuid:password@address:port?params#label

    TUIC v5 provides high-performance UDP relay with QUIC transport,
    optimized for environments with aggressive UDP filtering.
    """
    if user_uuid is None:
        user_uuid = str(uuid_mod.uuid4())

    params: dict[str, str] = {
        "congestion_control": congestion_control,
        "udp_relay_mode": udp_relay_mode,
        "alpn": alpn,
    }

    if sni:
        params["sni"] = sni

    if insecure:
        params["allow_insecure"] = "1"

    if zero_rtt_handshake:
        params["zero_rtt_handshake"] = "1"

    if disable_sni:
        params["disable_sni"] = "1"

    query_string = urlencode(params)
    encoded_label = quote(label, safe="")
    encoded_password = quote(password, safe="")

    return (
        f"tuic://{user_uuid}:{encoded_password}@{address}:{port}"
        f"?{query_string}#{encoded_label}"
    )


def generate_tuic_singbox_config(
    *,
    address: str,
    port: int = 443,
    user_uuid: Optional[str] = None,
    password: str,
    sni: Optional[str] = None,
    insecure: bool = False,
    congestion_control: str = "bbr",
    udp_relay_mode: str = "native",
    zero_rtt_handshake: bool = True,
    heartbeat_interval_sec: int = 10,
) -> dict:
    """
    Generate a TUIC v5 outbound configuration block for Sing-box.
    """
    if user_uuid is None:
        user_uuid = str(uuid_mod.uuid4())

    config: dict = {
        "type": "tuic",
        "tag": "tuic-out",
        "server": address,
        "server_port": port,
        "uuid": user_uuid,
        "password": password,
        "congestion_control": congestion_control,
        "udp_relay_mode": udp_relay_mode,
        "zero_rtt_handshake": zero_rtt_handshake,
        "heartbeat": f"{heartbeat_interval_sec}s",
        "tls": {
            "enabled": True,
            "insecure": insecure,
            "alpn": ["h3"],
        },
    }

    if sni:
        config["tls"]["server_name"] = sni
    else:
        config["tls"]["disable_sni"] = True

    return config


def generate_tuic_server_config(
    *,
    listen_port: int = 443,
    users: list[dict],
    cert_path: str = "/etc/ssl/certs/server.crt",
    key_path: str = "/etc/ssl/private/server.key",
    congestion_control: str = "bbr",
    max_idle_time_ms: int = 15000,
    authentication_timeout_ms: int = 1000,
    max_external_packet_size: int = 1500,
) -> dict:
    """
    Generate TUIC v5 server-side configuration.

    Args:
        users: List of dicts with 'uuid' and 'password' keys.
    """
    user_map = {}
    for user in users:
        user_map[user["uuid"]] = user["password"]

    return {
        "server": f"[::]:{ listen_port}",
        "users": user_map,
        "certificate": cert_path,
        "private_key": key_path,
        "congestion_control": congestion_control,
        "max_idle_time": f"{max_idle_time_ms}ms",
        "authentication_timeout": f"{authentication_timeout_ms}ms",
        "alpn": ["h3"],
        "max_external_packet_size": max_external_packet_size,
        "log_level": "info",
    }
