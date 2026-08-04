"""
MTGroup VPN Ultimate — AmneziaWG Configuration Generator
Builds valid .conf files with Amnezia junk packet parameters
(Jc, Jmin, Jmax, S1, S2, H1, H2, H3, H4) fully compatible
with the official AmneziaWG client.
"""

from __future__ import annotations

import secrets
from typing import Optional


def _generate_wg_keypair() -> tuple[str, str]:
    """
    Generate a simulated WireGuard keypair (base64-encoded 32 bytes).
    In production, use `wg genkey` / `wg pubkey` on the server.
    """
    import base64
    private_bytes = secrets.token_bytes(32)
    private_key = base64.b64encode(private_bytes).decode("ascii")
    # In production this would be derived via Curve25519; here we generate
    # a placeholder public key for template completeness
    public_bytes = secrets.token_bytes(32)
    public_key = base64.b64encode(public_bytes).decode("ascii")
    return private_key, public_key


def generate_amnezia_conf(
    *,
    # Server / Peer parameters
    server_public_key: str,
    server_endpoint: str,
    server_port: int = 51820,
    # Client parameters
    client_private_key: Optional[str] = None,
    client_address: str = "10.0.0.2/32",
    dns: str = "1.1.1.1, 1.0.0.1",
    mtu: int = 1280,
    allowed_ips: str = "0.0.0.0/0, ::/0",
    persistent_keepalive: int = 25,
    # AmneziaWG obfuscation parameters
    jc: int = 4,
    jmin: int = 40,
    jmax: int = 70,
    s1: int = 0,
    s2: int = 0,
    h1: int = 1,
    h2: int = 2,
    h3: int = 3,
    h4: int = 4,
    # Preshared key (optional extra layer)
    preshared_key: Optional[str] = None,
) -> str:
    """
    Generate an AmneziaWG .conf file with full obfuscation parameters.

    The output is directly importable into the official AmneziaWG client
    on Android, iOS, Windows, macOS, and Linux.

    Parameters:
        jc:  Junk packet count (0-128) — number of junk packets injected
        jmin: Minimum junk packet size in bytes (0-1280)
        jmax: Maximum junk packet size in bytes (0-1280, must be >= jmin)
        s1: Init packet junk padding size (0-1280)
        s2: Response packet junk padding size (0-1280)
        h1: Init packet header magic value (0-4294967295)
        h2: Response packet header magic value
        h3: Under-load packet header magic value
        h4: Transport packet header magic value
    """
    if client_private_key is None:
        client_private_key, _ = _generate_wg_keypair()

    # Validate obfuscation parameters
    if jmax < jmin:
        raise ValueError(f"jmax ({jmax}) must be >= jmin ({jmin})")
    if jc < 0 or jc > 128:
        raise ValueError(f"jc ({jc}) must be in range 0-128")
    if not (0 <= jmin <= 1280):
        raise ValueError(f"jmin ({jmin}) must be in range 0-1280")
    if not (0 <= jmax <= 1280):
        raise ValueError(f"jmax ({jmax}) must be in range 0-1280")

    lines = [
        "[Interface]",
        f"PrivateKey = {client_private_key}",
        f"Address = {client_address}",
        f"DNS = {dns}",
        f"MTU = {mtu}",
        # AmneziaWG specific parameters
        f"Jc = {jc}",
        f"Jmin = {jmin}",
        f"Jmax = {jmax}",
        f"S1 = {s1}",
        f"S2 = {s2}",
        f"H1 = {h1}",
        f"H2 = {h2}",
        f"H3 = {h3}",
        f"H4 = {h4}",
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
    ]

    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")

    lines.extend([
        f"AllowedIPs = {allowed_ips}",
        f"Endpoint = {server_endpoint}:{server_port}",
        f"PersistentKeepalive = {persistent_keepalive}",
    ])

    return "\n".join(lines) + "\n"


def generate_amnezia_server_peer(
    *,
    client_public_key: str,
    client_address: str = "10.0.0.2/32",
    preshared_key: Optional[str] = None,
) -> str:
    """
    Generate the server-side [Peer] block for an AmneziaWG client.
    """
    lines = [
        "[Peer]",
        f"PublicKey = {client_public_key}",
    ]
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines.append(f"AllowedIPs = {client_address}")
    return "\n".join(lines) + "\n"


def generate_amnezia_server_conf(
    *,
    server_private_key: str,
    server_address: str = "10.0.0.1/24",
    listen_port: int = 51820,
    dns: str = "1.1.1.1",
    mtu: int = 1280,
    post_up: str = "iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
    post_down: str = "iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
    # AmneziaWG server-side params (must match client)
    jc: int = 4,
    jmin: int = 40,
    jmax: int = 70,
    s1: int = 0,
    s2: int = 0,
    h1: int = 1,
    h2: int = 2,
    h3: int = 3,
    h4: int = 4,
    peers: Optional[list[dict]] = None,
) -> str:
    """
    Generate a complete AmneziaWG server configuration.
    """
    lines = [
        "[Interface]",
        f"PrivateKey = {server_private_key}",
        f"Address = {server_address}",
        f"ListenPort = {listen_port}",
        f"DNS = {dns}",
        f"MTU = {mtu}",
        f"PostUp = {post_up}",
        f"PostDown = {post_down}",
        # AmneziaWG parameters
        f"Jc = {jc}",
        f"Jmin = {jmin}",
        f"Jmax = {jmax}",
        f"S1 = {s1}",
        f"S2 = {s2}",
        f"H1 = {h1}",
        f"H2 = {h2}",
        f"H3 = {h3}",
        f"H4 = {h4}",
    ]

    if peers:
        for peer in peers:
            lines.append("")
            lines.append(
                generate_amnezia_server_peer(
                    client_public_key=peer["public_key"],
                    client_address=peer.get("address", "10.0.0.2/32"),
                    preshared_key=peer.get("preshared_key"),
                )
            )

    return "\n".join(lines) + "\n"


def generate_amnezia_url(
    *,
    conf_content: str,
    label: str = "MTGroup-AmneziaWG",
) -> str:
    """
    Generate a vpn:// deep link for AmneziaWG import.
    Uses base64-encoded conf content in the URI.
    """
    import base64
    from urllib.parse import quote

    encoded = base64.b64encode(conf_content.encode("utf-8")).decode("ascii")
    return f"vpn://{quote(label)}#{encoded}"


def calculate_optimal_amnezia_params(
    *,
    network_type: str = "mobile",  # "mobile", "broadband", "satellite"
    aggression_level: str = "medium",  # "low", "medium", "high", "extreme"
) -> dict:
    """
    Calculate optimal AmneziaWG obfuscation parameters based on
    network conditions and desired DPI evasion aggressiveness.

    Higher aggression = more junk packets = more obfuscation but
    slightly higher bandwidth overhead.
    """
    presets = {
        ("mobile", "low"): {"jc": 2, "jmin": 20, "jmax": 50, "s1": 0, "s2": 0},
        ("mobile", "medium"): {"jc": 4, "jmin": 40, "jmax": 70, "s1": 10, "s2": 10},
        ("mobile", "high"): {"jc": 8, "jmin": 50, "jmax": 100, "s1": 50, "s2": 50},
        ("mobile", "extreme"): {"jc": 16, "jmin": 60, "jmax": 150, "s1": 100, "s2": 100},
        ("broadband", "low"): {"jc": 3, "jmin": 30, "jmax": 60, "s1": 0, "s2": 0},
        ("broadband", "medium"): {"jc": 5, "jmin": 50, "jmax": 90, "s1": 20, "s2": 20},
        ("broadband", "high"): {"jc": 10, "jmin": 60, "jmax": 120, "s1": 80, "s2": 80},
        ("broadband", "extreme"): {"jc": 20, "jmin": 80, "jmax": 200, "s1": 150, "s2": 150},
        ("satellite", "low"): {"jc": 1, "jmin": 10, "jmax": 30, "s1": 0, "s2": 0},
        ("satellite", "medium"): {"jc": 2, "jmin": 20, "jmax": 40, "s1": 5, "s2": 5},
        ("satellite", "high"): {"jc": 4, "jmin": 30, "jmax": 60, "s1": 20, "s2": 20},
        ("satellite", "extreme"): {"jc": 8, "jmin": 40, "jmax": 80, "s1": 40, "s2": 40},
    }

    key = (network_type, aggression_level)
    params = presets.get(key, presets[("mobile", "medium")])

    # Header magic values are randomized per deployment
    import random
    params["h1"] = random.randint(1, 2**32 - 1)
    params["h2"] = random.randint(1, 2**32 - 1)
    params["h3"] = random.randint(1, 2**32 - 1)
    params["h4"] = random.randint(1, 2**32 - 1)

    return params
