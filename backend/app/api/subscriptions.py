"""
MTGroup VPN Ultimate — Subscription Endpoints
Universal subscription endpoint that auto-detects client type
and generates optimized configs for Streisand, V2Box, Nekobox,
AmneziaWG, and v2rayNG.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import uuid as uuid_mod
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Header, Request, Response
from fastapi.responses import PlainTextResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.auth import get_db
from backend.app.core.config import settings
from backend.app.core.wireguard_peers import NoAddressesAvailable, get_or_create_peer
from backend.app.generators.generator_amnezia import generate_amnezia_conf
from backend.app.generators.generator_clash import (
    generate_clash_config,
    generate_clash_hysteria2_proxy,
    generate_clash_tuic_proxy,
    generate_clash_vless_proxy,
)
from backend.app.generators.generator_hysteria2 import generate_hysteria2_link
from backend.app.generators.generator_singbox import generate_singbox_config
from backend.app.generators.generator_tuic import generate_tuic_link, generate_tuic_singbox_config
from backend.app.generators.generator_vless import generate_vless_reality_link
from backend.app.generators.generator_hysteria2 import generate_hysteria2_json_config
from backend.app.models import Node, NodeProtocol, Subscription, User
from backend.app.orchestrator import orchestrator

logger = logging.getLogger("mtgroup.api.subscriptions")
router = APIRouter(tags=["Subscriptions"])


async def _get_user_by_sub_token(
    token: str, db: AsyncSession
) -> tuple[User, Subscription]:
    """Look up user and subscription by token, validating active status."""
    result = await db.execute(
        select(Subscription).where(
            Subscription.token == token,
            Subscription.is_active,
        )
    )
    sub = result.scalar_one_or_none()
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")

    result = await db.execute(select(User).where(User.id == sub.user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=403, detail="User account is inactive")

    # Check expiration (normalize to UTC-aware — SQLite may return naive)
    if user.expire_date:
        expire_dt = user.expire_date
        if expire_dt.tzinfo is None:
            expire_dt = expire_dt.replace(tzinfo=timezone.utc)
        if expire_dt < datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Subscription expired")

    # Check data limit
    if user.data_limit_bytes > 0 and user.data_used_bytes >= user.data_limit_bytes:
        raise HTTPException(status_code=403, detail="Data limit exceeded")

    return user, sub


async def _get_active_nodes(db: AsyncSession) -> list[Node]:
    """Fetch all active nodes."""
    result = await db.execute(
        select(Node).where(Node.is_active)
    )
    return list(result.scalars().all())


def _generate_user_uuid(user_id: int, node_id: int) -> str:
    """Generate a deterministic UUID for a user+node combination."""
    namespace = uuid_mod.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
    return str(uuid_mod.uuid5(namespace, f"{user_id}:{node_id}"))


def _detect_client(user_agent: str) -> str:
    """Detect client type from User-Agent header."""
    ua_lower = user_agent.lower()
    if "streisand" in ua_lower:
        return "singbox"
    if "nekobox" in ua_lower or "neko" in ua_lower:
        return "singbox"
    if "v2box" in ua_lower:
        return "singbox"
    if "clash" in ua_lower or "mihomo" in ua_lower or "stash" in ua_lower:
        return "clash"
    if "v2ray" in ua_lower or "v2rayng" in ua_lower:
        return "v2ray"
    if "amnezia" in ua_lower:
        return "amnezia"
    # Default to singbox for unknown clients
    return "singbox"


# ---------------------------------------------------------------------------
# Universal Subscription Endpoint (auto-detect)
# ---------------------------------------------------------------------------

@router.get("/sub/{token}")
async def get_subscription(
    token: str,
    request: Request,
    user_agent: str = Header(default=""),
    db: AsyncSession = Depends(get_db),
):
    """
    Universal subscription endpoint.
    Auto-detects client type from User-Agent and returns the
    appropriate configuration format.
    """
    client_type = _detect_client(user_agent)

    if client_type == "singbox":
        return await get_singbox_config(token, db=db)
    elif client_type == "clash":
        return await get_clash_config(token, db=db)
    elif client_type == "amnezia":
        return await get_amnezia_config(token, db=db)
    else:
        return await get_v2ray_links(token, db=db)


# ---------------------------------------------------------------------------
# Sing-box JSON Config
# ---------------------------------------------------------------------------

@router.get("/sub/{token}/singbox")
async def get_singbox_config(
    token: str,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Generate Sing-box JSON config for Streisand/Nekobox/V2Box."""
    user, sub = await _get_user_by_sub_token(token, db)
    nodes = await _get_active_nodes(db)

    if not nodes:
        raise HTTPException(status_code=503, detail="No active nodes available")

    enabled_protocols = json.loads(sub.protocols)
    split_bypass = json.loads(user.split_tunnel_bypass or "[]")
    split_force = json.loads(user.split_tunnel_force or "[]")

    outbounds = []
    for node in nodes:
        if node.protocol.value not in enabled_protocols:
            continue

        user_uuid = _generate_user_uuid(user.id, node.id)
        address = node.floating_ip or node.address

        if node.protocol == NodeProtocol.VLESS_REALITY:
            outbounds.append({
                "type": "vless",
                "tag": f"vless-{node.name}",
                "server": address,
                "server_port": node.port,
                "uuid": user_uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": node.sni or settings.DEFAULT_SNI,
                    "utls": {
                        "enabled": True,
                        "fingerprint": settings.DEFAULT_FINGERPRINT,
                    },
                    "reality": {
                        "enabled": True,
                        "public_key": node.reality_public_key or "",
                        "short_id": node.reality_short_id or "",
                    },
                },
                "packet_encoding": "xudp",
            })

        elif node.protocol == NodeProtocol.HYSTERIA2:
            outbounds.append(
                generate_hysteria2_json_config(
                    address=address,
                    port=node.port,
                    password=user_uuid,
                    sni=node.sni,
                    up_mbps=min(user.bandwidth_limit_mbps or 50, 50),
                    down_mbps=min(user.bandwidth_limit_mbps or 100, 100),
                )
            )
            outbounds[-1]["tag"] = f"hy2-{node.name}"

        elif node.protocol == NodeProtocol.TUIC_V5:
            outbounds.append(
                generate_tuic_singbox_config(
                    address=address,
                    port=node.port,
                    user_uuid=user_uuid,
                    password=user_uuid[:16],
                    sni=node.sni,
                )
            )
            outbounds[-1]["tag"] = f"tuic-{node.name}"

    config = generate_singbox_config(
        outbounds=outbounds,
        iran_bypass=sub.iran_bypass,
        gamer_mode=user.gamer_mode,
        battery_saver=user.battery_saver,
        warp_bypass=user.warp_bypass,
        split_bypass_domains=split_bypass,
        split_force_domains=split_force,
        tls_fragment_enabled=settings.TLS_FRAGMENT_ENABLED,
        tls_fragment_size=f"{settings.TLS_FRAGMENT_SIZE_MIN}-{settings.TLS_FRAGMENT_SIZE_MAX}",
        tls_fragment_sleep=f"{settings.TLS_FRAGMENT_INTERVAL_MIN_MS}-{settings.TLS_FRAGMENT_INTERVAL_MAX_MS}",
        label=sub.label,
    )

    content = json.dumps(config, indent=2, ensure_ascii=False)
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{sub.label}.json"',
            "Subscription-Userinfo": _build_userinfo_header(user),
            "Profile-Title": f"base64:{base64.b64encode(sub.label.encode()).decode()}",
            "Profile-Update-Interval": "6",
        },
    )


# ---------------------------------------------------------------------------
# Clash Meta YAML Config
# ---------------------------------------------------------------------------

@router.get("/sub/{token}/clash")
async def get_clash_config(
    token: str,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Generate Clash Meta YAML config."""
    user, sub = await _get_user_by_sub_token(token, db)
    nodes = await _get_active_nodes(db)

    if not nodes:
        raise HTTPException(status_code=503, detail="No active nodes available")

    enabled_protocols = json.loads(sub.protocols)
    split_bypass = json.loads(user.split_tunnel_bypass or "[]")
    split_force = json.loads(user.split_tunnel_force or "[]")

    proxies = []
    for node in nodes:
        if node.protocol.value not in enabled_protocols:
            continue

        user_uuid = _generate_user_uuid(user.id, node.id)
        address = node.floating_ip or node.address

        if node.protocol == NodeProtocol.VLESS_REALITY:
            proxies.append(generate_clash_vless_proxy(
                name=f"🚀 {node.name}",
                server=address,
                port=node.port,
                uuid=user_uuid,
                sni=node.sni or settings.DEFAULT_SNI,
                reality_public_key=node.reality_public_key,
                reality_short_id=node.reality_short_id,
            ))
        elif node.protocol == NodeProtocol.HYSTERIA2:
            proxies.append(generate_clash_hysteria2_proxy(
                name=f"⚡ {node.name}",
                server=address,
                port=node.port,
                password=user_uuid,
                sni=node.sni,
            ))
        elif node.protocol == NodeProtocol.TUIC_V5:
            proxies.append(generate_clash_tuic_proxy(
                name=f"🌊 {node.name}",
                server=address,
                port=node.port,
                uuid=user_uuid,
                password=user_uuid[:16],
                sni=node.sni,
            ))

    yaml_content = generate_clash_config(
        proxies=proxies,
        iran_bypass=sub.iran_bypass,
        gamer_mode=user.gamer_mode,
        split_bypass_domains=split_bypass,
        split_force_domains=split_force,
        label=sub.label,
    )

    return Response(
        content=yaml_content,
        media_type="text/yaml",
        headers={
            "Content-Disposition": f'attachment; filename="{sub.label}.yaml"',
            "Subscription-Userinfo": _build_userinfo_header(user),
            "Profile-Title": f"base64:{base64.b64encode(sub.label.encode()).decode()}",
            "Profile-Update-Interval": "6",
        },
    )


# ---------------------------------------------------------------------------
# V2Ray Base64 Links
# ---------------------------------------------------------------------------

@router.get("/sub/{token}/v2ray")
async def get_v2ray_links(
    token: str,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Generate Base64-encoded V2Ray subscription links for v2rayNG."""
    user, sub = await _get_user_by_sub_token(token, db)
    nodes = await _get_active_nodes(db)

    if not nodes:
        raise HTTPException(status_code=503, detail="No active nodes available")

    enabled_protocols = json.loads(sub.protocols)
    links = []

    for node in nodes:
        if node.protocol.value not in enabled_protocols:
            continue

        user_uuid = _generate_user_uuid(user.id, node.id)
        address = node.floating_ip or node.address

        if node.protocol == NodeProtocol.VLESS_REALITY:
            links.append(generate_vless_reality_link(
                address=address,
                port=node.port,
                user_uuid=user_uuid,
                sni=node.sni or settings.DEFAULT_SNI,
                public_key=node.reality_public_key or "",
                short_id=node.reality_short_id,
                label=f"MTGroup-{node.name}",
                tls_fragment_enabled=settings.TLS_FRAGMENT_ENABLED,
                tls_fragment_size_min=settings.TLS_FRAGMENT_SIZE_MIN,
                tls_fragment_size_max=settings.TLS_FRAGMENT_SIZE_MAX,
                tls_fragment_interval_min=settings.TLS_FRAGMENT_INTERVAL_MIN_MS,
                tls_fragment_interval_max=settings.TLS_FRAGMENT_INTERVAL_MAX_MS,
            ))

        elif node.protocol == NodeProtocol.HYSTERIA2:
            links.append(generate_hysteria2_link(
                address=address,
                port=node.port,
                password=user_uuid,
                sni=node.sni,
                label=f"MTGroup-{node.name}",
            ))

        elif node.protocol == NodeProtocol.TUIC_V5:
            links.append(generate_tuic_link(
                address=address,
                port=node.port,
                user_uuid=user_uuid,
                password=user_uuid[:16],
                sni=node.sni,
                label=f"MTGroup-{node.name}",
            ))

    content = base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")

    return Response(
        content=content,
        media_type="text/plain",
        headers={
            "Subscription-Userinfo": _build_userinfo_header(user),
            "Profile-Title": f"base64:{base64.b64encode(sub.label.encode()).decode()}",
            "Profile-Update-Interval": "6",
        },
    )


# ---------------------------------------------------------------------------
# AmneziaWG Config
# ---------------------------------------------------------------------------

@router.get("/sub/{token}/amnezia")
async def get_amnezia_config(
    token: str,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """
    Return a working AmneziaWG .conf for this subscription.

    "Working" is the whole point: the peer is allocated once and stored,
    then registered on the node before the config is handed over. Earlier
    this endpoint minted a throwaway keypair per request and told the node
    nothing, so the file it returned could never complete a handshake —
    and refetching produced a different key, invalidating whatever the
    user had already installed.
    """
    user, sub = await _get_user_by_sub_token(token, db)
    nodes = await _get_active_nodes(db)

    awg_nodes = [n for n in nodes if n.protocol == NodeProtocol.AMNEZIA_WG]
    if not awg_nodes:
        raise HTTPException(
            status_code=503,
            detail="No AmneziaWG nodes available",
        )

    node = awg_nodes[0]
    address = node.floating_ip or node.address

    # The node's WireGuard identity. NOT reality_public_key — that's an
    # x25519 key for VLESS-Reality and belongs to a different protocol
    # entirely; using it here produced configs pointing at a key the
    # WireGuard server does not hold.
    if not node.amnezia_server_public_key:
        logger.error(
            "Node %s (%s) is marked amnezia_wg but has no "
            "amnezia_server_public_key — it has not been provisioned.",
            node.id, node.name,
        )
        raise HTTPException(
            status_code=503,
            detail=(
                "AmneziaWG node is not fully provisioned yet "
                "(missing server public key)"
            ),
        )

    try:
        peer, created = await get_or_create_peer(db, subscription_id=sub.id, node=node)
    except NoAddressesAvailable:
        logger.error("Node %s (%s) has exhausted its tunnel subnet", node.id, node.name)
        raise HTTPException(
            status_code=503, detail="AmneziaWG node has no free tunnel addresses",
        ) from None

    # Register the peer on the node. Without this the client's public key is
    # unknown to the server and the tunnel cannot come up, so a failure here
    # must not be silent — but it also shouldn't lose the allocation, which
    # is why is_synced_to_node is tracked and retried on the next fetch.
    if created or not peer.is_synced_to_node:
        synced = await orchestrator.sync_node_config(
            node,
            {
                "config_type": NodeProtocol.AMNEZIA_WG.value,
                "payload": {
                    "action": "add_peer",
                    "public_key": peer.public_key,
                    "allowed_ips": f"{peer.assigned_ip}/32",
                },
            },
        )
        peer.is_synced_to_node = bool(synced)
        await db.commit()

        if not peer.is_synced_to_node:
            logger.error(
                "Could not register peer for subscription %s on node %s — "
                "returning 503 rather than a config that cannot connect.",
                sub.id, node.id,
            )
            raise HTTPException(
                status_code=503,
                detail=(
                    "Could not register your device with the VPN node. "
                    "Please try again shortly."
                ),
            )

    conf = generate_amnezia_conf(
        server_public_key=node.amnezia_server_public_key,
        server_endpoint=address,
        server_port=node.port,
        client_private_key=peer.private_key,
        client_address=f"{peer.assigned_ip}/32",
        jc=node.amnezia_jc,
        jmin=node.amnezia_jmin,
        jmax=node.amnezia_jmax,
        s1=node.amnezia_s1,
        s2=node.amnezia_s2,
        h1=node.amnezia_h1,
        h2=node.amnezia_h2,
        h3=node.amnezia_h3,
        h4=node.amnezia_h4,
    )

    return Response(
        content=conf,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="MTGroup-{node.name}.conf"',
        },
    )


# ---------------------------------------------------------------------------
# QR Code Generator
# ---------------------------------------------------------------------------

@router.get("/sub/{token}/qr")
async def get_qr_code(
    token: str,
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Generate a QR code image for the subscription URL."""
    # Validate token
    await _get_user_by_sub_token(token, db)

    sub_url = f"{settings.BASE_URL}{settings.SUBSCRIPTION_PATH_PREFIX}/{token}"

    try:
        import qrcode
        from qrcode.constants import ERROR_CORRECT_H

        qr = qrcode.QRCode(
            version=1,
            error_correction=ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(sub_url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="#00FF66", back_color="#000000")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")  # type: ignore
        buffer.seek(0)

        return StreamingResponse(
            buffer,
            media_type="image/png",
            headers={"Content-Disposition": "inline; filename=qr.png"},
        )
    except ImportError:
        # Fallback: return the URL as plain text
        return PlainTextResponse(
            content=sub_url,
            headers={"Content-Type": "text/plain"},
        )


# ---------------------------------------------------------------------------
# Raw Links (Non-encoded)
# ---------------------------------------------------------------------------

@router.get("/sub/{token}/links")
async def get_raw_links(
    token: str,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Get raw (non-base64) protocol links, one per line."""
    user, sub = await _get_user_by_sub_token(token, db)
    nodes = await _get_active_nodes(db)
    enabled_protocols = json.loads(sub.protocols)

    links = []
    for node in nodes:
        if node.protocol.value not in enabled_protocols:
            continue

        user_uuid = _generate_user_uuid(user.id, node.id)
        address = node.floating_ip or node.address

        if node.protocol == NodeProtocol.VLESS_REALITY:
            links.append(generate_vless_reality_link(
                address=address,
                port=node.port,
                user_uuid=user_uuid,
                sni=node.sni or settings.DEFAULT_SNI,
                public_key=node.reality_public_key or "",
                short_id=node.reality_short_id,
                label=f"MTGroup-{node.name}",
            ))
        elif node.protocol == NodeProtocol.HYSTERIA2:
            links.append(generate_hysteria2_link(
                address=address,
                port=node.port,
                password=user_uuid,
                sni=node.sni,
                label=f"MTGroup-{node.name}",
            ))
        elif node.protocol == NodeProtocol.TUIC_V5:
            links.append(generate_tuic_link(
                address=address,
                port=node.port,
                user_uuid=user_uuid,
                password=user_uuid[:16],
                sni=node.sni,
                label=f"MTGroup-{node.name}",
            ))

    return PlainTextResponse(content="\n".join(links))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_userinfo_header(user: User) -> str:
    """Build the Subscription-Userinfo header for client consumption."""
    parts = [
        f"upload={user.upload_bytes}",
        f"download={user.download_bytes}",
        f"total={user.data_limit_bytes}",
    ]
    if user.expire_date:
        expire_ts = int(user.expire_date.timestamp())
        parts.append(f"expire={expire_ts}")
    return "; ".join(parts)
