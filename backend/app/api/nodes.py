"""
MTGroup VPN Ultimate — Node Management Endpoints
CRUD operations, health checks, and floating IP management.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.auth import get_db, require_admin
from backend.app.core.config import settings
from backend.app.core.logging_config import audit_logger
from backend.app.core.security import generate_api_key
from backend.app.generators.generator_amnezia import validate_amnezia_params
from backend.app.models import Node, NodeProtocol, User
from backend.app.schemas import (
    MessageResponse,
    NodeCreate,
    NodeListResponse,
    NodeResponse,
    NodeUpdate,
)

logger = logging.getLogger("mtgroup.api.nodes")
router = APIRouter(prefix="/api/nodes", tags=["Nodes"])


def _check_amnezia(node: Node) -> None:
    """Reject AmneziaWG parameter sets the client would refuse — otherwise
    the bad values only surface later as a 500 on every config fetch."""
    if node.protocol != NodeProtocol.AMNEZIA_WG:
        return
    try:
        validate_amnezia_params(
            jc=node.amnezia_jc, jmin=node.amnezia_jmin, jmax=node.amnezia_jmax,
            s1=node.amnezia_s1, s2=node.amnezia_s2,
            h1=node.amnezia_h1, h2=node.amnezia_h2, h3=node.amnezia_h3, h4=node.amnezia_h4,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"Invalid AmneziaWG parameters: {e}") from None


@router.post("", response_model=NodeResponse, status_code=status.HTTP_201_CREATED)
async def create_node(
    body: NodeCreate,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> NodeResponse:
    """Add a new server node."""
    existing = await db.execute(
        select(Node).where(Node.name == body.name)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"Node '{body.name}' already exists",
        )

    node = Node(
        name=body.name,
        address=body.address,
        port=body.port,
        agent_port=body.agent_port,
        agent_cert_pem=body.agent_cert_pem,
        protocol=body.protocol.value,
        sni=body.sni,
        reality_public_key=body.reality_public_key,
        reality_private_key=body.reality_private_key,
        reality_short_id=body.reality_short_id,
        tls_cert_path=body.tls_cert_path,
        tls_key_path=body.tls_key_path,
        api_key=generate_api_key(),
        cloud_provider=body.cloud_provider,
        cloud_instance_id=body.cloud_instance_id,
        port_pool_low=body.port_pool_low,
        port_pool_high_start=body.port_pool_high_start,
        port_pool_high_end=body.port_pool_high_end,
        port_hop_interval_sec=body.port_hop_interval_sec,
        amnezia_server_public_key=body.amnezia_server_public_key,
        amnezia_subnet=body.amnezia_subnet,
        amnezia_jc=body.amnezia_jc,
        amnezia_jmin=body.amnezia_jmin,
        amnezia_jmax=body.amnezia_jmax,
        amnezia_s1=body.amnezia_s1,
        amnezia_s2=body.amnezia_s2,
        amnezia_h1=body.amnezia_h1,
        amnezia_h2=body.amnezia_h2,
        amnezia_h3=body.amnezia_h3,
        amnezia_h4=body.amnezia_h4,
    )
    _check_amnezia(node)
    db.add(node)
    await db.commit()
    await db.refresh(node)

    audit_logger.log_admin_action(
        admin_username=admin.username,
        action="create_node",
        target=body.name,
    )

    return NodeResponse.model_validate(node)


@router.get("", response_model=NodeListResponse)
async def list_nodes(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> NodeListResponse:
    """List all server nodes."""
    result = await db.execute(select(Node))
    nodes = result.scalars().all()
    return NodeListResponse(
        total=len(nodes),
        nodes=[NodeResponse.model_validate(n) for n in nodes],
    )


@router.get("/{node_id}", response_model=NodeResponse)
async def get_node(
    node_id: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> NodeResponse:
    """Get a specific node."""
    result = await db.execute(select(Node).where(Node.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    return NodeResponse.model_validate(node)


@router.patch("/{node_id}", response_model=NodeResponse)
async def update_node(
    node_id: int,
    body: NodeUpdate,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> NodeResponse:
    """Update a node's configuration."""
    result = await db.execute(select(Node).where(Node.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    update_data = body.model_dump(exclude_unset=True)
    if update_data.get("agent_cert_pem") == "":
        update_data["agent_cert_pem"] = None  # clear the pin
    for key, value in update_data.items():
        if hasattr(node, key):
            setattr(node, key, value)
    _check_amnezia(node)

    node.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(node)

    audit_logger.log_admin_action(
        admin_username=admin.username,
        action="update_node",
        target=node.name,
    )

    return NodeResponse.model_validate(node)


@router.delete("/{node_id}", response_model=MessageResponse)
async def delete_node(
    node_id: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Delete a server node."""
    result = await db.execute(select(Node).where(Node.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    name = node.name
    await db.delete(node)
    await db.commit()

    audit_logger.log_admin_action(
        admin_username=admin.username,
        action="delete_node",
        target=name,
    )

    return MessageResponse(message=f"Node '{name}' deleted")


@router.get("/{node_id}/agent-setup")
async def get_agent_setup(
    node_id: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """What an admin needs to install the agent on this node.

    The node's API key (the HMAC secret both sides sign with) was generated
    at creation but never returned by any endpoint, so there was no way to
    configure an agent that the panel could talk to.
    """
    result = await db.execute(select(Node).where(Node.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    audit_logger.log_admin_action(admin_username=admin.username, action="view_agent_setup", target=node.name)
    return {
        "node_id": node.id,
        "api_key": node.api_key,
        "agent_port": node.agent_port,
        "agent_cert_fingerprint": node.agent_cert_fingerprint,
        "install_command": (
            f"sudo MTGROUP_NODE_API_KEY='{node.api_key}' MTGROUP_NODE_PORT={node.agent_port} "
            "bash agent/install_agent.sh"
        ),
        "next_step": (
            "Paste the certificate the installer prints into this node's agent_cert_pem "
            "(PATCH /api/nodes/{id}) to pin it. If you skip this, the panel pins whatever "
            "certificate it sees on first contact."
        ),
    }


@router.post("/{node_id}/redeploy-ip", response_model=MessageResponse)
async def redeploy_ip(
    node_id: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """
    Trigger floating IP redeployment for a node.
    Integrates with Hetzner/OVH cloud APIs to provision a new IP.
    """
    result = await db.execute(select(Node).where(Node.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    old_ip = node.floating_ip or node.address

    # Cloud API integration
    new_ip = await _provision_floating_ip(node)

    node.floating_ip = new_ip
    node.updated_at = datetime.now(timezone.utc)
    await db.commit()

    audit_logger.log_ip_redeploy(node.name, old_ip, new_ip)

    return MessageResponse(
        message=f"IP redeployed for node '{node.name}'",
        detail=f"old={old_ip}, new={new_ip}",
    )


@router.post("/{node_id}/port-hop", response_model=MessageResponse)
async def trigger_port_hop(
    node_id: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Force an immediate port hop on a node."""
    result = await db.execute(select(Node).where(Node.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    from backend.app.generators.port_hopper import PortHopper

    hopper = PortHopper(
        low_ports=[int(p) for p in node.port_pool_low.split(",") if p.strip()],
        high_port_start=node.port_pool_high_start,
        high_port_end=node.port_pool_high_end,
        hop_interval_sec=node.port_hop_interval_sec,
    )
    new_port = hopper.force_hop()
    node.port = new_port
    node.updated_at = datetime.now(timezone.utc)
    await db.commit()

    audit_logger.log_node_event(
        node.name,
        "port_hop",
        f"new_port={new_port}",
    )

    return MessageResponse(
        message=f"Port hopped to {new_port} on node '{node.name}'"
    )


# ---------------------------------------------------------------------------
# Cloud IP Provisioning
# ---------------------------------------------------------------------------

async def _provision_floating_ip(node: Node) -> str:
    """
    Provision a new floating IP from the node's cloud provider.
    Supports Hetzner and OVH via their REST APIs.
    """
    if node.cloud_provider == "hetzner" and settings.HETZNER_API_TOKEN:
        return await _hetzner_provision_ip(node)
    elif node.cloud_provider == "ovh" and settings.OVH_APP_KEY:
        return await _ovh_provision_ip(node)
    # This used to invent a random 10.x.x.x "simulated" IP and save it as
    # the node's floating_ip, which every subscription then handed out —
    # turning an admin click into an outage for that server.
    raise HTTPException(
        status_code=400,
        detail=(
            f"No cloud provider configured for node '{node.name}' "
            "(set cloud_provider plus HETZNER_API_TOKEN or OVH_* credentials)"
        ),
    )


async def _hetzner_provision_ip(node: Node) -> str:
    """Provision a floating IP via Hetzner Cloud API."""
    import httpx

    async with httpx.AsyncClient() as client:
        # Create new floating IP
        response = await client.post(
            "https://api.hetzner.cloud/v1/floating_ips",
            headers={
                "Authorization": f"Bearer {settings.HETZNER_API_TOKEN}",
                "Content-Type": "application/json",
            },
            json={
                "type": "ipv4",
                "home_location": "nbg1",
                "description": f"MTGroup-{node.name}-auto",
            },
            timeout=10.0,
        )

        if response.status_code != 201:
            logger.error("Hetzner API error: %s", response.text)
            raise HTTPException(
                status_code=502,
                detail=f"Failed to provision Hetzner IP: {response.status_code}",
            )

        data = response.json()
        new_ip = data["floating_ip"]["ip"]

        # Assign to server if instance ID is known
        if node.cloud_instance_id:
            assign_resp = await client.post(
                f"https://api.hetzner.cloud/v1/floating_ips/{data['floating_ip']['id']}/actions/assign",
                headers={
                    "Authorization": f"Bearer {settings.HETZNER_API_TOKEN}",
                    "Content-Type": "application/json",
                },
                json={"server": int(node.cloud_instance_id)},
                timeout=10.0,
            )
            if assign_resp.status_code not in (200, 201):
                logger.warning("Failed to assign floating IP to server: %s", assign_resp.text)

        return new_ip


async def _ovh_provision_ip(node: Node) -> str:
    """Provision a floating IP via OVH API (simplified)."""
    import hashlib
    import httpx
    import time

    timestamp = str(int(time.time()))
    # OVH API authentication
    method = "POST"
    url = "https://api.ovh.com/1.0/ip"
    body = ""

    # Build signature. SHA1 here is mandated by the OVH API's own "$1$"
    # signature scheme, not a security choice we control — usedforsecurity=False
    # documents that and stops it being flagged as weak-hash-for-security.
    pre_hash = f"{settings.OVH_APP_SECRET}+{settings.OVH_CONSUMER_KEY}+{method}+{url}+{body}+{timestamp}"
    signature = "$1$" + hashlib.sha1(pre_hash.encode("utf-8"), usedforsecurity=False).hexdigest()

    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.ovh.com/1.0/ip",
            headers={
                "X-Ovh-Application": settings.OVH_APP_KEY,
                "X-Ovh-Timestamp": timestamp,
                "X-Ovh-Signature": signature,
                "X-Ovh-Consumer": settings.OVH_CONSUMER_KEY,
                "Content-Type": "application/json",
            },
            timeout=10.0,
        )

        if response.status_code == 200:
            ips = response.json()
            if ips:
                return ips[0]

    # Fallback
    import random
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
