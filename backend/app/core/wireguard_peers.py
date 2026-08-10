"""
MTGroup VPN Ultimate — AmneziaWG Peer Provisioning
═══════════════════════════════════════════════════════════════════
Allocates and persists the client side of a WireGuard/AmneziaWG peer:
a Curve25519 keypair and a tunnel IP out of the node's subnet.

Why this exists: a WireGuard client config only works if the *server*
has been told the client's public key. The subscription endpoint used to
generate a throwaway keypair per request and discard the public half, so
the `.conf` it returned could never connect — and a second fetch produced
a different key, so even a hand-registered peer would break. Peers are
now allocated once, stored, and reused.
"""

from __future__ import annotations

import base64
import ipaddress
import logging

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models import Node, WireGuardPeer

logger = logging.getLogger("mtgroup.wireguard_peers")

# How many times to retry allocation when two requests race for the same IP.
# The (node_id, assigned_ip) unique constraint means the loser gets an
# IntegrityError rather than a duplicate; it just needs to pick again.
_ALLOCATION_ATTEMPTS = 5


def generate_keypair() -> tuple[str, str]:
    """
    Generate a real Curve25519 keypair, base64-encoded as wg expects.

    Returns ``(private_key, public_key)``. The public key is *derived*
    from the private key — an earlier implementation generated the two
    independently, which produced structurally valid but functionally
    dead keypairs.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519

    private = x25519.X25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return (
        base64.b64encode(private_bytes).decode("ascii"),
        base64.b64encode(public_bytes).decode("ascii"),
    )


def candidate_addresses(subnet: str) -> list[str]:
    """
    Usable peer addresses in `subnet`, in allocation order.

    The first usable host is reserved for the server itself (the `.1`
    convention that `install.sh` provisions), so peers start at `.2`.
    """
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts())
    return [str(h) for h in hosts[1:]]


async def _taken_addresses(session: AsyncSession, node_id: int) -> set[str]:
    result = await session.execute(
        select(WireGuardPeer.assigned_ip).where(WireGuardPeer.node_id == node_id)
    )
    return set(result.scalars().all())


class NoAddressesAvailable(RuntimeError):
    """The node's tunnel subnet is fully allocated."""


async def get_or_create_peer(
    session: AsyncSession,
    *,
    subscription_id: int,
    node: Node,
) -> tuple[WireGuardPeer, bool]:
    """
    Return this subscription's peer on `node`, creating it if absent.

    Returns ``(peer, created)``. Callers use `created` to decide whether
    the node still needs to be told about it.

    Idempotent by design: fetching a subscription config repeatedly must
    keep returning the *same* keypair, or every refetch would invalidate
    the config the user already installed.
    """
    existing = await session.execute(
        select(WireGuardPeer).where(
            WireGuardPeer.subscription_id == subscription_id,
            WireGuardPeer.node_id == node.id,
        )
    )
    peer = existing.scalar_one_or_none()
    if peer is not None:
        return peer, False

    subnet = node.amnezia_subnet or "10.8.0.0/24"
    candidates = candidate_addresses(subnet)

    for attempt in range(_ALLOCATION_ATTEMPTS):
        taken = await _taken_addresses(session, node.id)
        free = next((ip for ip in candidates if ip not in taken), None)
        if free is None:
            raise NoAddressesAvailable(
                f"node {node.id} ({node.name}) has no free addresses in {subnet}"
            )

        private_key, public_key = generate_keypair()
        peer = WireGuardPeer(
            subscription_id=subscription_id,
            node_id=node.id,
            private_key=private_key,
            public_key=public_key,
            assigned_ip=free,
            is_synced_to_node=False,
        )
        session.add(peer)
        try:
            await session.flush()
        except IntegrityError:
            # Another request took this address (or created this peer)
            # between our read and our write. The DB constraint is what
            # makes that safe; recover by re-reading and trying again.
            await session.rollback()
            recheck = await session.execute(
                select(WireGuardPeer).where(
                    WireGuardPeer.subscription_id == subscription_id,
                    WireGuardPeer.node_id == node.id,
                )
            )
            concurrent = recheck.scalar_one_or_none()
            if concurrent is not None:
                return concurrent, False
            logger.warning(
                "Address %s on node %s was taken concurrently; retrying (%d/%d)",
                free, node.id, attempt + 1, _ALLOCATION_ATTEMPTS,
            )
            continue

        logger.info(
            "Allocated WireGuard peer for subscription %s on node %s: %s",
            subscription_id, node.id, free,
        )
        return peer, True

    raise NoAddressesAvailable(
        f"could not allocate an address on node {node.id} after "
        f"{_ALLOCATION_ATTEMPTS} attempts"
    )
