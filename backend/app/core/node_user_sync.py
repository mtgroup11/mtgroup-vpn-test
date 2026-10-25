"""
MTGroup VPN Ultimate — Node user provisioning

Keeps every VLESS-Reality node's Xray config — and every Hysteria2/TUIC
node's sing-box config — in step with the panel's users.

Nothing did this before. Subscriptions handed out per-user credentials, but
no code path ever told a node which credentials were valid — the server
config builder (`ProxyManager.build_vless_reality_config`) was only ever
called from its own tests. A link worked only if someone had hand-edited the
node, and nothing on a node ever stopped working when a user expired, ran
out of quota or was deleted.

AmneziaWG nodes are reconciled surgically instead (their config is not
rendered here): a peer whose subscription stopped being eligible is
removed from the node with `remove_peer` but kept in the database, and is
re-added with `add_peer` — same key, so the user's installed config works
again — once the subscription is eligible again. Without this, expired and
over-quota users kept their AmneziaWG tunnels indefinitely.

How it works for Xray: for each active VLESS-Reality node that has its
Reality private key on file, render the complete server config with one client per
*eligible* subscription (active subscription, active user, not expired, not
over quota) and push it as a full `sync` — but only when it differs from the
last config that node accepted. A loop does this every
NODE_USER_SYNC_INTERVAL_SEC; `request_sync()` wakes it early after any user
change so new users work within seconds.

Hysteria2/TUIC nodes get a full sing-box server config the same way
(`build_singbox_server_config`), once they have a `tls_domain`: those
protocols do plain TLS, so the node needs a real certificate for a real
domain, which install_agent.sh obtains.

It owns the node's Xray/sing-box config outright, which would overwrite a hand-tuned
one, so it only runs when NODE_USER_SYNC_ENABLED is set.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, or_, select

from backend.app.core.proxy_manager import BLOCKED_DESTINATION_CIDRS, ProxyManager
from backend.app.core.security import derive_proxy_uuid
from backend.app.models import Node, NodeProtocol, Subscription, User, WireGuardPeer

logger = logging.getLogger("mtgroup.node_user_sync")

# After a wake-up, wait this long so a burst of user edits (bulk import, a
# reseller creating ten users) becomes one push — each push restarts Xray.
DEBOUNCE_SECONDS = 3.0


async def eligible_subscription_tokens(session) -> list[str]:
    """Tokens of every subscription whose holder may connect right now."""
    return [token for _, token in await eligible_subscriptions(session)]


async def eligible_subscriptions(session) -> list[tuple[int, str]]:
    """(id, token) of every subscription whose holder may connect right now."""
    now = datetime.now(timezone.utc)
    stmt = (
        select(Subscription.id, Subscription.token)
        .join(User, User.id == Subscription.user_id)
        .where(
            Subscription.is_active.is_(True),
            User.is_active.is_(True),
            or_(User.expire_date.is_(None), User.expire_date > now),
            or_(User.data_limit_bytes == 0, User.data_used_bytes < User.data_limit_bytes),
            or_(
                User.periodic_data_limit_bytes == 0,
                and_(User.periodic_data_limit_bytes > 0,
                     User.current_period_usage_bytes < User.periodic_data_limit_bytes),
            ),
        )
        .order_by(Subscription.id)
    )
    return [(row[0], row[1]) for row in (await session.execute(stmt)).all()]


def build_node_config(node: Node, tokens: list[str]) -> dict[str, Any]:
    """The full Xray server config for `node` with these subscriptions."""
    clients = []
    for token in tokens:
        cred = derive_proxy_uuid(token, node.id)
        # email == id: Xray keys per-user stats on email, and accounting's
        # _ingest_xray_traffic maps that key back through derive_proxy_uuid.
        clients.append({"uuid": cred, "email": cred})
    # Not www.microsoft.com: as a Reality cover it rejected every client in
    # a real Xray 25.3 test ("REALITY: processed invalid connection").
    sni = node.sni or "www.samsung.com"
    return ProxyManager().build_vless_reality_config(
        port=node.port,
        uuid=clients[0]["uuid"] if clients else "",
        sni_dest=f"{sni}:443",
        server_names=[sni],
        private_key=node.reality_private_key,
        clients=clients,
        short_ids=[node.reality_short_id] if node.reality_short_id else None,
    )


# Where install_agent.sh's Let's Encrypt deploy hook copies the node's
# certificate (fixed paths, so a renewal needs no config change).
PUBLIC_TLS_CERT = "/etc/sing-box/mtgroup-tls/fullchain.pem"
PUBLIC_TLS_KEY = "/etc/sing-box/mtgroup-tls/privkey.pem"

SINGBOX_PROTOCOLS = (NodeProtocol.HYSTERIA2, NodeProtocol.TUIC_V5)


def build_singbox_server_config(node: Node, tokens: list[str]) -> dict[str, Any]:
    """The full sing-box server config for a Hysteria2 or TUIC node.

    Credentials must match what subscriptions hand out for this node:
    Hysteria2 password = derive_proxy_uuid(token, node.id); TUIC uuid = that
    value and password = its first 16 characters.
    """
    tls = {
        "enabled": True,
        "server_name": node.tls_domain,
        "alpn": ["h3"],
        "certificate_path": node.tls_cert_path or PUBLIC_TLS_CERT,
        "key_path": node.tls_key_path or PUBLIC_TLS_KEY,
    }
    creds = [derive_proxy_uuid(token, node.id) for token in tokens]
    if node.protocol == NodeProtocol.HYSTERIA2:
        inbound = {
            "type": "hysteria2", "tag": "hy2-in", "listen": "::", "listen_port": node.port,
            "users": [{"name": c, "password": c} for c in creds],
            "tls": tls,
        }
    else:
        inbound = {
            "type": "tuic", "tag": "tuic-in", "listen": "::", "listen_port": node.port,
            "users": [{"name": c, "uuid": c, "password": c[:16]} for c in creds],
            "congestion_control": "bbr",
            "tls": tls,
        }
    return {
        "log": {"level": "warn"},
        "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [{"ip_cidr": list(BLOCKED_DESTINATION_CIDRS), "action": "reject"}],
            "final": "direct",
        },
    }


def _digest(config: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


class NodeUserSync:
    def __init__(self, db_session_factory, orchestrator, interval_sec: float = 60.0):
        self._db_session_factory = db_session_factory
        self._orchestrator = orchestrator
        self._interval = interval_sec
        self._wake = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._is_running = False
        # node.id -> digest of the last config that node accepted
        self._pushed: dict[int, str] = {}

    def request_sync(self) -> None:
        """Ask for a sync soon (debounced). Safe to call from request handlers."""
        self._wake.set()

    async def sync_once(self) -> dict[int, bool]:
        """Push to every node whose desired config changed. Returns
        {node_id: accepted} for the nodes it attempted."""
        async with self._db_session_factory() as session:
            nodes = list((await session.execute(
                select(Node).where(
                    Node.is_active.is_(True),
                    Node.protocol.in_((NodeProtocol.VLESS_REALITY, *SINGBOX_PROTOCOLS)),
                )
            )).scalars().all())
            eligible = await eligible_subscriptions(session)
        tokens = [token for _, token in eligible]

        results: dict[int, bool] = {}
        for node in nodes:
            if node.protocol in SINGBOX_PROTOCOLS:
                if not node.tls_domain:
                    logger.warning(
                        "Node %s (%s) is %s but has no tls_domain; its users are not being "
                        "provisioned.", node.id, node.name, node.protocol.value,
                    )
                    continue
                config = build_singbox_server_config(node, tokens)
                # The agent picks the sing-box config path/unit from this label.
                config_type = f"singbox-{node.protocol.value}"
            elif not node.reality_private_key:
                logger.warning(
                    "Node %s (%s) has no reality_private_key on file; can't render its "
                    "server config, so its users are not being provisioned.", node.id, node.name,
                )
                continue
            else:
                config = build_node_config(node, tokens)
                config_type = node.protocol.value
            digest = _digest(config)
            if self._pushed.get(node.id) == digest:
                continue
            ok = await self._orchestrator.send_command(
                node, {"config_type": config_type, "payload": config},
            )
            results[node.id] = ok
            if ok:
                self._pushed[node.id] = digest
                logger.info("Provisioned %d user(s) on node %s (%s)", len(tokens), node.id, node.name)

        await self._sync_amnezia({sub_id for sub_id, _ in eligible})
        return results

    async def _sync_amnezia(self, eligible_ids: set[int]) -> tuple[int, int]:
        """Add/remove AmneziaWG peers so each node carries exactly the
        eligible subscriptions' peers. Returns (added, removed)."""
        added = removed = 0
        async with self._db_session_factory() as session:
            rows = (await session.execute(
                select(WireGuardPeer, Node)
                .join(Node, Node.id == WireGuardPeer.node_id)
                .where(Node.is_active.is_(True), Node.protocol == NodeProtocol.AMNEZIA_WG)
            )).all()
            for peer, node in rows:
                should_exist = peer.subscription_id in eligible_ids
                if should_exist == peer.is_synced_to_node:
                    continue
                if should_exist:
                    payload = {"action": "add_peer", "public_key": peer.public_key,
                               "allowed_ips": f"{peer.assigned_ip}/32"}
                else:
                    payload = {"action": "remove_peer", "public_key": peer.public_key}
                ok = await self._orchestrator.send_command(
                    node, {"config_type": NodeProtocol.AMNEZIA_WG.value, "payload": payload},
                )
                if not ok:
                    continue  # retried next cycle
                peer.is_synced_to_node = should_exist
                if should_exist:
                    added += 1
                else:
                    removed += 1
            await session.commit()
        if added or removed:
            logger.info("AmneziaWG reconcile: %d peer(s) added, %d removed", added, removed)
        return added, removed

    async def _loop(self) -> None:
        while self._is_running:
            try:
                await self.sync_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Node user sync cycle failed; retrying next cycle.")
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=self._interval)
                await asyncio.sleep(DEBOUNCE_SECONDS)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()

    async def start(self) -> None:
        if self._is_running:
            return
        self._is_running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


# Set by main.py's lifespan when NODE_USER_SYNC_ENABLED; None otherwise.
user_sync: NodeUserSync | None = None


def request_user_sync() -> None:
    """Called after anything that changes who may connect. No-op when the
    feature is off."""
    if user_sync is not None:
        user_sync.request_sync()
