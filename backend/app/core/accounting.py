"""
MTGroup VPN Ultimate — Async Traffic Accounting & Quota Engine
═══════════════════════════════════════════════════════════════════
Background worker that periodically checks user bandwidth limits
and instantly suspends users who exceed their quotas.
"""

import asyncio
import logging
from typing import Callable
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, bindparam, or_

from backend.app.models import User
from backend.app.orchestrator import orchestrator

logger = logging.getLogger("mtgroup.accounting")


class TrafficAccountingEngine:
    """
    Background worker that runs every 10 seconds.
    Fetches real-time bandwidth usage and manages quota limits.
    """

    # Bounds the retry buffer. If the DB is unreachable, `_process_accounting`
    # pushes the un-committed deltas back into `_traffic_buffer` so they aren't
    # lost — but with no cap that grows without limit for as long as the
    # outage lasts, in a worker that is meant to run forever. Same failure
    # mode the rate/login/handshake trackers were bounded for in
    # `core/security.py`; this buffer was missed at the time.
    MAX_BUFFER_ENTRIES: int = 50_000

    def __init__(self, db_session_factory: Callable[[], AsyncSession], dry_run: bool = True):
        self._db_session_factory = db_session_factory
        self._is_running = False
        self._worker_task: asyncio.Task | None = None
        self._traffic_buffer: dict[int, int] = {}
        self._buffer_lock = asyncio.Lock()
        # Safe-by-default: this engine has never run in production (see
        # CLAUDE.md), so its first real cycle is also the first time
        # anyone's quota is ever enforced. In dry-run mode, usage counters
        # (data_used_bytes/current_period_usage_bytes) still update
        # normally — that's just metering, useful regardless — but nobody
        # actually gets suspended or dropped from nodes; over-quota users
        # and agents are logged instead. Flip to False only once the
        # existing usage data has been sanity-checked (CLAUDE.md has the
        # query for this).
        self.dry_run = dry_run
        # Last-seen CUMULATIVE byte counter per (node_id, identifier), used
        # by ingest_node_traffic() to compute deltas from the cumulative
        # counters nodes report. See _consume_delta().
        self._last_node_counters: dict[tuple[int, str], int] = {}

    async def start(self):
        if self._is_running:
            return
        self._is_running = True
        self._worker_task = asyncio.create_task(self._accounting_loop())
        logger.info("Traffic Accounting Engine background worker started.")

    async def stop(self):
        self._is_running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("Traffic Accounting Engine background worker stopped.")

    async def ingest_traffic(self, user_id: int, bytes_delta: int):
        """
        Public API for nodes or gRPC streams to push live traffic data.
        Ingests data asynchronously into the RAM buffer without blocking.
        """
        if bytes_delta <= 0:
            return
        async with self._buffer_lock:
            self._traffic_buffer[user_id] = self._traffic_buffer.get(user_id, 0) + bytes_delta

    async def ingest_node_traffic(self, node, traffic: dict) -> None:
        """
        Translates a node's health-check traffic snapshot (cumulative
        counters as reported by the node — see agent/node_daemon.py's
        get_amnezia_peer_traffic()/get_xray_user_traffic(), surfaced via
        NodeOrchestrator.check_node_health()) into per-user deltas and
        feeds them into ingest_traffic().

        Never raises — this is best-effort telemetry processing, not a
        request that should ever fail its caller (typically fired via
        asyncio.create_task from a health check). A snapshot with neither
        key is a no-op.
        """
        try:
            amnezia = traffic.get("amnezia_peer_traffic")
            if amnezia:
                await self._ingest_amnezia_traffic(node, amnezia)

            xray = traffic.get("xray_user_traffic")
            if xray:
                await self._ingest_xray_traffic(node, xray)
        except Exception as e:
            logger.error("Error ingesting traffic snapshot from node %s: %s", node.id, e)

    def _consume_delta(self, node_id: int, identifier: str, cumulative_bytes: int) -> int:
        """
        Turns a cumulative counter into a delta since the last call for
        this (node, identifier) pair.

        A `cumulative_bytes` lower than the last-seen value means the
        counter reset — the node or its VPN service restarted, so the
        counter started over from zero — and the new value itself IS the
        delta (traffic since the reset), not `new - old`, which would be
        negative and silently dropped by ingest_traffic() (it no-ops on
        bytes_delta <= 0).
        """
        key = (node_id, identifier)
        last = self._last_node_counters.get(key, 0)
        self._last_node_counters[key] = cumulative_bytes
        return cumulative_bytes if cumulative_bytes < last else cumulative_bytes - last

    async def _ingest_amnezia_traffic(self, node, peer_traffic: dict[str, dict[str, int]]) -> None:
        """Maps each peer's public key to its subscription's user_id via a direct DB join — WireGuardPeer already stores this relationship."""
        from sqlalchemy import select

        from backend.app.models import Subscription, WireGuardPeer

        async with self._db_session_factory() as session:
            result = await session.execute(
                select(WireGuardPeer.public_key, Subscription.user_id)
                .join(Subscription, Subscription.id == WireGuardPeer.subscription_id)
                .where(WireGuardPeer.node_id == node.id)
            )
            peer_to_user = dict(result.all())

        for public_key, counters in peer_traffic.items():
            user_id = peer_to_user.get(public_key)
            if user_id is None:
                # Reported by the node but not (or no longer) registered to
                # any subscription on this node — nothing to bill it to.
                continue
            total = int(counters.get("rx_bytes", 0)) + int(counters.get("tx_bytes", 0))
            delta = self._consume_delta(node.id, f"awg:{public_key}", total)
            await self.ingest_traffic(user_id, delta)

    async def _ingest_xray_traffic(self, node, user_traffic: dict[str, int]) -> None:
        """
        Reverse-maps Xray's `email` stat key back to a user_id.

        No email->user_id table exists, so this recomputes the same
        deterministic per-(user, node) UUID subscriptions.py already uses
        for VLESS client IDs (`_generate_user_uuid`) against every active
        user and matches strings. O(active users) per node per health
        check — acceptable at the 60s polling cadence this runs at, would
        need revisiting at very large user counts.
        """
        from sqlalchemy import select

        from backend.app.api.subscriptions import _generate_user_uuid
        from backend.app.models import User

        async with self._db_session_factory() as session:
            result = await session.execute(select(User.id).where(User.is_active.is_(True)))
            active_user_ids = [row[0] for row in result.all()]

        email_to_user = {
            _generate_user_uuid(user_id, node.id): user_id
            for user_id in active_user_ids
        }

        for email, total_bytes in user_traffic.items():
            user_id = email_to_user.get(email)
            if user_id is None:
                continue
            delta = self._consume_delta(node.id, f"xray:{email}", int(total_bytes))
            await self.ingest_traffic(user_id, delta)

    async def _fetch_live_traffic_data(self) -> dict[int, int]:
        """
        Simulates fetching live traffic if pull-based is needed.
        Normally, data should be pushed via `ingest_traffic`.
        """
        return {}

    async def _process_accounting(self):
        """Main accounting cycle: updates DB in bulk and enforces limits."""
        async with self._buffer_lock:
            if not self._traffic_buffer:
                return
            # Swap the buffer for an empty one instantly
            current_buffer = self._traffic_buffer
            self._traffic_buffer = {}

        try:
            async with self._db_session_factory() as session:
                # 1. Bulk Update using bindparam for atomic arithmetic
                stmt = (
                    update(User)
                    .where(User.id == bindparam("b_id"))
                    .values(
                        data_used_bytes=User.data_used_bytes + bindparam("b_delta"),
                        current_period_usage_bytes=User.current_period_usage_bytes + bindparam("b_delta")
                    )
                )
                params = [{"b_id": uid, "b_delta": delta} for uid, delta in current_buffer.items()]

                if params:
                    # Executed via the underlying Core connection rather
                    # than session.execute(): going through the ORM
                    # Session here triggers SQLAlchemy's "ORM Bulk UPDATE
                    # by Primary Key" auto-detection (WHERE pk ==
                    # bindparam(), executed with a list of param dicts),
                    # which then demands the param dict key match the
                    # mapped column name ("b_id" vs "id") and separately
                    # refuses to run without opting out of ORM-session
                    # sync. Both failure modes were silently swallowed by
                    # the except-block below, meaning traffic accounting
                    # and quota suspension never actually executed. A
                    # plain Core executemany has neither problem.
                    conn = await session.connection()
                    await conn.execute(stmt, params)

                # 2. Check for suspended users (who exceeded quota)
                user_ids = list(current_buffer.keys())
                
                over_quota_stmt = select(User).where(
                    User.is_active,
                    User.id.in_(user_ids),
                    or_(
                        (User.data_limit_bytes > 0) & (User.data_used_bytes >= User.data_limit_bytes),
                        (User.periodic_data_limit_bytes > 0) & (User.current_period_usage_bytes >= User.periodic_data_limit_bytes)
                    )
                )
                
                result = await session.execute(over_quota_stmt)
                suspended_users = result.scalars().all()

                for user in suspended_users:
                    if self.dry_run:
                        logger.warning(
                            "[DRY RUN] User %s (ID: %s) exceeded quota — would suspend "
                            "and drop from nodes, but dry_run=True so no action taken.",
                            user.username, user.id,
                        )
                        continue
                    logger.warning(
                        f"User {user.username} (ID: {user.id}) exceeded quota. Suspending."
                    )
                    user.is_active = False
                    # Trigger orchestrator to drop user from nodes
                    asyncio.create_task(self._drop_user_from_nodes(user))

                # Commit user quota updates
                await session.commit()

                # 3. Check for Reseller/Agent quotas
                from backend.app.models import Agent
                agent_stmt = select(Agent).where(Agent.is_active.is_(True), Agent.traffic_used_bytes >= Agent.traffic_quota_bytes)
                over_quota_agents = (await session.execute(agent_stmt)).scalars().all()

                for agent in over_quota_agents:
                    if self.dry_run:
                        logger.warning(
                            "[DRY RUN] Agent %s exceeded quota — would suspend agent and "
                            "all sub-users, but dry_run=True so no action taken.",
                            agent.agent_code,
                        )
                        continue
                    logger.warning(f"Agent {agent.agent_code} exceeded quota. Suspending agent and all sub-users.")
                    agent.is_active = False

                    # Fetch all users associated directly or indirectly with this agent
                    users_stmt = select(User).where(User.agent_id == agent.id, User.is_active.is_(True))
                    agent_users = (await session.execute(users_stmt)).scalars().all()

                    for user in agent_users:
                        user.is_active = False
                        asyncio.create_task(self._drop_user_from_nodes(user))

                await session.commit()

        except Exception as e:
            logger.error(f"Error in traffic accounting cycle: {e}")
            # Push the un-committed deltas back so a transient DB failure
            # doesn't silently lose billable traffic — but bounded, so a
            # sustained outage can't grow this dict without limit.
            async with self._buffer_lock:
                for uid, delta in current_buffer.items():
                    self._traffic_buffer[uid] = self._traffic_buffer.get(uid, 0) + delta

                overflow = len(self._traffic_buffer) - self.MAX_BUFFER_ENTRIES
                if overflow > 0:
                    # Drop the oldest entries (dicts preserve insertion order),
                    # keeping the most recent traffic. Losing some accounting
                    # data is the lesser evil versus unbounded growth in a
                    # long-running worker.
                    for uid in list(self._traffic_buffer)[:overflow]:
                        del self._traffic_buffer[uid]
                    logger.error(
                        "Traffic accounting retry buffer exceeded %d entries — "
                        "dropped %d oldest users' pending deltas. Traffic for "
                        "those users is under-counted for this window.",
                        self.MAX_BUFFER_ENTRIES, overflow,
                    )

    async def _drop_user_from_nodes(self, user: User):
        """
        Pushes a command via orchestrator to drop the user's connection immediately.
        """
        from backend.app.models import Node
        
        try:
            async with self._db_session_factory() as session:
                # Fetch all active nodes to push the update
                result = await session.execute(select(Node).where(Node.is_active))
                active_nodes = result.scalars().all()
                
                # We need to construct a "delete_user" or "sync" payload 
                # (Assumes the Node Daemon supports a partial update or we sync full config without this user)
                drop_payload = {
                    "action": "drop_user",
                    "user_uuid": user.username, # Or whatever identifier the node uses
                }
                
                for node in active_nodes:
                    # Depending on Node Daemon implementation, you might hit a different endpoint
                    # or send a full sync. For now, we simulate a sync request with updated payload.
                    await orchestrator.sync_node_config(node, {
                        "config_type": node.protocol.value,
                        "payload": drop_payload
                    })
        except Exception as e:
            logger.error(f"Failed to push drop_user command for {user.username}: {e}")

    async def _accounting_loop(self):
        """Loop running every 10 seconds."""
        while self._is_running:
            try:
                await self._process_accounting()
                await asyncio.sleep(10.0)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Unexpected error in accounting loop: {e}")
                await asyncio.sleep(5.0)

# The engine will be instantiated in main.py lifespan
