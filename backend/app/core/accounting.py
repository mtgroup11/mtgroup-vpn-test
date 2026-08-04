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

    def __init__(self, db_session_factory: Callable[[], AsyncSession]):
        self._db_session_factory = db_session_factory
        self._is_running = False
        self._worker_task: asyncio.Task | None = None
        self._traffic_buffer: dict[int, int] = {}
        self._buffer_lock = asyncio.Lock()

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
                    await session.execute(stmt, params)

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
            # Optional: push current_buffer back to self._traffic_buffer on failure
            async with self._buffer_lock:
                for uid, delta in current_buffer.items():
                    self._traffic_buffer[uid] = self._traffic_buffer.get(uid, 0) + delta

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
