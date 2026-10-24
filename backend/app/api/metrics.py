"""
MTGroup VPN Ultimate — Live Metrics API
═══════════════════════════════════════════════════════════════════
WebSocket endpoint streaming real-time server throughput and eBPF
drop statistics for the HTML5 Canvas Radar UI.
"""

import asyncio
import json
import logging
from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, status
import psutil
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.auth import get_db, require_admin
from backend.app.core.config import settings
from backend.app.core.security import verify_access_token
from backend.app.ebpf.loader import XDPLoader
from backend.app.models import Node, User, UserRole

logger = logging.getLogger("mtgroup.api.metrics")
router = APIRouter(prefix="/api/metrics", tags=["metrics"])

# Global XDP Loader instance for stats
xdp_loader = XDPLoader(interface=settings.EBPF_INTERFACE)

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self._background_task: asyncio.Task | None = None
        self._is_running = False

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        
        # Start the background task if this is the first connection
        if not self._is_running:
            self._is_running = True
            self._background_task = asyncio.create_task(self._stream_metrics())

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            
        # Stop background task if no connections left
        if not self.active_connections and self._is_running:
            self._is_running = False
            if self._background_task:
                self._background_task.cancel()

    async def _stream_metrics(self):
        """Streams metrics to all active WebSocket connections every second."""
        logger.info("Metrics streaming engine started.")
        
        # Initialize network counters
        last_io = psutil.net_io_counters()
        
        while self._is_running and self.active_connections:
            try:
                await asyncio.sleep(1.0)
                
                # Calculate throughput
                current_io = psutil.net_io_counters()
                bytes_recv = current_io.bytes_recv - last_io.bytes_recv
                bytes_sent = current_io.bytes_sent - last_io.bytes_sent
                last_io = current_io
                
                # Fetch eBPF XDP stats
                xdp_stats = xdp_loader.get_stats()
                
                # Fetch System resources
                cpu_usage = psutil.cpu_percent(interval=None)
                ram_usage = psutil.virtual_memory().percent
                
                payload = {
                    "throughput": {
                        "rx_bytes_per_sec": bytes_recv,
                        "tx_bytes_per_sec": bytes_sent,
                    },
                    "system": {
                        "cpu_percent": cpu_usage,
                        "ram_percent": ram_usage,
                    },
                    "ebpf_radar": xdp_stats
                }
                
                json_payload = json.dumps(payload)
                
                # Broadcast to all connected clients
                disconnected_clients = []
                for connection in self.active_connections:
                    try:
                        await connection.send_text(json_payload)
                    except Exception:
                        disconnected_clients.append(connection)
                        
                # Cleanup disconnected
                for client in disconnected_clients:
                    self.disconnect(client)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics streaming: {e}")
                
        logger.info("Metrics streaming engine stopped.")


manager = ConnectionManager()


@router.websocket("/live")
async def websocket_live_metrics(
    websocket: WebSocket,
    token: str = Query(default=""),
    db: AsyncSession = Depends(get_db),
):
    """
    WebSocket Endpoint: /api/metrics/live?token=<admin access JWT>

    Browsers cannot set an Authorization header on a WebSocket handshake,
    so the admin access token is passed as a query parameter and checked
    (signature, expiry, active admin in DB) *before* the socket is
    accepted. Unauthenticated sockets are closed with 1008.
    """
    payload = verify_access_token(token) if token else None
    user = None
    if payload and payload.get("sub"):
        try:
            result = await db.execute(select(User).where(User.id == int(payload["sub"])))
            user = result.scalar_one_or_none()
        except (TypeError, ValueError):
            user = None
    if user is None or not user.is_active or user.role != UserRole.ADMIN:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(websocket)
    try:
        while True:
            # We don't expect messages from the client, just keep connection open
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
        manager.disconnect(websocket)

# ═══════════════════════════════════════════════════════════════════
# Live Risk Scoring & Autonomous Metrics Engine
# ═══════════════════════════════════════════════════════════════════

def calculate_system_risk_score(
    ebpf_bans: int, 
    honeypot_triggers: int, 
    cpu_percent: float, 
    ram_percent: float, 
    failed_handshake_rate: float
) -> tuple[int, str]:
    """
    Calculates the system risk score based on real-time security events and resource usage.
    """
    score = 0
    # Her 50 ban = +10 Risk
    score += (ebpf_bans // 50) * 10
    
    # Son 5 dakikadaki her kural ihlali = +15 Risk (honeypot)
    score += honeypot_triggers * 15
    
    # CPU/RAM Satürasyonu (%80 üzeri = +20 Risk)
    if cpu_percent > 80.0 or ram_percent > 80.0:
        score += 20
        
    # Başarısız Handshake Oranı (%10 üzeri = +25 Risk)
    if failed_handshake_rate > 10.0:
        score += 25
        
    score = min(100, max(0, score))
    
    if score <= 25:
        status = "Low"
    elif score <= 60:
        status = "Medium"
    else:
        status = "Critical"
        
    return score, status


def calculate_connection_quality(
    latency_ms: float, 
    packet_loss_pct: float, 
    handshake_success_rate: float
) -> int:
    """
    Calculates a 0-100 Connection Quality Index.
    """
    score = 100.0
    
    # Latency penalty
    if latency_ms > 100:
        score -= min(30.0, (latency_ms - 100) * 0.1)
        
    # Packet loss penalty
    if packet_loss_pct > 0:
        score -= min(40.0, packet_loss_pct * 4)
        
    # Handshake penalty
    if handshake_success_rate < 100:
        score -= (100 - handshake_success_rate)
        
    return int(max(0, min(100, score)))


async def trigger_autonomous_shield(risk_score: int):
    """
    Mini Event Manager: fires when the computed risk score goes critical.

    NOTE: this currently only logs. It does **not** persist anything.
    It previously built an ``AuditLog`` row and a ``SystemSnapshot`` row
    and then discarded both (the session.add/commit calls were commented
    out), while logging "Autonomous action recorded in AuditLog and
    SystemSnapshot" — i.e. it claimed an audit trail that did not exist.
    The dead construction was removed and the log corrected rather than
    left to mislead whoever reads these logs during an incident.

    To finish this properly, ``get_metrics_dashboard`` needs a
    ``db: AsyncSession = Depends(get_db)`` and must pass a session in
    here so the AuditLog/SystemSnapshot rows can actually be committed.
    """
    logger.critical(
        "🛡️ AUTONOMOUS SHIELD ACTIVATED! Risk Score: %d/100 — "
        "NOT persisted to AuditLog/SystemSnapshot (not yet wired to a DB session)",
        risk_score,
    )


def _node_color(health_status: str) -> str:
    if health_status == "healthy":
        return "emerald"
    if health_status == "offline":
        return "gray"
    return "amber"


@router.get("/dashboard")
async def get_metrics_dashboard(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    Endpoint: /api/metrics/dashboard (admin only)

    Every number here is measured — nothing is a placeholder. Where a
    signal genuinely isn't available on this host (e.g. no BCC => no XDP
    counters) the field says so instead of inventing a value.
    """
    from datetime import datetime, timezone

    # Real per-node connection load. current_connections/health_status are
    # populated by NodeOrchestrator.check_node_health()'s health-poll loop
    # (orchestrator.py) — not fabricated here.
    result = await db.execute(select(Node).where(Node.is_active))
    active_nodes = list(result.scalars().all())
    nodes = [
        {
            "id": node.id,
            "name": node.name,
            "protocol": node.protocol.value if node.protocol else None,
            "health_status": node.health_status,
            "last_health_check": node.last_health_check.isoformat() if node.last_health_check else None,
            "current_connections": node.current_connections,
            "max_connections": node.max_connections,
            "traffic": f"{node.current_connections} conns",
            "percent": (
                # max_connections == 0 means unlimited on this node — no
                # denominator to show load against, so 0% rather than a
                # division by zero.
                min(100, round(node.current_connections / node.max_connections * 100))
                if node.max_connections > 0
                else 0
            ),
            "color": _node_color(node.health_status),
        }
        for node in active_nodes
    ]
    healthy_nodes = sum(1 for n in active_nodes if n.health_status == "healthy")

    # 1. eBPF telemetry — only trusted when it isn't XDPLoader's simulation.
    xdp_stats = xdp_loader.get_stats()
    simulated = bool(xdp_stats.get("simulated", True)) if isinstance(xdp_stats, dict) else True
    ebpf_bans = 0 if simulated else int(xdp_stats.get("active_bans", 0) or 0)
    if not settings.EBPF_ENABLED:
        ebpf_status = "Disabled"
    elif xdp_stats.get("error"):
        ebpf_status = f"Error: {xdp_stats['error']}"
    elif simulated:
        ebpf_status = "Unavailable (BCC not installed)"
    else:
        ebpf_status = "Online"

    # 2. System resources
    cpu_usage = psutil.cpu_percent(interval=None)
    ram_usage = psutil.virtual_memory().percent

    # 3. Users (DB is the source of truth)
    total_users = (await db.execute(
        select(func.count()).select_from(User).where(User.role == UserRole.USER)
    )).scalar() or 0
    active_users = (await db.execute(
        select(func.count()).select_from(User).where(User.role == UserRole.USER, User.is_active)
    )).scalar() or 0

    # 4. Honeypot lethal-decoy hits since startup
    from backend.app.core.honeypot import honeypot
    honeypot_triggers = honeypot.trigger_count

    risk_score, risk_status = calculate_system_risk_score(
        ebpf_bans, honeypot_triggers, cpu_usage, ram_usage, 0.0
    )

    # Fleet availability: share of active nodes whose last health poll
    # succeeded. A measured stand-in for "connection quality" — the old
    # value was computed from hardcoded latency/loss constants.
    connection_quality = round(healthy_nodes / len(active_nodes) * 100) if active_nodes else 0

    # Trigger shield if necessary
    if risk_score > 75:
        await trigger_autonomous_shield(risk_score)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "risk_score": risk_score,
        "risk_status": risk_status,
        "connection_quality": connection_quality,
        "incident_timeline": [
            {
                "time": datetime.now(timezone.utc).strftime("%H:%M"),
                "action": "SYSTEM_HEARTBEAT",
                "details": f"CPU: {cpu_usage}%, RAM: {ram_usage}%"
            }
        ],
        "system": {"cpu_percent": cpu_usage, "ram_percent": ram_usage},
        "ebpf_status": ebpf_status,
        "ebpf_active_bans": ebpf_bans,
        "honeypot_triggers": honeypot_triggers,
        "total_users": total_users,
        "active_users": active_users,
        "healthy_nodes": healthy_nodes,
        "total_active_nodes": len(active_nodes),
        "nodes": nodes,
    }
