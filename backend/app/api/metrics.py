"""
MTGroup VPN Ultimate — Live Metrics API
═══════════════════════════════════════════════════════════════════
WebSocket endpoint streaming real-time server throughput and eBPF
drop statistics for the HTML5 Canvas Radar UI.
"""

import asyncio
import json
import logging
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
import psutil
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.auth import get_db
from backend.app.ebpf.loader import XDPLoader
from backend.app.models import Node

logger = logging.getLogger("mtgroup.api.metrics")
router = APIRouter(prefix="/api/metrics", tags=["metrics"])

# Global XDP Loader instance for stats
xdp_loader = XDPLoader(interface="eth0")

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
async def websocket_live_metrics(websocket: WebSocket):
    """
    WebSocket Endpoint: /api/metrics/live
    Connect to this endpoint to receive real-time JSON metrics for the Radar UI.
    """
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
async def get_metrics_dashboard(db: AsyncSession = Depends(get_db)):
    """
    Endpoint: /api/metrics/dashboard
    Returns durational awareness data for the Next.js frontend,
    driven by real system telemetry and eBPF kernel maps.
    """
    from datetime import datetime, timezone

    # Real per-node connection load. current_connections/health_status are
    # populated by NodeOrchestrator.check_node_health()'s health-poll loop
    # (orchestrator.py) — not fabricated here.
    result = await db.execute(select(Node).where(Node.is_active))
    nodes = [
        {
            "name": node.name,
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
        for node in result.scalars().all()
    ]

    # 1. Real eBPF Telemetry
    xdp_stats = xdp_loader.get_stats()
    ebpf_bans = xdp_stats.get("active_bans", 0) if isinstance(xdp_stats, dict) else 0
    
    ebpf_status = "Online" if not xdp_stats.get("simulated", True) else "Degraded/Offline (Simulation)"
    if xdp_stats.get("error"):
        ebpf_status = f"Error: {xdp_stats['error']}"
    
    # 2. Real System Resources
    cpu_usage = psutil.cpu_percent(interval=None)
    ram_usage = psutil.virtual_memory().percent
    
    # 3. Calculate Active Users via OS Socket Tracking
    active_users = 0
    try:
        # Safely attempt to read active TCP connections on VPN ports
        connections = psutil.net_connections(kind="tcp")
        active_users = sum(
            1 for c in connections 
            if c.status == 'ESTABLISHED' and c.laddr and c.laddr.port in (443, 8443, 8080)
        )
    except Exception as e:
        logger.warning(f"Could not read net connections for active_users: {e}")
        # Fallback if permission denied
        active_users = 0
    
    # These metrics require advanced log aggregation (e.g. vector/fluentbit), 
    # so we'll keep them as safe defaults for the API baseline.
    honeypot_triggers = 0 
    failed_handshake_rate = 0.0
    latency_ms = 45.0
    packet_loss_pct = 0.0
    handshake_success_rate = 100.0
    
    risk_score, risk_status = calculate_system_risk_score(
        ebpf_bans, honeypot_triggers, cpu_usage, ram_usage, failed_handshake_rate
    )
    
    connection_quality = calculate_connection_quality(
        latency_ms, packet_loss_pct, handshake_success_rate
    )
    
    # Trigger shield if necessary
    if risk_score > 75:
        await trigger_autonomous_shield(risk_score)
        
    return {
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
        "ebpf_status": ebpf_status,
        "active_users": active_users,
        "nodes": nodes,
    }
