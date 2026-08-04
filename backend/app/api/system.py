"""
MTGroup VPN Ultimate — System & Stats Endpoints
System monitoring, configuration management, and ban list.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.auth import get_db, require_admin
from backend.app.core.logging_config import audit_logger
from backend.app.models import BannedIP, Node, SystemConfig, User
from backend.app.core.crypto_quantum import hash_for_lookup
from backend.app.schemas import (
    BannedIPCreate,
    BannedIPResponse,
    MessageResponse,
    SystemConfigResponse,
    SystemConfigUpdate,
    SystemStatsResponse,
)

logger = logging.getLogger("mtgroup.api.system")
router = APIRouter(prefix="/api/system", tags=["System"])

_start_time = time.time()


@router.get("/stats", response_model=SystemStatsResponse)
async def get_system_stats(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> SystemStatsResponse:
    """Get current system resource usage and statistics."""
    # System metrics
    cpu_percent = 0.0
    mem_percent = 0.0
    mem_used_mb = 0.0
    mem_total_mb = 0.0
    disk_percent = 0.0

    try:
        import psutil

        cpu_percent = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        mem_percent = mem.percent
        mem_used_mb = mem.used / (1024 * 1024)
        mem_total_mb = mem.total / (1024 * 1024)
        disk = psutil.disk_usage("/")
        disk_percent = disk.percent
    except ImportError:
        # psutil not available — return zeros
        pass

    # Network bandwidth (simplified — would use /proc/net/dev on Linux)
    bw_up = 0.0
    bw_down = 0.0
    try:
        import psutil

        net = psutil.net_io_counters()
        bw_up = net.bytes_sent / (1024 * 1024)
        bw_down = net.bytes_recv / (1024 * 1024)
    except (ImportError, AttributeError):
        pass

    # Database counts
    total_users_result = await db.execute(select(func.count(User.id)))
    total_users = total_users_result.scalar() or 0

    active_users_result = await db.execute(
        select(func.count(User.id)).where(User.is_active)
    )
    active_users = active_users_result.scalar() or 0

    total_nodes_result = await db.execute(select(func.count(Node.id)))
    total_nodes = total_nodes_result.scalar() or 0

    active_nodes_result = await db.execute(
        select(func.count(Node.id)).where(Node.is_active)
    )
    active_nodes = active_nodes_result.scalar() or 0

    return SystemStatsResponse(
        cpu_percent=cpu_percent,
        memory_percent=mem_percent,
        memory_used_mb=round(mem_used_mb, 1),
        memory_total_mb=round(mem_total_mb, 1),
        disk_percent=disk_percent,
        bandwidth_up_mbps=round(bw_up, 2),
        bandwidth_down_mbps=round(bw_down, 2),
        total_users=total_users,
        active_users=active_users,
        total_nodes=total_nodes,
        active_nodes=active_nodes,
        uptime_seconds=round(time.time() - _start_time, 1),
    )


# ---------------------------------------------------------------------------
# System Configuration
# ---------------------------------------------------------------------------

@router.get("/config", response_model=list[SystemConfigResponse])
async def list_configs(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> list[SystemConfigResponse]:
    """List all system configuration entries."""
    result = await db.execute(select(SystemConfig))
    configs = result.scalars().all()
    responses = []
    for cfg in configs:
        try:
            parsed_value = json.loads(cfg.value)
        except (json.JSONDecodeError, TypeError):
            parsed_value = cfg.value
        responses.append(SystemConfigResponse(
            key=cfg.key,
            value=parsed_value,
            description=cfg.description,
            updated_at=cfg.updated_at,
        ))
    return responses


@router.put("/config", response_model=SystemConfigResponse)
async def upsert_config(
    body: SystemConfigUpdate,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> SystemConfigResponse:
    """Create or update a system configuration entry."""
    result = await db.execute(
        select(SystemConfig).where(SystemConfig.key == body.key)
    )
    cfg = result.scalar_one_or_none()

    value_str = json.dumps(body.value) if not isinstance(body.value, str) else body.value

    if cfg:
        cfg.value = value_str
        if body.description:
            cfg.description = body.description
        cfg.updated_at = datetime.now(timezone.utc)
    else:
        cfg = SystemConfig(
            key=body.key,
            value=value_str,
            description=body.description,
        )
        db.add(cfg)

    await db.commit()
    await db.refresh(cfg)

    audit_logger.log_admin_action(
        admin_username=admin.username,
        action="update_config",
        target=body.key,
    )

    try:
        parsed_value = json.loads(cfg.value)
    except (json.JSONDecodeError, TypeError):
        parsed_value = cfg.value

    return SystemConfigResponse(
        key=cfg.key,
        value=parsed_value,
        description=cfg.description,
        updated_at=cfg.updated_at,
    )


# ---------------------------------------------------------------------------
# Ban Management
# ---------------------------------------------------------------------------

@router.get("/bans", response_model=list[BannedIPResponse])
async def list_bans(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> list[BannedIPResponse]:
    """List all currently banned IPs."""
    result = await db.execute(select(BannedIP))
    bans = result.scalars().all()
    return [BannedIPResponse.model_validate(b) for b in bans]


@router.post("/bans", response_model=BannedIPResponse)
async def ban_ip(
    body: BannedIPCreate,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> BannedIPResponse:
    """Manually ban an IP address."""
    ip_h = hash_for_lookup(body.ip_address)
    existing = await db.execute(
        select(BannedIP).where(BannedIP.ip_hash == ip_h)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="IP already banned")

    ban = BannedIP(
        ip_address=body.ip_address,
        ip_hash=ip_h,
        reason=body.reason,
        details=body.details,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=body.duration_hours),
    )
    db.add(ban)
    await db.commit()
    await db.refresh(ban)

    audit_logger.log_ban(body.ip_address, body.reason, body.duration_hours)

    return BannedIPResponse.model_validate(ban)


@router.delete("/bans/{ip_address}", response_model=MessageResponse)
async def unban_ip(
    ip_address: str,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Remove an IP ban."""
    ip_h = hash_for_lookup(ip_address)
    result = await db.execute(
        select(BannedIP).where(BannedIP.ip_hash == ip_h)
    )
    ban = result.scalar_one_or_none()
    if not ban:
        raise HTTPException(status_code=404, detail="Ban not found")

    await db.delete(ban)
    await db.commit()

    audit_logger.log_admin_action(
        admin_username=admin.username,
        action="unban_ip",
        target=ip_address,
    )

    return MessageResponse(message=f"IP '{ip_address}' unbanned")
