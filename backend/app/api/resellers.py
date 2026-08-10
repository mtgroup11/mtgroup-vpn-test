"""
MTGroup VPN Ultimate — Resellers API
═══════════════════════════════════════════════════════════════════
Endpoints for managing multi-tier agents and quota allocations.
"""

from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.auth import get_current_user, get_db
from backend.app.models import Agent, User, UserRole

router = APIRouter(prefix="/api/resellers", tags=["resellers"])


class SubAgentCreate(BaseModel):
    username: str
    password: str
    traffic_quota_mb: int


@router.post("/sub-agents", status_code=status.HTTP_201_CREATED)
async def create_sub_agent(
    request: SubAgentCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Create a sub-agent (reseller) under the current agent."""
    if current_user.role not in [UserRole.ADMIN, UserRole.RESELLER]:
        raise HTTPException(status_code=403, detail="Not enough privileges")

    # Find current agent
    agent_result = await db.execute(select(Agent).where(Agent.user_id == current_user.id))
    parent_agent = agent_result.scalar_one_or_none()

    if not parent_agent and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=404, detail="Agent profile not found")

    quota_bytes = request.traffic_quota_mb * 1024 * 1024

    # Check parent quota if not admin
    if current_user.role != UserRole.ADMIN and parent_agent:
        remaining_quota = parent_agent.traffic_quota_bytes - parent_agent.traffic_used_bytes
        if remaining_quota < quota_bytes:
            raise HTTPException(status_code=400, detail="Insufficient quota to allocate")

    # Check if username exists
    user_result = await db.execute(select(User).where(User.username == request.username))
    if user_result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already registered")

    from backend.app.core.security import hash_password
    
    # Create User for sub-agent
    new_user = User(
        username=request.username,
        hashed_password=hash_password(request.password),
        role=UserRole.RESELLER,
        is_active=True,
        data_limit_bytes=0, # Agents don't consume VPN data directly
    )
    db.add(new_user)
    await db.flush()

    # Create Agent profile
    new_agent = Agent(
        user_id=new_user.id,
        parent_agent_id=parent_agent.id if parent_agent else None,
        traffic_quota_bytes=quota_bytes,
    )
    db.add(new_agent)
    
    # Deduct from parent
    if parent_agent:
        parent_agent.traffic_used_bytes += quota_bytes
        
    await db.commit()
    
    return {"status": "success", "agent_code": new_agent.agent_code, "allocated_mb": request.traffic_quota_mb}


@router.get("/sub-agents")
async def list_sub_agents(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """List all sub-agents under the current agent."""
    if current_user.role not in [UserRole.ADMIN, UserRole.RESELLER]:
        raise HTTPException(status_code=403, detail="Not enough privileges")

    if current_user.role == UserRole.ADMIN:
        # Admin sees top-level agents
        stmt = select(Agent).where(Agent.parent_agent_id.is_(None))
    else:
        # Reseller sees their direct sub-agents
        agent_result = await db.execute(select(Agent.id).where(Agent.user_id == current_user.id))
        parent_agent_id = agent_result.scalar_one_or_none()
        if not parent_agent_id:
            raise HTTPException(status_code=404, detail="Agent profile not found")
        stmt = select(Agent).where(Agent.parent_agent_id == parent_agent_id)

    result = await db.execute(stmt)
    agents = result.scalars().all()
    
    return [
        {
            "id": a.id,
            "agent_code": a.agent_code,
            "quota_bytes": a.traffic_quota_bytes,
            "used_bytes": a.traffic_used_bytes,
            "is_active": a.is_active
        }
        for a in agents
    ]

# End of file
