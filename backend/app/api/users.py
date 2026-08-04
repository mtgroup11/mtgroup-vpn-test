"""
MTGroup VPN Ultimate — User Management Endpoints
Full CRUD with quota enforcement and subscription token management.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.auth import get_db, require_admin, require_admin_or_reseller
from backend.app.core.config import settings
from backend.app.core.logging_config import audit_logger
from backend.app.core.security import generate_subscription_token, hash_password
from backend.app.models import Subscription, User
from backend.app.schemas import (
    MessageResponse,
    UserCreate,
    UserListResponse,
    UserResponse,
    UserUpdate,
)

logger = logging.getLogger("mtgroup.api.users")
router = APIRouter(prefix="/api/users", tags=["Users"])


def _user_to_response(user: User, sub_token: Optional[str] = None) -> UserResponse:
    """Convert a User ORM instance to a UserResponse schema."""
    sub_url = None
    if sub_token:
        sub_url = f"{settings.BASE_URL}{settings.SUBSCRIPTION_PATH_PREFIX}/{sub_token}"

    return UserResponse(
        id=user.id,
        username=user.username,
        role=user.role.value,
        is_active=user.is_active,
        data_limit_bytes=user.data_limit_bytes,
        data_used_bytes=user.data_used_bytes,
        upload_bytes=user.upload_bytes,
        download_bytes=user.download_bytes,
        bandwidth_limit_mbps=user.bandwidth_limit_mbps,
        expire_date=user.expire_date,
        telegram_chat_id=user.telegram_chat_id,
        gamer_mode=user.gamer_mode,
        battery_saver=user.battery_saver,
        warp_bypass=user.warp_bypass,
        split_tunnel_bypass=user.split_tunnel_bypass or "[]",
        split_tunnel_force=user.split_tunnel_force or "[]",
        subscription_token=sub_token,
        subscription_url=sub_url,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    current_user: User = Depends(require_admin_or_reseller),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Create a new user with subscription token."""
    # Check for duplicate username
    existing = await db.execute(
        select(User).where(User.username == body.username)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{body.username}' already exists",
        )

    # Calculate expiration
    expire_date = None
    if body.expire_days:
        expire_date = datetime.now(timezone.utc) + timedelta(days=body.expire_days)

    from backend.app.models import Agent
    agent_id = None
    if current_user.role == "reseller":
        agent_res = await db.execute(select(Agent).where(Agent.user_id == current_user.id))
        agent = agent_res.scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=403, detail="Reseller agent profile not found")
        agent_id = agent.id

    # Create User
    user = User(
        username=body.username,
        hashed_password=hash_password(body.password),
        role=body.role.value,
        data_limit_bytes=body.data_limit_bytes,
        bandwidth_limit_mbps=body.bandwidth_limit_mbps,
        expire_date=expire_date,
        telegram_chat_id=body.telegram_chat_id,
        gamer_mode=body.gamer_mode,
        battery_saver=body.battery_saver,
        warp_bypass=body.warp_bypass,
        split_tunnel_bypass=json.dumps(body.split_tunnel_bypass or []),
        split_tunnel_force=json.dumps(body.split_tunnel_force or []),
        agent_id=agent_id,
    )
    db.add(user)
    await db.flush()

    # Create subscription
    sub = Subscription(
        user_id=user.id,
        token=generate_subscription_token(),
        protocols=json.dumps(body.protocols),
        iran_bypass=body.iran_bypass,
    )
    db.add(sub)
    await db.commit()
    await db.refresh(user)

    audit_logger.log_admin_action(
        admin_username=current_user.username,
        action="create_user",
        target=body.username,
    )

    return _user_to_response(user, sub.token)


@router.get("/", response_model=UserListResponse)
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: str | None = None,
    is_active: Optional[bool] = None,
    current_user: User = Depends(require_admin_or_reseller),
    db: AsyncSession = Depends(get_db),
) -> UserListResponse:
    """
    Retrieve a paginated list of users.
    Resellers can only see their own users.
    """
    from backend.app.models import Agent

    base_query = select(User)
    
    if current_user.role == "reseller":
        # Find the agent id for this reseller
        agent_res = await db.execute(select(Agent).where(Agent.user_id == current_user.id))
        agent = agent_res.scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=403, detail="Reseller agent profile not found")
        base_query = base_query.where(User.agent_id == agent.id)

    if search:
        base_query = base_query.where(User.username.ilike(f"%{search}%"))
    if is_active is not None:
        base_query = base_query.where(User.is_active == is_active)

    # Count total
    count_query = select(func.count()).select_from(base_query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Paginate
    base_query = base_query.offset(skip).limit(limit)
    result = await db.execute(base_query)
    users = result.scalars().all()

    # Get subscription tokens
    user_responses = []
    for user in users:
        sub_result = await db.execute(
            select(Subscription.token)
            .where(Subscription.user_id == user.id, Subscription.is_active)
            .limit(1)
        )
        sub_token = sub_result.scalar_one_or_none()
        user_responses.append(_user_to_response(user, sub_token))

    return UserListResponse(
        total=total,
        page=(skip // limit) + 1 if limit > 0 else 1,
        per_page=limit,
        users=user_responses,
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Get a specific user by ID."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    sub_result = await db.execute(
        select(Subscription.token)
        .where(Subscription.user_id == user.id, Subscription.is_active)
        .limit(1)
    )
    sub_token = sub_result.scalar_one_or_none()

    return _user_to_response(user, sub_token)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    body: UserUpdate,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Update an existing user."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = body.model_dump(exclude_unset=True)

    if "password" in update_data:
        user.hashed_password = hash_password(update_data.pop("password"))

    if "expire_days" in update_data:
        days = update_data.pop("expire_days")
        if days:
            user.expire_date = datetime.now(timezone.utc) + timedelta(days=days)
        else:
            user.expire_date = None

    if "protocols" in update_data:
        protocols = update_data.pop("protocols")
        sub_result = await db.execute(
            select(Subscription)
            .where(Subscription.user_id == user.id, Subscription.is_active)
            .limit(1)
        )
        sub = sub_result.scalar_one_or_none()
        if sub:
            sub.protocols = json.dumps(protocols)

    if "iran_bypass" in update_data:
        iran_bypass = update_data.pop("iran_bypass")
        sub_result = await db.execute(
            select(Subscription)
            .where(Subscription.user_id == user.id, Subscription.is_active)
            .limit(1)
        )
        sub = sub_result.scalar_one_or_none()
        if sub:
            sub.iran_bypass = iran_bypass

    for key, value in update_data.items():
        if value is not None:
            if key in ("split_tunnel_bypass", "split_tunnel_force"):
                setattr(user, key, json.dumps(value))
            else:
                setattr(user, key, value)

    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)

    sub_result = await db.execute(
        select(Subscription.token)
        .where(Subscription.user_id == user.id, Subscription.is_active)
        .limit(1)
    )
    sub_token = sub_result.scalar_one_or_none()

    audit_logger.log_admin_action(
        admin_username=admin.username,
        action="update_user",
        target=user.username,
    )

    return _user_to_response(user, sub_token)


@router.delete("/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Delete a user and all their subscriptions."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    username = user.username
    await db.delete(user)
    await db.commit()

    audit_logger.log_admin_action(
        admin_username=admin.username,
        action="delete_user",
        target=username,
    )

    return MessageResponse(message=f"User '{username}' deleted successfully")


@router.post("/{user_id}/reset-traffic", response_model=UserResponse)
async def reset_user_traffic(
    user_id: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Reset traffic counters for a user."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.data_used_bytes = 0
    user.upload_bytes = 0
    user.download_bytes = 0
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)

    sub_result = await db.execute(
        select(Subscription.token)
        .where(Subscription.user_id == user.id, Subscription.is_active)
        .limit(1)
    )
    sub_token = sub_result.scalar_one_or_none()

    audit_logger.log_admin_action(
        admin_username=admin.username,
        action="reset_traffic",
        target=user.username,
    )

    return _user_to_response(user, sub_token)


@router.post("/{user_id}/regenerate-sub", response_model=UserResponse)
async def regenerate_subscription(
    user_id: int,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Regenerate the subscription token for a user."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Deactivate old subscriptions
    old_subs = await db.execute(
        select(Subscription).where(
            Subscription.user_id == user.id,
            Subscription.is_active,
        )
    )
    for sub in old_subs.scalars().all():
        sub.is_active = False

    # Create new subscription
    new_sub = Subscription(
        user_id=user.id,
        token=generate_subscription_token(),
        protocols=old_subs.scalars().first().protocols if old_subs else json.dumps(settings.default_protocol_list),
    )
    db.add(new_sub)
    await db.commit()
    await db.refresh(user)

    audit_logger.log_admin_action(
        admin_username=admin.username,
        action="regenerate_subscription",
        target=user.username,
    )

    return _user_to_response(user, new_sub.token)
