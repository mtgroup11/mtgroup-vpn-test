"""
MTGroup VPN Ultimate — Authentication Endpoints
JWT-based login/refresh with rate limiting and auto-ban.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.logging_config import audit_logger
from backend.app.core.security import (
    create_access_token,
    create_refresh_token,
    login_tracker,
    rate_limiter,
    verify_access_token,
    verify_password,
    verify_refresh_token,
)
from backend.app.models import User, UserRole
from backend.app.schemas import (
    MessageResponse,
    RefreshRequest,
    TokenRequest,
    TokenResponse,
)

logger = logging.getLogger("mtgroup.api.auth")
router = APIRouter(prefix="/api/auth", tags=["Authentication"])
bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Dependency: Get DB Session (injected from main.py lifespan)
# ---------------------------------------------------------------------------

async def get_db() -> AsyncSession:
    """Placeholder — overridden at app startup via dependency_overrides."""
    raise NotImplementedError("DB session not configured")


def token_claims(user: User) -> dict:
    """Claims for a freshly issued access/refresh token pair."""
    return {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role.value,
        "tv": user.token_version,
    }


def token_is_current(payload: dict, user: User) -> bool:
    """False for tokens issued before the user's token_version was bumped
    (password, role or active-state change, or "log out everywhere")."""
    return payload.get("tv", 0) == (user.token_version or 0)


async def user_from_payload(payload: dict | None, db: AsyncSession) -> User | None:
    """The active user a verified token belongs to, or None."""
    if not payload:
        return None
    try:
        user_id = int(payload.get("sub"))
    except (TypeError, ValueError):
        return None
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None or not user.is_active or not token_is_current(payload, user):
        return None
    return user


# ---------------------------------------------------------------------------
# Dependency: Get Current User from JWT
# ---------------------------------------------------------------------------

async def get_current_user(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(bearer_scheme)
    ] = None,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract and validate the current user from the JWT bearer token."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_access_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await user_from_payload(payload, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found, inactive, or session revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Require the current user to be an admin."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user

async def require_admin_or_reseller(
    current_user: User = Depends(get_current_user),
) -> User:
    """Require the current user to be an admin or reseller."""
    if current_user.role not in (UserRole.ADMIN, UserRole.RESELLER):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or Reseller access required",
        )
    return current_user


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    body: TokenRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """
    Authenticate with username/password and receive JWT tokens.
    Rate-limited: 5 failed attempts → 24h IP ban.
    """
    client_ip = request.client.host if request.client else "unknown"

    # Check rate limit
    if not rate_limiter.is_allowed(client_ip, cost=2.0):
        audit_logger.log_rate_limit(client_ip, "/api/auth/login")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Try again later.",
        )

    # Check if IP is already blocked from too many failures
    if login_tracker.is_blocked(client_ip):
        audit_logger.log_login_attempt(
            ip=client_ip,
            username=body.username,
            success=False,
            detail="IP blocked due to excessive failures",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="IP temporarily blocked. Try again later.",
        )

    # Find user
    result = await db.execute(
        select(User).where(User.username == body.username)
    )
    user = result.scalar_one_or_none()

    if user is None or not verify_password(body.password, user.hashed_password):
        should_ban = login_tracker.record_failure(client_ip)
        audit_logger.log_login_attempt(
            ip=client_ip,
            username=body.username,
            success=False,
            detail=f"attempts={login_tracker.get_attempts(client_ip)}",
        )

        if should_ban:
            # Auto-ban at nftables level would happen here on Linux
            audit_logger.log_ban(client_ip, "failed_login", settings.BAN_DURATION_HOURS)
            logger.warning(
                "Auto-banning IP %s after %d failed login attempts",
                client_ip,
                settings.MAX_FAILED_LOGINS,
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended",
        )

    # Success — clear failure counter
    login_tracker.record_success(client_ip)
    audit_logger.log_login_attempt(
        ip=client_ip, username=body.username, success=True
    )

    # Generate tokens
    token_data = token_claims(user)
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Refresh an expired access token using a valid refresh token."""
    client_ip = request.client.host if request.client else "unknown"

    if not rate_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
        )

    payload = verify_refresh_token(body.refresh_token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user = await user_from_payload(payload, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found, inactive, or session revoked",
        )

    token_data = token_claims(user)
    new_access = create_access_token(token_data)
    new_refresh = create_refresh_token(token_data)

    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout-all", response_model=MessageResponse)
async def logout_everywhere(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Revoke every access and refresh token issued to the caller so far
    (e.g. after a token may have leaked)."""
    current_user.token_version = (current_user.token_version or 0) + 1
    await db.commit()
    audit_logger.log_admin_action(admin_username=current_user.username, action="logout_all", target=current_user.username)
    return MessageResponse(message="All sessions revoked")


@router.get("/me", response_model=MessageResponse)
async def get_me(current_user: User = Depends(get_current_user)) -> MessageResponse:
    """Return basic info about the authenticated user."""
    return MessageResponse(
        message=f"Authenticated as {current_user.username}",
        detail=f"role={current_user.role.value}, id={current_user.id}",
    )
