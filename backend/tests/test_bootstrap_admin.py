"""The first admin comes from ADMIN_USERNAME/ADMIN_PASSWORD — once."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from backend.app.core.config import settings
from backend.app.core.security import hash_password, verify_password
from backend.app.main import _bootstrap_admin
from backend.app.models import User, UserRole, create_session_factory


@pytest.fixture
def admin_settings(monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_USERNAME", "root-admin")
    monkeypatch.setattr(settings, "ADMIN_PASSWORD", "Bootstrap-Pass-123")


async def _users(factory):
    async with factory() as s:
        return (await s.execute(select(User))).scalars().all()


async def test_creates_admin_on_empty_db(db_engine, admin_settings):
    factory = create_session_factory(db_engine)
    await _bootstrap_admin(factory)
    (user,) = await _users(factory)
    assert user.username == "root-admin" and user.role == UserRole.ADMIN and user.is_active
    assert verify_password("Bootstrap-Pass-123", user.hashed_password)


async def test_never_touches_existing_admin(db_engine, admin_settings):
    factory = create_session_factory(db_engine)
    async with factory() as s:
        s.add(User(username="boss", hashed_password=hash_password("Original-Pass-1"),
                   role=UserRole.ADMIN, is_active=True))
        await s.commit()
    await _bootstrap_admin(factory)
    (user,) = await _users(factory)
    assert user.username == "boss"
    assert verify_password("Original-Pass-1", user.hashed_password)


async def test_does_not_promote_non_admin_with_same_name(db_engine, admin_settings):
    factory = create_session_factory(db_engine)
    async with factory() as s:
        s.add(User(username="root-admin", hashed_password=hash_password("User-Pass-123"),
                   role=UserRole.USER, is_active=True))
        await s.commit()
    await _bootstrap_admin(factory)
    (user,) = await _users(factory)
    assert user.role == UserRole.USER


async def test_overlong_password_is_logged_not_raised(db_engine, admin_settings, monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_PASSWORD", "x" * 100)
    factory = create_session_factory(db_engine)
    await _bootstrap_admin(factory)
    assert await _users(factory) == []
