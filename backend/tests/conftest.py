"""
MTGroup VPN Ultimate — Shared pytest fixtures for backend/tests/.
Extracted from test_api.py so other test files (test_api_users.py,
test_api_nodes.py, etc.) can reuse the same fresh-DB test client instead
of duplicating this setup.
"""

from __future__ import annotations

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from backend.app.core.config import settings
from backend.app.core.security import hash_password
from backend.app.main import app
from backend.app.models import (
    Base,
    Node,
    NodeProtocol,
    User,
    UserRole,
    create_db_engine,
    create_session_factory,
)

TEST_DB_URL = "sqlite+aiosqlite:///./test_mtgroup.db"


@pytest_asyncio.fixture(scope="function")
async def db_engine():
    """
    Create a fresh test database for each test.

    Builds the schema straight from `Base.metadata` rather than calling
    `init_db()` (which runs the full Alembic migration chain). Running
    every migration for every one of ~500 DB-backed tests took the suite
    from ~2.5 to ~5.5 minutes for no added signal: the two are provably
    equivalent, and `backend/tests/test_migrations.py` is what proves it
    — it fails the build if the migrations and `Base.metadata` ever
    describe different schemas, and it separately exercises the real
    `init_db()` path on fresh, legacy and already-migrated databases.

    `alembic_version` is dropped alongside the model tables. It isn't
    created here, but a previously-interrupted run can leave one behind,
    and a database stamped at head with no tables would make every
    subsequent test fail with "no such table".
    """
    engine = create_db_engine(TEST_DB_URL)
    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine):
    """Create a test database session."""
    factory = create_session_factory(db_engine)
    async with factory() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def seed_admin(db_session):
    """Create a test admin user."""
    admin = User(
        username="testadmin",
        hashed_password=hash_password("TestAdmin123!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    db_session.add(admin)
    await db_session.commit()
    await db_session.refresh(admin)
    return admin


@pytest_asyncio.fixture(scope="function")
async def seed_node(db_session):
    """Create a test node."""
    node = Node(
        name="test-node-1",
        address="10.0.0.1",
        port=443,
        protocol=NodeProtocol.VLESS_REALITY,
        sni="www.google.com",
        reality_public_key="test_public_key_base64",
        reality_short_id="abcd1234",
    )
    db_session.add(node)
    await db_session.commit()
    await db_session.refresh(node)
    return node


@pytest_asyncio.fixture(scope="function")
async def client(db_engine):
    """Create an async test client with fresh DB."""
    factory = create_session_factory(db_engine)

    async def override_get_db():
        async with factory() as session:
            yield session

    from backend.app.api.auth import get_db
    app.dependency_overrides[get_db] = override_get_db

    # RateLimitMiddleware (registered globally in main.py) shares the same
    # module-level `rate_limiter` singleton across every test in the
    # session. The ASGI test transport has no real peer IP, so every
    # request in every test collapses onto the same bucket key — without
    # resetting it here, later tests start already-throttled by earlier
    # ones and fail with 429s that have nothing to do with what they're
    # actually testing.
    from backend.app.core.security import rate_limiter
    with rate_limiter._lock:
        rate_limiter._buckets.clear()

    # Seed admin
    async with factory() as session:
        admin = User(
            username="admin",
            hashed_password=hash_password("TestAdmin123!"),
            role=UserRole.ADMIN,
            is_active=True,
        )
        session.add(admin)

        node = Node(
            name="test-node",
            address="10.0.0.1",
            port=443,
            protocol=NodeProtocol.VLESS_REALITY,
            sni="www.google.com",
            reality_public_key="test_pub_key",
            reality_short_id="abcd",
        )
        session.add(node)
        await session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-Stealth-Token": settings.STEALTH_TOKEN or "SUPER_SECRET_NOC_TOKEN_2026"},
        follow_redirects=True
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


async def get_admin_token(client: AsyncClient) -> str:
    """Helper to authenticate as admin and return the access token."""
    response = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "TestAdmin123!"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]
