"""
Token revocation via User.token_version ("tv" claim).

Before this, a JWT stayed valid until it expired no matter what happened to
the account: a demoted reseller kept admin access for up to an hour, and a
refresh token survived a password change for 7 days.
"""

from __future__ import annotations

import pytest

from backend.tests.conftest import get_admin_token


async def _login(client, username, password):
    resp = await client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _make_user(client, admin_auth, username, role="user"):
    resp = await client.post("/api/users/", json={"username": username, "password": "Original123!", "role": role},
                             headers=admin_auth)
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_password_change_revokes_existing_access_and_refresh_tokens(client):
    admin = {"Authorization": f"Bearer {await get_admin_token(client)}"}
    user = await _make_user(client, admin, "pwchange", role="admin")
    old = await _login(client, "pwchange", "Original123!")
    old_auth = {"Authorization": f"Bearer {old['access_token']}"}
    assert (await client.get("/api/auth/me", headers=old_auth)).status_code == 200

    await client.patch(f"/api/users/{user['id']}", json={"password": "Changed1234!"}, headers=admin)

    assert (await client.get("/api/auth/me", headers=old_auth)).status_code == 401
    refreshed = await client.post("/api/auth/refresh", json={"refresh_token": old["refresh_token"]})
    assert refreshed.status_code == 401
    new = await _login(client, "pwchange", "Changed1234!")
    assert (await client.get("/api/auth/me", headers={"Authorization": f"Bearer {new['access_token']}"})).status_code == 200


@pytest.mark.asyncio
async def test_demotion_takes_effect_immediately(client):
    admin = {"Authorization": f"Bearer {await get_admin_token(client)}"}
    user = await _make_user(client, admin, "demoted", role="admin")
    tok = (await _login(client, "demoted", "Original123!"))["access_token"]
    their = {"Authorization": f"Bearer {tok}"}
    assert (await client.get("/api/nodes", headers=their)).status_code == 200

    await client.patch(f"/api/users/{user['id']}", json={"role": "user"}, headers=admin)
    assert (await client.get("/api/nodes", headers=their)).status_code == 401


@pytest.mark.asyncio
async def test_unrelated_edits_do_not_log_the_user_out(client):
    admin = {"Authorization": f"Bearer {await get_admin_token(client)}"}
    user = await _make_user(client, admin, "keeper", role="admin")
    tok = (await _login(client, "keeper", "Original123!"))["access_token"]
    await client.patch(f"/api/users/{user['id']}", json={"data_limit_bytes": 10**9, "role": "admin",
                                                       "is_active": True}, headers=admin)
    assert (await client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"})).status_code == 200


@pytest.mark.asyncio
async def test_logout_all_revokes_the_callers_tokens(client):
    login = await _login(client, "admin", "TestAdmin123!")
    auth = {"Authorization": f"Bearer {login['access_token']}"}
    assert (await client.post("/api/auth/logout-all", headers=auth)).status_code == 200
    assert (await client.get("/api/auth/me", headers=auth)).status_code == 401
    assert (await client.post("/api/auth/refresh", json={"refresh_token": login["refresh_token"]})).status_code == 401


@pytest.mark.asyncio
async def test_token_with_non_numeric_subject_is_401_not_500(client):
    from backend.app.core.security import create_access_token
    tok = create_access_token({"sub": "not-a-number", "tv": 0})
    assert (await client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"})).status_code == 401
