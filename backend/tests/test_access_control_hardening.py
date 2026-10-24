"""
Regression tests for the access-control / secrets hardening pass.

Each test here pins down a hole that was exploitable before the fix:
reseller -> admin escalation, negative-quota refunds, the public
`.env.example` placeholders passing the production boot check, publicly
computable proxy credentials, bcrypt's 72-byte limit turning into 500s,
and `/sub/*` leaking FastAPI's JSON 404 past the stealth gate.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from backend.app.core.security import derive_proxy_uuid, hash_password, verify_password
from backend.app.models import Agent, User, UserRole, create_session_factory
from backend.tests.conftest import get_admin_token


async def _make_reseller(db_engine, username: str, quota_bytes: int = 0) -> None:
    factory = create_session_factory(db_engine)
    async with factory() as s:
        reseller = User(username=username, hashed_password=hash_password("Reseller123!"),
                        role=UserRole.RESELLER, is_active=True)
        s.add(reseller)
        await s.flush()
        s.add(Agent(user_id=reseller.id, traffic_quota_bytes=quota_bytes))
        await s.commit()


async def _token(client, username: str, password: str) -> str:
    resp = await client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


class TestResellerCannotEscalate:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("role", ["admin", "reseller"])
    async def test_reseller_cannot_create_privileged_roles(self, client, db_engine, role):
        await _make_reseller(db_engine, "res-esc")
        tok = await _token(client, "res-esc", "Reseller123!")
        resp = await client.post(
            "/api/users/",
            json={"username": f"evil-{role}", "password": "Evil12345!", "role": role},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 403
        factory = create_session_factory(db_engine)
        async with factory() as s:
            created = (await s.execute(select(User).where(User.username == f"evil-{role}"))).scalar_one_or_none()
        assert created is None

    @pytest.mark.asyncio
    async def test_reseller_can_still_create_regular_users_under_own_agent(self, client, db_engine):
        await _make_reseller(db_engine, "res-ok")
        tok = await _token(client, "res-ok", "Reseller123!")
        resp = await client.post(
            "/api/users/",
            json={"username": "customer1", "password": "Customer123!"},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 201
        assert resp.json()["role"] == "user"

    @pytest.mark.asyncio
    async def test_admin_can_still_create_admins(self, client):
        tok = await get_admin_token(client)
        resp = await client.post(
            "/api/users/",
            json={"username": "second-admin", "password": "Admin12345!", "role": "admin"},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 201
        assert resp.json()["role"] == "admin"


class TestSubAgentQuotaValidation:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("quota_mb", [-10_000_000, 0])
    async def test_non_positive_quota_is_rejected_and_parent_untouched(self, client, db_engine, quota_mb):
        await _make_reseller(db_engine, "res-quota", quota_bytes=1024 * 1024)
        tok = await _token(client, "res-quota", "Reseller123!")
        resp = await client.post(
            "/api/resellers/sub-agents",
            json={"username": "sub-x", "password": "SubAgent123!", "traffic_quota_mb": quota_mb},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 422
        factory = create_session_factory(db_engine)
        async with factory() as s:
            agent = (await s.execute(
                select(Agent).join(User, Agent.user_id == User.id).where(User.username == "res-quota")
            )).scalar_one()
        assert agent.traffic_used_bytes == 0

    @pytest.mark.asyncio
    async def test_short_password_is_rejected(self, client, db_engine):
        await _make_reseller(db_engine, "res-pw", quota_bytes=10 * 1024 * 1024)
        tok = await _token(client, "res-pw", "Reseller123!")
        resp = await client.post(
            "/api/resellers/sub-agents",
            json={"username": "sub-y", "password": "x", "traffic_quota_mb": 1},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 422


class TestProductionSecretPlaceholders:
    def _settings(self, monkeypatch, **overrides):
        from backend.app import main
        values = {
            "DEBUG": False,
            "DB_ENCRYPTION_KEY": "a" * 64,
            "ADMIN_PASSWORD": "a-real-admin-password",
            "STEALTH_TOKEN": "a-real-stealth-token-0123456789",
            "JWT_SECRET_KEY": "j" * 64,
        }
        values.update(overrides)
        for key, value in values.items():
            monkeypatch.setattr(main.settings, key, value)
        fields_set = set(main.settings.model_fields_set) | {"JWT_SECRET_KEY"}
        monkeypatch.setattr(type(main.settings), "model_fields_set", property(lambda self: fields_set))
        return main

    def test_real_values_boot(self, monkeypatch):
        self._settings(monkeypatch)._enforce_production_secrets()

    @pytest.mark.parametrize("key,placeholder", [
        ("JWT_SECRET_KEY", "CHANGE_ME_TO_A_RANDOM_64_CHAR_STRING"),
        ("ADMIN_PASSWORD", "CHANGE_ME_SECURE_PASSWORD"),
        ("STEALTH_TOKEN", "CHANGE_ME_SECURE_STEALTH_TOKEN"),
    ])
    def test_env_example_placeholders_refuse_to_boot(self, monkeypatch, key, placeholder):
        # These are the literal values in .env.example. Each is long enough
        # to pass the length checks, so only the placeholder check stops a
        # `cp .env.example .env` deployment from booting with public secrets.
        main = self._settings(monkeypatch, **{key: placeholder})
        with pytest.raises(RuntimeError, match=key):
            main._enforce_production_secrets()

    def test_env_example_file_itself_is_rejected(self, monkeypatch):
        """Guards the coupling: if .env.example's placeholders ever change,
        this fails until the boot check is updated to match."""
        from pathlib import Path
        env = {}
        for line in (Path(__file__).resolve().parents[2] / ".env.example").read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
        main = self._settings(
            monkeypatch,
            JWT_SECRET_KEY=env["JWT_SECRET_KEY"],
            ADMIN_PASSWORD=env["ADMIN_PASSWORD"],
            STEALTH_TOKEN=env["STEALTH_TOKEN"],
        )
        with pytest.raises(RuntimeError) as excinfo:
            main._enforce_production_secrets()
        for key in ("JWT_SECRET_KEY", "ADMIN_PASSWORD", "STEALTH_TOKEN"):
            assert key in str(excinfo.value)


class TestProxyCredential:
    def test_not_computable_from_public_inputs(self):
        # The old derivation: uuid5(NAMESPACE_DNS, "user_id:node_id").
        assert derive_proxy_uuid("some-secret-token", 1) != str(uuid.uuid5(uuid.NAMESPACE_DNS, "1:1"))

    def test_stable_per_token_and_node(self):
        assert derive_proxy_uuid("tok", 3) == derive_proxy_uuid("tok", 3)
        assert derive_proxy_uuid("tok", 3) != derive_proxy_uuid("tok", 4)
        assert derive_proxy_uuid("tok", 3) != derive_proxy_uuid("tok2", 3)

    def test_is_a_valid_v4_uuid(self):
        parsed = uuid.UUID(derive_proxy_uuid("tok", 1))
        assert parsed.version == 4
        assert parsed.variant == uuid.RFC_4122

    @pytest.mark.asyncio
    async def test_regenerating_subscription_rotates_the_credential(self, client):
        tok = await get_admin_token(client)
        auth = {"Authorization": f"Bearer {tok}"}
        user = (await client.post("/api/users/", json={"username": "rot", "password": "Rotate123!",
                                                         "protocols": ["vless_reality"]}, headers=auth)).json()
        before = (await client.get(f"/sub/{user['subscription_token']}/links")).text
        regenerated = (await client.post(f"/api/users/{user['id']}/regenerate-sub", headers=auth)).json()
        after = (await client.get(f"/sub/{regenerated['subscription_token']}/links")).text
        assert before.startswith("vless://") and after.startswith("vless://")
        assert before.split("@")[0] != after.split("@")[0]


class TestBcryptLimit:
    def test_overlong_login_password_is_a_clean_false_not_an_exception(self):
        assert verify_password("x" * 200, hash_password("short-password")) is False

    def test_legacy_hash_of_truncated_password_still_verifies(self):
        # bcrypt<5 silently truncated at 72 bytes when hashing; those hashes
        # must keep working when the user types the full password.
        long_pw = "p" * 100
        legacy_hash = hash_password(long_pw[:72])
        assert verify_password(long_pw, legacy_hash) is True

    @pytest.mark.asyncio
    async def test_overlong_password_on_create_is_422_not_500(self, client):
        tok = await get_admin_token(client)
        resp = await client.post(
            "/api/users/",
            json={"username": "persian-pw", "password": "رمز" * 15},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_overlong_password_on_login_is_401_not_500(self, client):
        resp = await client.post("/api/auth/login", json={"username": "admin", "password": "x" * 200})
        assert resp.status_code == 401


class TestSubscriptionStealth:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("method,path", [
        ("GET", "/sub/does-not-exist"),
        ("GET", "/sub/does-not-exist/singbox"),
        ("GET", "/sub/x/no-such-route"),
        ("POST", "/sub/does-not-exist"),
    ])
    async def test_unknown_token_or_route_looks_like_nginx(self, client, method, path):
        resp = await client.request(method, path, headers={"X-Stealth-Token": ""})
        assert resp.status_code == 404
        assert resp.headers["content-type"].startswith("text/html")
        assert resp.headers.get("server") == "nginx"
        assert "detail" not in resp.text

    @pytest.mark.asyncio
    async def test_api_404s_behind_the_gate_keep_json(self, client):
        tok = await get_admin_token(client)
        resp = await client.get("/api/users/999999", headers={"Authorization": f"Bearer {tok}"})
        assert resp.status_code == 404
        assert resp.json()["detail"] == "User not found"


@pytest.mark.asyncio
async def test_regenerate_subscription_keeps_iran_bypass_off(client, db_engine):
    from backend.app.models import Subscription
    tok = await get_admin_token(client)
    auth = {"Authorization": f"Bearer {tok}"}
    user = (await client.post("/api/users/", json={"username": "nobypass", "password": "NoBypass123!",
                                                     "iran_bypass": False}, headers=auth)).json()
    await client.post(f"/api/users/{user['id']}/regenerate-sub", headers=auth)
    factory = create_session_factory(db_engine)
    async with factory() as s:
        active = (await s.execute(select(Subscription).where(
            Subscription.user_id == user["id"], Subscription.is_active.is_(True)))).scalar_one()
    assert active.iran_bypass is False
