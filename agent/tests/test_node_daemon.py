"""
MTGroup VPN Ultimate — Node Daemon Command Dispatch Tests

The regression these exist for: the daemon used to ignore `action`
entirely and write whatever `payload` arrived straight over the node's
config.json before restarting the service — so a two-key
`{"action": "drop_user", ...}` command replaced the node's entire
configuration and took every user on it offline.

The load-bearing assertions here are the ones proving the on-disk config
is NOT clobbered by non-config payloads.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

import agent.node_daemon as nd


API_KEY = "test-node-api-key"


def _signed_body(payload_dict: dict) -> tuple[bytes, str]:
    body = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(API_KEY.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return body, sig


def _xray_config(port: int = 443, users: list[str] | None = None) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "port": port,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": u, "email": f"{u}@mtgroup"} for u in (users or ["alice", "bob"])]
                },
            }
        ],
        "outbounds": [{"protocol": "freedom"}],
    }


def _singbox_config(port: int = 443, users: list[str] | None = None) -> dict:
    return {
        "inbounds": [
            {
                "type": "vless",
                "listen_port": port,
                "users": [{"uuid": u, "name": u} for u in (users or ["alice", "bob"])],
            }
        ],
        "outbounds": [{"type": "direct"}],
    }


@pytest.fixture
def node_env(tmp_path, monkeypatch):
    """Point the daemon at a temp config file and stub out systemctl."""
    cfg = tmp_path / "config.json"
    monkeypatch.setattr(nd, "API_KEY", API_KEY)
    monkeypatch.setattr(nd, "resolve_target", lambda ct: (str(cfg), "xray"))

    restarts: list[str] = []

    async def _fake_restart(service):
        restarts.append(service)

    monkeypatch.setattr(nd, "restart_service", _fake_restart)
    return cfg, restarts


async def _post(client, body: bytes, sig: str):
    return await client.post("/api/v1/sync", data=body, headers={"X-MTGroup-Signature": sig})


@pytest_asyncio.fixture
async def client(node_env):
    # aiohttp's own test utils rather than the pytest-aiohttp plugin, so
    # this needs no extra dependency beyond aiohttp + pytest-asyncio.
    server = TestServer(nd.create_app())
    async with TestClient(server) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Pure config-manipulation helpers
# ---------------------------------------------------------------------------

class TestLooksLikeFullConfig:
    def test_accepts_xray_config(self):
        assert nd.looks_like_full_config(_xray_config()) is True

    def test_accepts_singbox_config(self):
        assert nd.looks_like_full_config(_singbox_config()) is True

    def test_rejects_drop_user_command(self):
        assert nd.looks_like_full_config({"action": "drop_user", "user_uuid": "alice"}) is False

    def test_rejects_update_port_command(self):
        assert nd.looks_like_full_config({"action": "update_port", "new_port": 8443}) is False

    def test_rejects_empty_and_non_dict(self):
        assert nd.looks_like_full_config({}) is False
        assert nd.looks_like_full_config([]) is False
        assert nd.looks_like_full_config("inbounds") is False


class TestDropUserFromConfig:
    def test_removes_matching_xray_client(self):
        cfg = _xray_config(users=["alice", "bob"])
        assert nd.drop_user_from_config(cfg, "alice") == 1
        remaining = [c["id"] for c in cfg["inbounds"][0]["settings"]["clients"]]
        assert remaining == ["bob"]

    def test_removes_matching_singbox_user(self):
        cfg = _singbox_config(users=["alice", "bob"])
        assert nd.drop_user_from_config(cfg, "bob") == 1
        assert [u["uuid"] for u in cfg["inbounds"][0]["users"]] == ["alice"]

    def test_matches_on_email_not_just_id(self):
        cfg = _xray_config(users=["alice"])
        assert nd.drop_user_from_config(cfg, "alice@mtgroup") == 1

    def test_unknown_user_removes_nothing(self):
        cfg = _xray_config(users=["alice"])
        assert nd.drop_user_from_config(cfg, "nobody") == 0
        assert len(cfg["inbounds"][0]["settings"]["clients"]) == 1

    def test_tolerates_config_without_inbounds(self):
        assert nd.drop_user_from_config({"outbounds": []}, "alice") == 0


class TestSetPortInConfig:
    def test_updates_xray_port(self):
        cfg = _xray_config(port=443)
        assert nd.set_port_in_config(cfg, 8443) == 1
        assert cfg["inbounds"][0]["port"] == 8443

    def test_updates_singbox_listen_port(self):
        cfg = _singbox_config(port=443)
        assert nd.set_port_in_config(cfg, 8443) == 1
        assert cfg["inbounds"][0]["listen_port"] == 8443

    def test_no_change_when_already_on_target_port(self):
        cfg = _xray_config(port=8443)
        assert nd.set_port_in_config(cfg, 8443) == 0


class TestAtomicWriteConfig:
    def test_writes_readable_json(self, tmp_path):
        path = tmp_path / "sub" / "config.json"
        nd.atomic_write_config(str(path), {"inbounds": []})
        assert json.loads(path.read_text(encoding="utf-8")) == {"inbounds": []}

    def test_leaves_no_temp_files_behind(self, tmp_path):
        path = tmp_path / "config.json"
        nd.atomic_write_config(str(path), {"inbounds": []})
        assert [p.name for p in tmp_path.iterdir()] == ["config.json"]

    def test_original_survives_a_failed_write(self, tmp_path, monkeypatch):
        path = tmp_path / "config.json"
        nd.atomic_write_config(str(path), _xray_config(port=443))

        def _boom(*a, **kw):
            raise OSError("disk full")

        monkeypatch.setattr(nd.json, "dump", _boom)
        with pytest.raises(OSError):
            nd.atomic_write_config(str(path), {"inbounds": ["new"]})

        # The good config must still be intact and parseable.
        assert json.loads(path.read_text(encoding="utf-8"))["inbounds"][0]["port"] == 443
        assert [p.name for p in tmp_path.iterdir()] == ["config.json"]


# ---------------------------------------------------------------------------
# HTTP dispatch — the actual regression surface
# ---------------------------------------------------------------------------

class TestSyncAction:
    async def test_full_config_is_written_and_service_restarted(self, node_env, client):
        cfg, restarts = node_env
        body, sig = _signed_body({"_ts": int(time.time()), "config_type": "vless", "payload": _xray_config()})
        resp = await _post(client, body, sig)

        assert resp.status == 200
        assert (await resp.json())["status"] == "synced"
        assert json.loads(cfg.read_text(encoding="utf-8"))["inbounds"][0]["port"] == 443
        assert restarts == ["xray"]

    async def test_non_config_payload_is_refused_and_file_untouched(self, node_env, client):
        """THE regression: a command blob must never overwrite the config."""
        cfg, restarts = node_env
        original = _xray_config(port=443, users=["alice"])
        nd.atomic_write_config(str(cfg), original)

        # Explicit sync action with a payload that is not a config — this is
        # the shape that used to overwrite config.json wholesale.
        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "vless",
            "action": "sync",
            "payload": {"totally": "not a config"},
        })
        resp = await _post(client, body, sig)

        assert resp.status == 400
        assert json.loads(cfg.read_text(encoding="utf-8")) == original
        assert restarts == []


class TestDropUserAction:
    async def test_removes_user_without_destroying_config(self, node_env, client):
        cfg, restarts = node_env
        nd.atomic_write_config(str(cfg), _xray_config(port=443, users=["alice", "bob"]))

        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "vless",
            "payload": {"action": "drop_user", "user_uuid": "alice"},
        })
        resp = await _post(client, body, sig)

        assert resp.status == 200
        assert (await resp.json())["removed"] == 1

        written = json.loads(cfg.read_text(encoding="utf-8"))
        # bob survives, and so does the rest of the config
        assert [c["id"] for c in written["inbounds"][0]["settings"]["clients"]] == ["bob"]
        assert written["inbounds"][0]["port"] == 443
        assert written["outbounds"] == [{"protocol": "freedom"}]
        assert restarts == ["xray"]

    async def test_unknown_user_is_a_noop_with_no_restart(self, node_env, client):
        cfg, restarts = node_env
        original = _xray_config(users=["alice"])
        nd.atomic_write_config(str(cfg), original)

        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "vless",
            "payload": {"action": "drop_user", "user_uuid": "ghost"},
        })
        resp = await _post(client, body, sig)

        assert (await resp.json())["status"] == "noop"
        assert json.loads(cfg.read_text(encoding="utf-8")) == original
        assert restarts == []  # must not churn the service for nothing

    async def test_missing_identifier_is_rejected(self, node_env, client):
        cfg, restarts = node_env
        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "vless",
            "payload": {"action": "drop_user"},
        })
        resp = await _post(client, body, sig)
        assert resp.status == 400
        assert restarts == []

    async def test_noop_when_no_config_on_disk(self, node_env, client):
        cfg, restarts = node_env
        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "vless",
            "payload": {"action": "drop_user", "user_uuid": "alice"},
        })
        resp = await _post(client, body, sig)
        assert (await resp.json())["status"] == "noop"
        assert not cfg.exists()  # must not create a bogus config
        assert restarts == []


class TestUpdatePortAction:
    async def test_repoints_inbounds_without_destroying_config(self, node_env, client):
        cfg, restarts = node_env
        nd.atomic_write_config(str(cfg), _xray_config(port=443, users=["alice"]))

        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "vless",
            "payload": {"action": "update_port", "new_port": 8443},
        })
        resp = await _post(client, body, sig)

        assert resp.status == 200
        written = json.loads(cfg.read_text(encoding="utf-8"))
        assert written["inbounds"][0]["port"] == 8443
        # users and outbounds survive the port change
        assert [c["id"] for c in written["inbounds"][0]["settings"]["clients"]] == ["alice"]
        assert written["outbounds"] == [{"protocol": "freedom"}]
        assert restarts == ["xray"]

    @pytest.mark.parametrize("bad_port", ["not-a-number", None, 0, 70000, -1])
    async def test_invalid_port_is_rejected(self, node_env, client, bad_port):
        cfg, restarts = node_env
        original = _xray_config(port=443)
        nd.atomic_write_config(str(cfg), original)

        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "vless",
            "payload": {"action": "update_port", "new_port": bad_port},
        })
        resp = await _post(client, body, sig)

        assert resp.status == 400
        assert json.loads(cfg.read_text(encoding="utf-8")) == original
        assert restarts == []

    async def test_same_port_is_a_noop(self, node_env, client):
        cfg, restarts = node_env
        nd.atomic_write_config(str(cfg), _xray_config(port=8443))

        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "vless",
            "payload": {"action": "update_port", "new_port": 8443},
        })
        resp = await _post(client, body, sig)
        assert (await resp.json())["status"] == "noop"
        assert restarts == []


class TestUnknownAndMalformedCommands:
    async def test_unknown_action_is_rejected_and_config_untouched(self, node_env, client):
        cfg, restarts = node_env
        original = _xray_config()
        nd.atomic_write_config(str(cfg), original)

        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "vless",
            "payload": {"action": "rm_rf_everything"},
        })
        resp = await _post(client, body, sig)

        assert resp.status == 400
        assert json.loads(cfg.read_text(encoding="utf-8")) == original
        assert restarts == []

    async def test_non_dict_payload_is_rejected(self, node_env, client):
        cfg, restarts = node_env
        body, sig = _signed_body({"_ts": int(time.time()), "config_type": "vless", "payload": "oops"})
        resp = await _post(client, body, sig)
        assert resp.status == 400
        assert restarts == []

    async def test_bad_signature_is_rejected_before_any_dispatch(self, node_env, client):
        cfg, restarts = node_env
        original = _xray_config()
        nd.atomic_write_config(str(cfg), original)

        body, _ = _signed_body({
            "_ts": int(time.time()),
            "config_type": "vless",
            "payload": {"action": "drop_user", "user_uuid": "alice"},
        })
        resp = await _post(client, body, "deadbeef")

        assert resp.status == 401
        assert json.loads(cfg.read_text(encoding="utf-8")) == original
        assert restarts == []

    async def test_stale_timestamp_is_rejected(self, node_env, client):
        cfg, restarts = node_env
        body, sig = _signed_body({
            "_ts": int(time.time()) - 120,  # outside the ±30s replay window
            "config_type": "vless",
            "payload": _xray_config(),
        })
        resp = await _post(client, body, sig)
        assert resp.status == 401
        assert restarts == []
