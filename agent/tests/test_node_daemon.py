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
async def client():
    """
    HTTP client for the daemon app.

    Deliberately does NOT depend on an env fixture. It used to depend on
    `node_env`, which meant an amnezia test requesting `awg_env` pulled
    `node_env` in as well and the two `resolve_target` patches fought —
    the xray one won and the amnezia tests silently exercised the wrong
    target. Tests now name whichever env they need first in the signature,
    so its patches are in place before this builds the app.

    Uses aiohttp's own test utils rather than the pytest-aiohttp plugin,
    so it needs no dependency beyond aiohttp + pytest-asyncio.
    """
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


AWG_CONFIG = """\
[Interface]
PrivateKey = SERVERPRIVATEKEY=
Address = 10.8.0.1/24
ListenPort = 51820
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1234567
H2 = 2345678
H3 = 3456789
H4 = 4567890

[Peer]
PublicKey = EXISTINGPEERKEY=
AllowedIPs = 10.8.0.2/32
"""


@pytest.fixture
def awg_env(tmp_path, monkeypatch):
    """Point the daemon's amnezia target at a temp file; stub `awg set`."""
    cfg = tmp_path / "awg0.conf"
    monkeypatch.setattr(nd, "API_KEY", API_KEY)
    monkeypatch.setattr(nd, "resolve_target", lambda ct: (str(cfg), "awg-quick@awg0"))

    live_calls: list[tuple] = []

    async def _fake_apply_live(public_key, allowed_ips, remove=False):
        live_calls.append((public_key, allowed_ips, remove))
        return True

    monkeypatch.setattr(nd, "apply_peer_live", _fake_apply_live)

    restarts: list[str] = []

    async def _fake_restart(service):
        restarts.append(service)

    monkeypatch.setattr(nd, "restart_service", _fake_restart)

    watchdog_calls: list[str] = []
    monkeypatch.setattr(
        nd.watchdog_client, "arm_and_snapshot",
        lambda path: watchdog_calls.append(f"arm:{path}") or True,
    )
    monkeypatch.setattr(
        nd.watchdog_client, "disarm",
        lambda: watchdog_calls.append("disarm") or True,
    )

    return cfg, live_calls, restarts, watchdog_calls


class TestWgConfigParsing:
    def test_round_trips_without_losing_amnezia_parameters(self):
        interface, peers = nd.parse_wg_config(AWG_CONFIG)
        rendered = nd.render_wg_config(interface, peers)
        # The Jc/Jmin/H1..H4 obfuscation parameters are what make this
        # AmneziaWG rather than plain detectable WireGuard — losing them
        # silently downgrades the tunnel's censorship resistance.
        for param in ("Jc = 4", "Jmin = 40", "H1 = 1234567", "H4 = 4567890"):
            assert param in rendered
        assert "PrivateKey = SERVERPRIVATEKEY=" in rendered

    def test_separates_interface_from_peers(self):
        interface, peers = nd.parse_wg_config(AWG_CONFIG)
        assert any("[Interface]" in line for line in interface)
        assert not any("[Peer]" in line for line in interface)
        assert len(peers) == 1

    def test_handles_multiple_peers(self):
        text = AWG_CONFIG + "\n[Peer]\nPublicKey = SECOND=\nAllowedIPs = 10.8.0.3/32\n"
        _, peers = nd.parse_wg_config(text)
        assert len(peers) == 2
        assert nd.peer_public_key(peers[1]) == "SECOND="

    def test_handles_a_config_with_no_peers(self):
        interface, peers = nd.parse_wg_config("[Interface]\nPrivateKey = X=\n")
        assert peers == []
        assert interface

    def test_peer_public_key_returns_none_when_absent(self):
        assert nd.peer_public_key(["[Peer]", "AllowedIPs = 10.8.0.9/32"]) is None


class TestUpsertAndRemovePeer:
    def test_appends_a_new_peer(self):
        _, peers = nd.parse_wg_config(AWG_CONFIG)
        peers, changed = nd.upsert_peer(peers, "NEWKEY=", "10.8.0.5/32")
        assert changed is True
        assert len(peers) == 2

    def test_replaces_an_existing_peer_rather_than_duplicating(self):
        _, peers = nd.parse_wg_config(AWG_CONFIG)
        peers, changed = nd.upsert_peer(peers, "EXISTINGPEERKEY=", "10.8.0.99/32")
        assert changed is True
        assert len(peers) == 1
        assert "10.8.0.99/32" in "\n".join(peers[0])

    def test_identical_peer_is_not_a_change(self):
        _, peers = nd.parse_wg_config(AWG_CONFIG)
        peers, changed = nd.upsert_peer(peers, "EXISTINGPEERKEY=", "10.8.0.2/32")
        assert changed is False

    def test_includes_preshared_key_when_given(self):
        _, peers = nd.parse_wg_config(AWG_CONFIG)
        peers, _ = nd.upsert_peer(peers, "K=", "10.8.0.6/32", preshared_key="PSK=")
        assert "PresharedKey = PSK=" in "\n".join(peers[-1])

    def test_removes_a_peer(self):
        _, peers = nd.parse_wg_config(AWG_CONFIG)
        peers, removed = nd.remove_peer_block(peers, "EXISTINGPEERKEY=")
        assert removed == 1
        assert peers == []

    def test_removing_an_absent_peer_is_zero(self):
        _, peers = nd.parse_wg_config(AWG_CONFIG)
        _, removed = nd.remove_peer_block(peers, "NOPE=")
        assert removed == 0


class TestAddPeerAction:
    async def test_adds_peer_and_preserves_the_rest_of_the_config(self, awg_env, client):
        cfg, live_calls, restarts, watchdog_calls = awg_env
        nd.atomic_write_text(str(cfg), AWG_CONFIG)

        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "amnezia_wg",
            "payload": {"action": "add_peer", "public_key": "NEWCLIENT=", "allowed_ips": "10.8.0.7/32"},
        })
        resp = await _post(client, body, sig)

        assert resp.status == 200
        written = cfg.read_text(encoding="utf-8")
        assert "NEWCLIENT=" in written
        assert "10.8.0.7/32" in written
        # Existing peer and the Amnezia obfuscation parameters survive.
        assert "EXISTINGPEERKEY=" in written
        assert "Jc = 4" in written and "H4 = 4567890" in written
        assert "PrivateKey = SERVERPRIVATEKEY=" in written
        # Applied live rather than by restarting — a restart would drop
        # every other user's tunnel just to add one peer.
        assert live_calls == [("NEWCLIENT=", "10.8.0.7/32", False)]
        assert restarts == []
        # Watchdog armed (snapshotting the pre-change config) before the
        # write, disarmed right after — see node_daemon.py's module docstring.
        assert watchdog_calls == [f"arm:{cfg}", "disarm"]

    async def test_adding_the_same_peer_twice_is_a_noop(self, awg_env, client):
        cfg, live_calls, _, watchdog_calls = awg_env
        nd.atomic_write_text(str(cfg), AWG_CONFIG)

        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "amnezia_wg",
            "payload": {"action": "add_peer", "public_key": "EXISTINGPEERKEY=", "allowed_ips": "10.8.0.2/32"},
        })
        resp = await _post(client, body, sig)
        assert (await resp.json())["status"] == "noop"
        assert live_calls == []
        assert watchdog_calls == []  # nothing changed — no reason to arm

    async def test_requires_allowed_ips(self, awg_env, client):
        cfg, _, _, _ = awg_env
        nd.atomic_write_text(str(cfg), AWG_CONFIG)
        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "amnezia_wg",
            "payload": {"action": "add_peer", "public_key": "K="},
        })
        resp = await _post(client, body, sig)
        assert resp.status == 400
        assert cfg.read_text(encoding="utf-8") == AWG_CONFIG

    async def test_requires_public_key(self, awg_env, client):
        cfg, _, _, _ = awg_env
        nd.atomic_write_text(str(cfg), AWG_CONFIG)
        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "amnezia_wg",
            "payload": {"action": "add_peer", "allowed_ips": "10.8.0.8/32"},
        })
        resp = await _post(client, body, sig)
        assert resp.status == 400

    async def test_noop_when_interface_not_provisioned(self, awg_env, client):
        cfg, _, _, _ = awg_env  # no config written
        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "amnezia_wg",
            "payload": {"action": "add_peer", "public_key": "K=", "allowed_ips": "10.8.0.9/32"},
        })
        resp = await _post(client, body, sig)
        assert (await resp.json())["status"] == "noop"
        assert not cfg.exists()

    async def test_rejected_on_a_non_amnezia_node(self, node_env, client):
        cfg, restarts = node_env
        nd.atomic_write_config(str(cfg), _xray_config())
        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "vless",
            "payload": {"action": "add_peer", "public_key": "K=", "allowed_ips": "10.8.0.9/32"},
        })
        resp = await _post(client, body, sig)
        assert resp.status == 400
        assert restarts == []


class TestRemovePeerAction:
    async def test_removes_peer_and_keeps_the_interface(self, awg_env, client):
        cfg, live_calls, _, watchdog_calls = awg_env
        nd.atomic_write_text(str(cfg), AWG_CONFIG)

        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "amnezia_wg",
            "payload": {"action": "remove_peer", "public_key": "EXISTINGPEERKEY="},
        })
        resp = await _post(client, body, sig)

        assert (await resp.json())["removed"] == 1
        written = cfg.read_text(encoding="utf-8")
        assert "EXISTINGPEERKEY=" not in written
        assert "[Interface]" in written and "Jc = 4" in written
        assert live_calls == [("EXISTINGPEERKEY=", None, True)]
        assert watchdog_calls == [f"arm:{cfg}", "disarm"]

    async def test_removing_an_absent_peer_is_a_noop(self, awg_env, client):
        cfg, live_calls, _, watchdog_calls = awg_env
        nd.atomic_write_text(str(cfg), AWG_CONFIG)
        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "amnezia_wg",
            "payload": {"action": "remove_peer", "public_key": "GHOST="},
        })
        resp = await _post(client, body, sig)
        assert (await resp.json())["status"] == "noop"
        assert live_calls == []
        assert cfg.read_text(encoding="utf-8") == AWG_CONFIG
        assert watchdog_calls == []


class TestAmneziaSync:
    async def test_writes_rendered_conf_text(self, awg_env, client):
        cfg, _, restarts, watchdog_calls = awg_env
        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "amnezia_wg",
            "payload": {"config": AWG_CONFIG},
        })
        resp = await _post(client, body, sig)

        assert resp.status == 200
        assert cfg.read_text(encoding="utf-8") == AWG_CONFIG
        assert restarts == ["awg-quick@awg0"]
        assert watchdog_calls == [f"arm:{cfg}", "disarm"]

    async def test_refuses_a_json_payload_for_an_amnezia_node(self, awg_env, client):
        """
        Guards the mirror image of the original incident: an Xray-shaped
        JSON config written over awg0.conf would leave awg-quick unable to
        parse its own config and the interface down.
        """
        cfg, _, restarts, watchdog_calls = awg_env
        nd.atomic_write_text(str(cfg), AWG_CONFIG)
        body, sig = _signed_body({
            "_ts": int(time.time()),
            "config_type": "amnezia_wg",
            "payload": _xray_config(),
        })
        resp = await _post(client, body, sig)

        assert resp.status == 400
        assert cfg.read_text(encoding="utf-8") == AWG_CONFIG
        assert restarts == []
        assert watchdog_calls == []  # rejected before ever touching disk


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
