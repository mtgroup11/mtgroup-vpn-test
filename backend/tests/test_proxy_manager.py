"""
MTGroup VPN Ultimate — Proxy Manager Test Suite
Tests backend/app/core/proxy_manager.py's REALITY keypair generation,
Xray config building, and config deployment (with file I/O, the watchdog
snapshot, and the privileged helper all mocked out).
"""

from __future__ import annotations

import base64
import json

import pytest

from backend.app.core.privileged_helper import HelperResponse, PrivilegedHelperError
from backend.app.core.proxy_manager import XRAY_API_PORT, ProxyManager


@pytest.fixture
def manager():
    return ProxyManager()


class TestGenerateRealityKeypair:
    def test_returns_valid_base64url_keys_of_expected_length(self, manager):
        keys = manager.generate_reality_keypair()
        assert set(keys.keys()) == {"privateKey", "publicKey"}
        for value in keys.values():
            # X25519 keys are 32 raw bytes; base64url without padding.
            padded = value + "=" * (-len(value) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            assert len(decoded) == 32
            assert "=" not in value  # padding stripped, matches Xray's own format

    def test_generates_a_different_keypair_each_call(self, manager):
        first = manager.generate_reality_keypair()
        second = manager.generate_reality_keypair()
        assert first != second


def _vless_inbound(config):
    return next(ib for ib in config["inbounds"] if ib["protocol"] == "vless")


class TestBuildVlessRealityConfig:
    def test_embeds_port_uuid_and_generated_keys(self, manager):
        config = manager.build_vless_reality_config(
            port=8443, uuid="test-uuid-1234", sni_dest="cdn.example.com:443",
            server_names=["cdn.example.com"],
        )
        inbound = _vless_inbound(config)
        assert inbound["port"] == 8443
        assert inbound["protocol"] == "vless"
        assert inbound["settings"]["clients"][0]["id"] == "test-uuid-1234"
        assert inbound["streamSettings"]["realitySettings"]["dest"] == "cdn.example.com:443"
        assert inbound["streamSettings"]["realitySettings"]["serverNames"] == ["cdn.example.com"]
        # Private key must be present and non-empty — this is what makes
        # the config actually usable, not just structurally valid.
        assert inbound["streamSettings"]["realitySettings"]["privateKey"]

    def test_defaults_server_names_when_not_provided(self, manager):
        config = manager.build_vless_reality_config(port=443, uuid="u")
        reality = _vless_inbound(config)["streamSettings"]["realitySettings"]
        assert reality["serverNames"] == ["www.microsoft.com"]

    def test_output_is_json_serialisable(self, manager):
        config = manager.build_vless_reality_config(port=443, uuid="u")
        json.dumps(config)  # must not raise

    def test_client_is_tagged_with_email_for_per_user_stats(self, manager):
        """
        Xray's per-user stats are keyed by the client's `email` field
        (`user>>>{email}>>>traffic>>>...`) — without it, StatsService has
        no per-user breakdown at all, only inbound-level aggregates.
        """
        config = manager.build_vless_reality_config(port=443, uuid="the-uuid")
        assert _vless_inbound(config)["settings"]["clients"][0]["email"] == "the-uuid"

    def test_enables_stats_service_on_a_loopback_only_api_inbound(self, manager):
        config = manager.build_vless_reality_config(port=443, uuid="u")
        assert config["api"]["services"] == ["StatsService"]
        assert "stats" in config
        api_inbound = next(ib for ib in config["inbounds"] if ib.get("tag") == "api")
        assert api_inbound["listen"] == "127.0.0.1"
        assert api_inbound["port"] == XRAY_API_PORT
        assert api_inbound["protocol"] == "dokodemo-door"

    def test_enables_per_user_and_per_inbound_stats_policy(self, manager):
        config = manager.build_vless_reality_config(port=443, uuid="u")
        assert config["policy"]["levels"]["0"]["statsUserUplink"] is True
        assert config["policy"]["levels"]["0"]["statsUserDownlink"] is True

    def test_routes_api_inbound_traffic_to_the_api_outbound(self, manager):
        config = manager.build_vless_reality_config(port=443, uuid="u")
        rule = config["routing"]["rules"][0]
        assert rule["inboundTag"] == ["api"]
        assert rule["outboundTag"] == "api"


class TestDeployConfig:
    @pytest.mark.asyncio
    async def test_writes_config_snapshots_and_restarts_via_helper(self, manager, tmp_path, monkeypatch):
        target = tmp_path / "xray_config.json"
        config = {"inbounds": []}

        snapshot_called = []
        monkeypatch.setattr(
            "backend.app.core.proxy_manager.snapshot_and_arm",
            lambda: snapshot_called.append(True),
        )

        async def _fake_helper_request(operation, payload=None, **kw):
            assert operation == "service.restart"
            assert payload == {"service": "xray"}
            return HelperResponse(ok=True, message="restarted")

        monkeypatch.setattr(
            "backend.app.core.proxy_manager.helper_request", _fake_helper_request,
        )

        await manager.deploy_config("node-1", config, filepath=str(target))

        assert snapshot_called == [True]
        assert json.loads(target.read_text()) == config

    @pytest.mark.asyncio
    async def test_helper_refusal_raises(self, manager, tmp_path, monkeypatch):
        target = tmp_path / "xray_config.json"
        monkeypatch.setattr("backend.app.core.proxy_manager.snapshot_and_arm", lambda: None)

        async def _fake_helper_request(operation, payload=None, **kw):
            return HelperResponse(ok=False, message="service is not allowlisted")

        monkeypatch.setattr(
            "backend.app.core.proxy_manager.helper_request", _fake_helper_request,
        )

        with pytest.raises(RuntimeError):
            await manager.deploy_config("node-1", {"inbounds": []}, filepath=str(target))

    @pytest.mark.asyncio
    async def test_privileged_helper_unreachable_propagates(self, manager, tmp_path, monkeypatch):
        target = tmp_path / "xray_config.json"
        monkeypatch.setattr("backend.app.core.proxy_manager.snapshot_and_arm", lambda: None)

        async def _fake_helper_request(operation, payload=None, **kw):
            raise PrivilegedHelperError("helper unavailable")

        monkeypatch.setattr(
            "backend.app.core.proxy_manager.helper_request", _fake_helper_request,
        )

        with pytest.raises(PrivilegedHelperError):
            await manager.deploy_config("node-1", {"inbounds": []}, filepath=str(target))
