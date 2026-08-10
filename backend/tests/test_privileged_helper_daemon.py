"""
MTGroup VPN Ultimate — Privileged Helper Daemon Test Suite
Tests the allowlisted-operation dispatch, input validation, and command
construction of backend/app/privileged_helper_daemon.py WITHOUT executing
any real subprocess/root operation — `_run` is monkeypatched throughout so
these tests are portable (they don't require Linux/iptables/nft/root) and
still exercise the exact code paths CI (ubuntu-latest) would hit.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from backend.app import privileged_helper_daemon as helper


@pytest.fixture
def fake_run(monkeypatch):
    """Records every argv the daemon would have executed and returns a
    canned success response, without touching the real system."""
    calls: list[list[str]] = []

    def _fake(argv, timeout=15):
        calls.append(argv)
        return {"ok": True, "message": "", "code": 0}

    monkeypatch.setattr(helper, "_run", _fake)
    return calls


class TestValidateIP:
    def test_accepts_valid_ipv4(self):
        result = helper._validate_ip({"ip": "203.0.113.4"})
        assert str(result) == "203.0.113.4"

    def test_accepts_valid_ipv6(self):
        result = helper._validate_ip({"ip": "2001:db8::1"})
        assert str(result) == "2001:db8::1"

    def test_rejects_shell_injection_attempt(self):
        result = helper._validate_ip({"ip": "1.2.3.4; touch /tmp/pwned"})
        assert isinstance(result, dict)
        assert result["ok"] is False

    def test_rejects_nft_syntax_injection_attempt(self):
        """Even without a shell, extra whitespace-separated tokens could
        smuggle additional nft syntax if they were ever passed through as
        separate argv entries — ipaddress.ip_address() must reject this
        outright rather than accepting a "close enough" string."""
        result = helper._validate_ip({"ip": "1.2.3.4 counter accept"})
        assert isinstance(result, dict)
        assert result["ok"] is False

    def test_rejects_non_string_ip(self):
        result = helper._validate_ip({"ip": 12345})
        assert isinstance(result, dict)
        assert result["ok"] is False

    def test_rejects_missing_ip(self):
        result = helper._validate_ip({})
        assert isinstance(result, dict)
        assert result["ok"] is False


class TestFirewallBanUnban:
    def test_ban_ip_rejects_invalid_before_touching_run(self, fake_run):
        result = helper._firewall_ban_ip({"ip": "not-an-ip; rm -rf /"})
        assert result["ok"] is False
        assert fake_run == []  # never even tried to build a command

    def test_ban_ip_v4_uses_v4_set(self, fake_run):
        result = helper._firewall_ban_ip({"ip": "203.0.113.4"})
        assert result["ok"] is True
        ban_calls = [c for c in fake_run if "element" in c and "add" in c]
        assert ban_calls
        assert helper.NFT_SET_V4 in ban_calls[-1]
        assert "203.0.113.4" in ban_calls[-1]

    def test_ban_ip_v6_uses_v6_set(self, fake_run):
        helper._firewall_ban_ip({"ip": "2001:db8::1"})
        ban_calls = [c for c in fake_run if "element" in c and "add" in c]
        assert ban_calls
        assert helper.NFT_SET_V6 in ban_calls[-1]

    def test_unban_ip_missing_element_is_treated_as_success(self, monkeypatch):
        def _fake(argv, timeout=15):
            if argv[:3] == ["nft", "delete", "element"]:
                return {"ok": False, "message": "does not exist", "code": 1}
            return {"ok": True, "message": "", "code": 0}

        monkeypatch.setattr(helper, "_run", _fake)
        result = helper._firewall_unban_ip({"ip": "203.0.113.4"})
        assert result["ok"] is True

    def test_unban_ip_rejects_invalid(self, fake_run):
        result = helper._firewall_unban_ip({"ip": "garbage"})
        assert result["ok"] is False
        assert fake_run == []


class TestServiceRestart:
    def test_allowlisted_service_is_restarted(self, fake_run):
        result = helper._service_restart({"service": "xray"})
        assert result["ok"] is True
        assert ["systemctl", "restart", "xray"] in fake_run

    @pytest.mark.parametrize("service", ["ssh", "cron", "../../etc/passwd", "xray; rm -rf /", ""])
    def test_non_allowlisted_service_is_rejected(self, fake_run, service):
        result = helper._service_restart({"service": service})
        assert result["ok"] is False
        assert fake_run == []  # never even attempted systemctl


class TestKillswitch:
    def test_apply_rejects_invalid_port_type(self, fake_run):
        result = helper._killswitch_apply({"whitelist_ports": ["not-an-int"]})
        assert result["ok"] is False

    def test_apply_rejects_out_of_range_port(self, fake_run):
        result = helper._killswitch_apply({"whitelist_ports": [99999]})
        assert result["ok"] is False

    def test_apply_builds_expected_iptables_chain(self, fake_run):
        result = helper._killswitch_apply({"whitelist_ports": [22, 443]})
        assert result["ok"] is True
        joined = [" ".join(c) for c in fake_run]
        assert any(f"-N {helper.KILLSWITCH_CHAIN}" in c for c in joined)
        assert any("--dport 22" in c for c in joined)
        assert any("--dport 443" in c for c in joined)
        assert any("-j DROP" in c for c in joined)

    def test_release_removes_chain_and_route(self, fake_run):
        result = helper._killswitch_release({})
        assert result["ok"] is True
        joined = [" ".join(c) for c in fake_run]
        assert any(f"-X {helper.KILLSWITCH_CHAIN}" in c for c in joined)
        assert any("blackhole" in c for c in joined)


class TestDispatch:
    def test_unknown_operation_is_rejected(self, fake_run):
        result = helper._dispatch("shell.exec", {"cmd": "rm -rf /"})
        assert result["ok"] is False
        assert "not allowlisted" in result["message"]
        assert fake_run == []

    def test_known_operation_routes_to_handler(self, fake_run):
        result = helper._dispatch("service.restart", {"service": "xray"})
        assert result["ok"] is True

    def test_handler_exception_does_not_crash_dispatch(self, monkeypatch):
        def _boom(payload):
            raise RuntimeError("boom")

        monkeypatch.setitem(helper._OPERATIONS, "service.restart", _boom)
        result = helper._dispatch("service.restart", {"service": "xray"})
        assert result["ok"] is False
        assert "internal error" in result["message"]


class TestPeerAllowed:
    def test_falls_back_when_so_peercred_unavailable(self):
        """On platforms without SO_PEERCRED (e.g. this dev sandbox), the
        daemon must not crash — it degrades to socket-file-permission-only
        auth (with a logged warning), never to an unconditional accept
        that silently ignores the missing check."""
        with patch.object(helper.socket, "SO_PEERCRED", None, create=True):
            with patch("backend.app.privileged_helper_daemon.hasattr", side_effect=lambda o, n: False if n == "SO_PEERCRED" else hasattr(o, n)):
                assert helper._peer_allowed(writer=object()) is True
