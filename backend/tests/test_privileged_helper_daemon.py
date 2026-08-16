"""
MTGroup VPN Ultimate — Privileged Helper Daemon Test Suite
Tests the allowlisted-operation dispatch, input validation, and command
construction of backend/app/privileged_helper_daemon.py WITHOUT executing
any real subprocess/root operation — `_run` is monkeypatched throughout so
these tests are portable (they don't require Linux/iptables/nft/root) and
still exercise the exact code paths CI (ubuntu-latest) would hit.
"""

from __future__ import annotations

import struct
import sys
from types import ModuleType, SimpleNamespace
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


class TestPeerAllowedSoPeercred:
    """Exercises the real Linux SO_PEERCRED credential-check path — this
    daemon is the whole privilege boundary between the unprivileged panel
    process and root, so an untested access-control path here is worse
    than untested elsewhere. `pwd`/`grp` are POSIX-only stdlib modules
    (imported locally inside `_peer_allowed`, so patching sys.modules
    before the call is what makes this portable to non-Linux dev/CI
    hosts) and SO_PEERCRED's struct layout (3 native ints: pid, uid, gid)
    is faked via a fake socket object rather than a real one.
    """

    class _FakeSocket:
        def __init__(self, peercred_bytes):
            self._peercred_bytes = peercred_bytes

        def getsockopt(self, level, optname, buflen):
            return self._peercred_bytes

    @staticmethod
    def _peercred_bytes(pid: int, uid: int, gid: int) -> bytes:
        return struct.pack("3i", pid, uid, gid)

    @staticmethod
    def _fake_writer(sock):
        writer = SimpleNamespace()
        writer.get_extra_info = lambda key: sock if key == "socket" else None
        return writer

    @pytest.fixture(autouse=True)
    def _has_so_peercred(self):
        with patch.object(helper.socket, "SO_PEERCRED", 17, create=True):
            yield

    @pytest.fixture
    def fake_pwd_grp(self, monkeypatch):
        """Registers fake pwd/grp modules so `import pwd`/`import grp`
        inside _peer_allowed resolve to these instead of failing on
        non-POSIX hosts."""
        pwd_module = ModuleType("pwd")
        grp_module = ModuleType("grp")
        pwd_module.getpwnam = lambda name: SimpleNamespace(pw_uid=1000)
        grp_module.getgrnam = lambda name: SimpleNamespace(gr_gid=2000)
        monkeypatch.setitem(sys.modules, "pwd", pwd_module)
        monkeypatch.setitem(sys.modules, "grp", grp_module)
        return pwd_module, grp_module

    def test_allows_when_uid_matches(self, fake_pwd_grp):
        sock = self._FakeSocket(self._peercred_bytes(pid=1, uid=1000, gid=9999))
        assert helper._peer_allowed(self._fake_writer(sock)) is True

    def test_allows_when_gid_matches_even_if_uid_does_not(self, fake_pwd_grp):
        sock = self._FakeSocket(self._peercred_bytes(pid=1, uid=9999, gid=2000))
        assert helper._peer_allowed(self._fake_writer(sock)) is True

    def test_rejects_when_neither_uid_nor_gid_matches(self, fake_pwd_grp):
        sock = self._FakeSocket(self._peercred_bytes(pid=1, uid=9999, gid=9999))
        assert helper._peer_allowed(self._fake_writer(sock)) is False

    def test_rejects_when_socket_is_unavailable(self):
        writer = SimpleNamespace()
        writer.get_extra_info = lambda key: None
        assert helper._peer_allowed(writer) is False

    def test_rejects_and_does_not_crash_on_unknown_panel_user(self, monkeypatch):
        """PANEL_USER/PANEL_GROUP misconfigured (e.g. the daemon deployed
        before the mtgroup system user was created) must fail closed, not
        raise out of the connection handler."""
        pwd_module = ModuleType("pwd")
        grp_module = ModuleType("grp")

        def _raise_keyerror(name):
            raise KeyError(name)

        pwd_module.getpwnam = _raise_keyerror
        grp_module.getgrnam = lambda name: SimpleNamespace(gr_gid=2000)
        monkeypatch.setitem(sys.modules, "pwd", pwd_module)
        monkeypatch.setitem(sys.modules, "grp", grp_module)

        sock = self._FakeSocket(self._peercred_bytes(pid=1, uid=1000, gid=2000))
        assert helper._peer_allowed(self._fake_writer(sock)) is False
