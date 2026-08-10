"""
MTGroup VPN Ultimate — Anti-Lockout Watchdog Test Suite
Tests backend/app/core/watchdog.py's HMAC auth, arm/heartbeat protocol,
and rollback logic — with the secret file, subprocess calls, and sockets
all mocked out. `run()` (the real socket-accept loop) is intentionally
not covered here; it's a thin `while True: accept()` wrapper around
`handle_connection`, which is covered directly.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from unittest.mock import MagicMock, mock_open, patch

import pytest

import backend.app.core.watchdog as wd


SECRET = b"test-secret-shared-with-panel"


@pytest.fixture
def watchdog():
    with patch("builtins.open", mock_open(read_data=SECRET.decode())):
        wd_instance = wd.Watchdog()
    return wd_instance


def _signed_parts(command: str, secret: bytes = SECRET, ts: float | None = None) -> list[str]:
    timestamp_str = str(int(ts if ts is not None else time.time()))
    signature = hmac.new(secret, timestamp_str.encode("utf-8"), hashlib.sha256).hexdigest()
    return [command, timestamp_str, signature]


class TestGetSecret:
    def test_reads_and_strips_secret_file(self):
        with patch("builtins.open", mock_open(read_data="  my-secret\n")):
            assert wd.get_secret() == b"my-secret"

    def test_exits_when_secret_file_missing(self):
        with patch("builtins.open", side_effect=FileNotFoundError()):
            with pytest.raises(SystemExit):
                wd.get_secret()


class TestVerifyAuth:
    def test_accepts_valid_signature(self, watchdog):
        parts = _signed_parts("ARM")
        err, valid = watchdog.verify_auth(parts, "ARM")
        assert valid is True
        assert err == ""

    def test_rejects_wrong_signature(self, watchdog):
        parts = _signed_parts("ARM")
        parts[2] = "0" * 64  # bogus signature
        err, valid = watchdog.verify_auth(parts, "ARM")
        assert valid is False
        assert "signature" in err.lower()

    def test_rejects_signature_from_wrong_secret(self, watchdog):
        parts = _signed_parts("ARM", secret=b"attacker-does-not-know-real-secret")
        err, valid = watchdog.verify_auth(parts, "ARM")
        assert valid is False

    def test_rejects_stale_timestamp(self, watchdog):
        parts = _signed_parts("ARM", ts=time.time() - 3600)  # 1h old — replay attempt
        err, valid = watchdog.verify_auth(parts, "ARM")
        assert valid is False
        assert "timestamp" in err.lower()

    def test_rejects_future_timestamp_beyond_window(self, watchdog):
        parts = _signed_parts("ARM", ts=time.time() + 3600)
        err, valid = watchdog.verify_auth(parts, "ARM")
        assert valid is False

    def test_rejects_malformed_message(self, watchdog):
        err, valid = watchdog.verify_auth(["ARM"], "ARM")
        assert valid is False

    def test_rejects_non_numeric_timestamp(self, watchdog):
        parts = ["ARM", "not-a-number", "deadbeef"]
        err, valid = watchdog.verify_auth(parts, "ARM")
        assert valid is False
        assert "timestamp" in err.lower()


class TestHandleHeartbeat:
    def test_disarms_when_armed(self, watchdog):
        watchdog.armed = True
        watchdog.timer = MagicMock()

        resp = watchdog.handle_heartbeat(_signed_parts("HEARTBEAT"))

        assert "disarmed" in resp.lower()
        watchdog.timer.cancel.assert_called_once()
        assert watchdog.armed is False

    def test_reports_not_armed(self, watchdog):
        watchdog.armed = False
        resp = watchdog.handle_heartbeat(_signed_parts("HEARTBEAT"))
        assert "not armed" in resp.lower()

    def test_invalid_signature_does_not_disarm(self, watchdog):
        watchdog.armed = True
        watchdog.timer = MagicMock()
        parts = _signed_parts("HEARTBEAT")
        parts[2] = "0" * 64

        resp = watchdog.handle_heartbeat(parts)

        assert "error" in resp.lower()
        watchdog.timer.cancel.assert_not_called()
        assert watchdog.armed is True  # unchanged — forged heartbeat must not disarm


class TestHandleArm:
    def test_arms_on_valid_request(self, watchdog):
        try:
            resp = watchdog.handle_arm(_signed_parts("ARM"))
            assert "armed" in resp.lower()
            assert watchdog.armed is True
        finally:
            if watchdog.timer:
                watchdog.timer.cancel()  # don't let the real 60s timer fire in test suite

    def test_rejects_invalid_signature(self, watchdog):
        parts = _signed_parts("ARM")
        parts[2] = "0" * 64
        resp = watchdog.handle_arm(parts)
        assert "error" in resp.lower()
        assert watchdog.armed is False


class TestHandleConnection:
    def test_routes_arm_command(self, watchdog):
        conn = MagicMock()
        conn.recv.return_value = ":".join(_signed_parts("ARM")).encode("utf-8")

        try:
            watchdog.handle_connection(conn)
            sent = conn.sendall.call_args.args[0]
            assert b"SUCCESS" in sent
        finally:
            if watchdog.timer:
                watchdog.timer.cancel()

    def test_unknown_command_returns_error(self, watchdog):
        conn = MagicMock()
        conn.recv.return_value = b"NUKE:123:abc"

        watchdog.handle_connection(conn)

        sent = conn.sendall.call_args.args[0]
        assert b"Unknown command" in sent

    def test_connection_is_always_closed(self, watchdog):
        conn = MagicMock()
        conn.recv.side_effect = RuntimeError("socket error")

        watchdog.handle_connection(conn)  # must not raise

        conn.close.assert_called_once()


class TestExecuteRollback:
    def test_restores_iptables_and_xray_and_restarts_services(self, watchdog):
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data="")), \
             patch("backend.app.core.watchdog.subprocess.run") as run_mock:
            run_mock.return_value = MagicMock(returncode=0)
            watchdog._execute_rollback()

        commands = [call.args[0] for call in run_mock.call_args_list]
        assert ["iptables-restore"] in commands
        assert ["cp", wd.XRAY_BAK, wd.XRAY_TARGET] in commands
        assert ["systemctl", "restart", "xray"] in commands
        assert ["systemctl", "restart", "mtgroup-backend"] in commands
        assert watchdog.armed is False

    def test_falls_back_to_accept_all_when_snapshots_missing(self, watchdog):
        with patch("os.path.exists", return_value=False), \
             patch("backend.app.core.watchdog.subprocess.run") as run_mock:
            run_mock.return_value = MagicMock(returncode=0)
            watchdog._execute_rollback()

        commands = [call.args[0] for call in run_mock.call_args_list]
        # Last-resort "open everything up" fallback so the operator isn't
        # locked out even if the snapshot-based restore couldn't run.
        assert ["iptables", "-P", "INPUT", "ACCEPT"] in commands
        assert ["iptables", "-F"] in commands
