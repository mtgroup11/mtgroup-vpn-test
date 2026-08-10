"""
MTGroup VPN Ultimate — Watchdog Client Test Suite
Tests backend/app/core/watchdog_client.py's snapshot_and_arm(): iptables/
Xray config snapshotting and HMAC-signed watchdog arming — subprocess,
filesystem, and the Unix socket all mocked out (no real iptables-save or
watchdog daemon needed).
"""

from __future__ import annotations

import hashlib
import hmac
import subprocess
from unittest.mock import MagicMock, mock_open, patch

import backend.app.core.watchdog_client as wc


class TestSnapshotAndArm:
    def test_creates_snapshot_directory(self):
        with patch("backend.app.core.watchdog_client.os.makedirs") as makedirs_mock, \
             patch("backend.app.core.watchdog_client.subprocess.run"), \
             patch("backend.app.core.watchdog_client.os.path.exists", return_value=False), \
             patch("builtins.open", mock_open(read_data="secret")), \
             patch("backend.app.core.watchdog_client.socket") as socket_mod:
            socket_mod.socket.return_value.recv.return_value = b"ARMED\n"
            wc.snapshot_and_arm()
            makedirs_mock.assert_called_once_with(wc.SNAPSHOT_DIR, exist_ok=True)

    def test_saves_iptables_snapshot_via_argv_no_shell(self):
        with patch("backend.app.core.watchdog_client.os.makedirs"), \
             patch("backend.app.core.watchdog_client.subprocess.run") as run_mock, \
             patch("backend.app.core.watchdog_client.os.path.exists", return_value=False), \
             patch("builtins.open", mock_open(read_data="secret")), \
             patch("backend.app.core.watchdog_client.socket") as socket_mod:
            socket_mod.socket.return_value.recv.return_value = b"ARMED\n"
            wc.snapshot_and_arm()
            iptables_call = run_mock.call_args_list[0]
            assert iptables_call.args[0] == ["iptables-save"]
            assert iptables_call.kwargs["check"] is True

    def test_iptables_snapshot_failure_is_logged_not_raised(self):
        with patch("backend.app.core.watchdog_client.os.makedirs"), \
             patch(
                 "backend.app.core.watchdog_client.subprocess.run",
                 side_effect=subprocess.CalledProcessError(1, "iptables-save"),
             ), \
             patch("backend.app.core.watchdog_client.os.path.exists", return_value=False), \
             patch("builtins.open", mock_open(read_data="secret")), \
             patch("backend.app.core.watchdog_client.socket") as socket_mod:
            socket_mod.socket.return_value.recv.return_value = b"ARMED\n"
            wc.snapshot_and_arm()  # must not raise

    def test_snapshots_xray_config_when_present(self):
        with patch("backend.app.core.watchdog_client.os.makedirs"), \
             patch("backend.app.core.watchdog_client.subprocess.run") as run_mock, \
             patch("backend.app.core.watchdog_client.os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data="secret")), \
             patch("backend.app.core.watchdog_client.socket") as socket_mod:
            socket_mod.socket.return_value.recv.return_value = b"ARMED\n"
            wc.snapshot_and_arm()
            xray_call = run_mock.call_args_list[1]
            assert xray_call.args[0][0] == "cp"

    def test_skips_xray_snapshot_when_config_absent(self):
        with patch("backend.app.core.watchdog_client.os.makedirs"), \
             patch("backend.app.core.watchdog_client.subprocess.run") as run_mock, \
             patch("backend.app.core.watchdog_client.os.path.exists", return_value=False), \
             patch("builtins.open", mock_open(read_data="secret")), \
             patch("backend.app.core.watchdog_client.socket") as socket_mod:
            socket_mod.socket.return_value.recv.return_value = b"ARMED\n"
            wc.snapshot_and_arm()
            assert run_mock.call_count == 1  # only iptables-save, no cp

    def test_xray_snapshot_failure_is_logged_not_raised(self):
        def _run_side_effect(args, **kwargs):
            if args[0] == "cp":
                raise subprocess.CalledProcessError(1, "cp")
            return MagicMock()

        with patch("backend.app.core.watchdog_client.os.makedirs"), \
             patch("backend.app.core.watchdog_client.subprocess.run", side_effect=_run_side_effect), \
             patch("backend.app.core.watchdog_client.os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data="secret")), \
             patch("backend.app.core.watchdog_client.socket") as socket_mod:
            socket_mod.socket.return_value.recv.return_value = b"ARMED\n"
            wc.snapshot_and_arm()  # must not raise

    def test_arms_watchdog_with_valid_hmac_signature(self):
        secret = "shared-secret"
        with patch("backend.app.core.watchdog_client.os.makedirs"), \
             patch("backend.app.core.watchdog_client.subprocess.run"), \
             patch("backend.app.core.watchdog_client.os.path.exists", return_value=False), \
             patch("builtins.open", mock_open(read_data=secret)), \
             patch("backend.app.core.watchdog_client.socket") as socket_mod, \
             patch("backend.app.core.watchdog_client.time.time", return_value=1_700_000_000.0):
            client = socket_mod.socket.return_value
            client.recv.return_value = b"ARMED\n"

            wc.snapshot_and_arm()

            client.connect.assert_called_once_with(wc.SOCK_FILE)
            sent = client.sendall.call_args.args[0].decode("utf-8")
            assert sent.startswith("ARM:1700000000:")
            _, timestamp_str, signature = sent.strip().split(":")
            expected_sig = hmac.new(
                secret.encode("utf-8"), timestamp_str.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            assert signature == expected_sig
            client.close.assert_called_once()

    def test_missing_secret_file_does_not_raise(self):
        with patch("backend.app.core.watchdog_client.os.makedirs"), \
             patch("backend.app.core.watchdog_client.subprocess.run"), \
             patch("backend.app.core.watchdog_client.os.path.exists", return_value=False), \
             patch("builtins.open", side_effect=FileNotFoundError()):
            wc.snapshot_and_arm()  # must not raise — logged as "NOT armed"

    def test_socket_connect_failure_does_not_raise(self):
        with patch("backend.app.core.watchdog_client.os.makedirs"), \
             patch("backend.app.core.watchdog_client.subprocess.run"), \
             patch("backend.app.core.watchdog_client.os.path.exists", return_value=False), \
             patch("builtins.open", mock_open(read_data="secret")), \
             patch("backend.app.core.watchdog_client.socket") as socket_mod:
            socket_mod.socket.return_value.connect.side_effect = ConnectionRefusedError()
            wc.snapshot_and_arm()  # must not raise — logged as "NOT armed"
