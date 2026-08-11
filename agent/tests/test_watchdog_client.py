"""
MTGroup VPN Ultimate — Node-side Watchdog Client Tests

Tests agent/watchdog_client.py's arm_and_snapshot()/disarm(): HMAC-signed
ARM/HEARTBEAT framing and the AmneziaWG config snapshot, with the secret
file, subprocess calls, and the Unix socket all mocked out — no real
watchdog daemon needed. Mirrors backend/tests/test_watchdog_client.py's
coverage of the master-side twin of this protocol.
"""

from __future__ import annotations

import hashlib
import hmac
import subprocess
from unittest.mock import mock_open, patch

import agent.watchdog_client as wc


class TestArmAndSnapshot:
    def test_creates_snapshot_directory(self):
        with patch("agent.watchdog_client.os.makedirs") as makedirs_mock, \
             patch("agent.watchdog_client.subprocess.run"), \
             patch("agent.watchdog_client.os.path.exists", return_value=False), \
             patch("builtins.open", mock_open(read_data="secret")), \
             patch("agent.watchdog_client.socket") as socket_mod:
            socket_mod.socket.return_value.recv.return_value = b"SUCCESS: Armed\n"
            wc.arm_and_snapshot("/etc/amnezia/amneziawg/awg0.conf")
            makedirs_mock.assert_called_once_with(wc.SNAPSHOT_DIR, exist_ok=True)

    def test_snapshots_config_when_present(self):
        with patch("agent.watchdog_client.os.makedirs"), \
             patch("agent.watchdog_client.subprocess.run") as run_mock, \
             patch("agent.watchdog_client.os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data="secret")), \
             patch("agent.watchdog_client.socket") as socket_mod:
            socket_mod.socket.return_value.recv.return_value = b"SUCCESS: Armed\n"
            wc.arm_and_snapshot("/etc/amnezia/amneziawg/awg0.conf")
            cp_call = run_mock.call_args_list[0]
            assert cp_call.args[0][0] == "cp"
            assert cp_call.args[0][1] == "/etc/amnezia/amneziawg/awg0.conf"
            assert cp_call.args[0][2].endswith(wc.AWG_BAK_NAME)

    def test_skips_snapshot_when_config_absent(self):
        with patch("agent.watchdog_client.os.makedirs"), \
             patch("agent.watchdog_client.subprocess.run") as run_mock, \
             patch("agent.watchdog_client.os.path.exists", return_value=False), \
             patch("builtins.open", mock_open(read_data="secret")), \
             patch("agent.watchdog_client.socket") as socket_mod:
            socket_mod.socket.return_value.recv.return_value = b"SUCCESS: Armed\n"
            wc.arm_and_snapshot("/etc/amnezia/amneziawg/awg0.conf")
            run_mock.assert_not_called()  # nothing to snapshot, first-ever provisioning

    def test_snapshot_failure_is_logged_not_raised(self):
        with patch("agent.watchdog_client.os.makedirs"), \
             patch(
                 "agent.watchdog_client.subprocess.run",
                 side_effect=subprocess.CalledProcessError(1, "cp"),
             ), \
             patch("agent.watchdog_client.os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data="secret")), \
             patch("agent.watchdog_client.socket") as socket_mod:
            socket_mod.socket.return_value.recv.return_value = b"SUCCESS: Armed\n"
            wc.arm_and_snapshot("/etc/amnezia/amneziawg/awg0.conf")  # must not raise

    def test_sends_signed_arm_and_returns_true_on_success(self):
        secret = "shared-secret"
        with patch("agent.watchdog_client.os.makedirs"), \
             patch("agent.watchdog_client.subprocess.run"), \
             patch("agent.watchdog_client.os.path.exists", return_value=False), \
             patch("builtins.open", mock_open(read_data=secret)), \
             patch("agent.watchdog_client.socket") as socket_mod, \
             patch("agent.watchdog_client.time.time", return_value=1_700_000_000.0):
            client = socket_mod.socket.return_value
            client.recv.return_value = b"SUCCESS: Armed\n"

            result = wc.arm_and_snapshot("/etc/amnezia/amneziawg/awg0.conf")

            assert result is True
            client.connect.assert_called_once_with(wc.SOCK_FILE)
            sent = client.sendall.call_args.args[0].decode("utf-8")
            assert sent.startswith("ARM:1700000000:")
            _, timestamp_str, signature = sent.strip().split(":")
            expected_sig = hmac.new(
                secret.encode("utf-8"), timestamp_str.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            assert signature == expected_sig

    def test_missing_secret_file_does_not_raise(self):
        with patch("agent.watchdog_client.os.makedirs"), \
             patch("agent.watchdog_client.subprocess.run"), \
             patch("agent.watchdog_client.os.path.exists", return_value=False), \
             patch("builtins.open", side_effect=FileNotFoundError()):
            result = wc.arm_and_snapshot("/etc/amnezia/amneziawg/awg0.conf")
            assert result is False

    def test_socket_connect_failure_returns_false_not_raise(self):
        with patch("agent.watchdog_client.os.makedirs"), \
             patch("agent.watchdog_client.subprocess.run"), \
             patch("agent.watchdog_client.os.path.exists", return_value=False), \
             patch("builtins.open", mock_open(read_data="secret")), \
             patch("agent.watchdog_client.socket") as socket_mod:
            socket_mod.socket.return_value.connect.side_effect = ConnectionRefusedError()
            result = wc.arm_and_snapshot("/etc/amnezia/amneziawg/awg0.conf")
            assert result is False


class TestDisarm:
    def test_sends_signed_heartbeat(self):
        with patch("builtins.open", mock_open(read_data="secret")), \
             patch("agent.watchdog_client.socket") as socket_mod:
            client = socket_mod.socket.return_value
            client.recv.return_value = b"SUCCESS: Watchdog disarmed\n"

            result = wc.disarm()

            assert result is True
            sent = client.sendall.call_args.args[0].decode("utf-8")
            assert sent.startswith("HEARTBEAT:")

    def test_failure_response_returns_false(self):
        with patch("builtins.open", mock_open(read_data="secret")), \
             patch("agent.watchdog_client.socket") as socket_mod:
            socket_mod.socket.return_value.recv.return_value = b"ERROR: Invalid signature\n"
            assert wc.disarm() is False

    def test_missing_secret_file_returns_false_not_raise(self):
        with patch("builtins.open", side_effect=FileNotFoundError()):
            assert wc.disarm() is False
