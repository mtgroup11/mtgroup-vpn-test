"""
MTGroup VPN Ultimate — SSL Manager Test Suite
Tests backend/app/core/ssl_manager.py's certbot invocation logic with
`asyncio.create_subprocess_exec` mocked out — no real certbot/network call.
"""

from __future__ import annotations

import asyncio

import pytest

from backend.app.core.ssl_manager import AsyncSSLManager


class _FakeProcess:
    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self):
        return self._stdout, self._stderr


@pytest.fixture
def manager():
    return AsyncSSLManager()


class TestIssueCertificate:
    @pytest.mark.asyncio
    async def test_success_returns_true(self, manager, monkeypatch):
        captured_cmd = {}

        async def _fake_exec(*cmd, **kw):
            captured_cmd["cmd"] = cmd
            return _FakeProcess(0, stdout=b"Congratulations!")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

        ok = await manager.issue_certificate("example.com", "admin@example.com")
        assert ok is True
        assert "certbot" in captured_cmd["cmd"]
        assert "-d" in captured_cmd["cmd"]
        assert "example.com" in captured_cmd["cmd"]
        assert "-m" in captured_cmd["cmd"]
        assert "admin@example.com" in captured_cmd["cmd"]

    @pytest.mark.asyncio
    async def test_failure_returns_false(self, manager, monkeypatch):
        async def _fake_exec(*cmd, **kw):
            return _FakeProcess(1, stderr=b"Port 80 in use")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
        ok = await manager.issue_certificate("example.com", "admin@example.com")
        assert ok is False

    @pytest.mark.asyncio
    async def test_certbot_not_installed_returns_false_not_raise(self, manager, monkeypatch):
        async def _fake_exec(*cmd, **kw):
            raise FileNotFoundError("certbot not found")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
        ok = await manager.issue_certificate("example.com", "admin@example.com")
        assert ok is False


class TestCheckAndRenew:
    @pytest.mark.asyncio
    async def test_no_renewals_needed_does_not_raise(self, manager, monkeypatch):
        async def _fake_exec(*cmd, **kw):
            return _FakeProcess(0, stdout=b"No renewals were attempted.")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
        await manager._check_and_renew()  # must not raise

    @pytest.mark.asyncio
    async def test_certbot_missing_is_handled_gracefully(self, manager, monkeypatch):
        async def _fake_exec(*cmd, **kw):
            raise FileNotFoundError("no certbot")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
        await manager._check_and_renew()  # must not raise

    @pytest.mark.asyncio
    async def test_renewal_failure_is_logged_not_raised(self, manager, monkeypatch):
        async def _fake_exec(*cmd, **kw):
            return _FakeProcess(1, stderr=b"renewal failed")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
        await manager._check_and_renew()  # must not raise


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_start_stop_cron_is_idempotent_and_clean(self, manager, monkeypatch):
        async def _fake_exec(*cmd, **kw):
            return _FakeProcess(0, stdout=b"No renewals were attempted.")

        monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

        await manager.start_auto_renew_cron()
        assert manager._is_running is True
        await manager.start_auto_renew_cron()  # second call is a no-op
        assert manager._cron_task is not None

        await manager.stop()
        assert manager._is_running is False
