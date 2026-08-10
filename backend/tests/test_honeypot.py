"""
MTGroup VPN Ultimate — Dynamic Honeypot Engine Test Suite
Covers self-signed cert generation (real cryptography, real temp files —
cheap enough not to mock), handle_client's response-selection and
lethal-decoy-ban branches (fake asyncio streams, mocked orchestrator),
and the start/stop lifecycle (mocked asyncio.start_server/ssl context).
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.app.core.honeypot import HoneypotEngine


class _FakeReader:
    def __init__(self, chunks: list[bytes]):
        self._chunks = list(chunks)

    async def read(self, n: int) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        return b""


class _FakeWriter:
    def __init__(self, peer=("198.51.100.7", 4444)):
        self.written = bytearray()
        self.closed = False
        self._peer = peer

    def get_extra_info(self, name):
        return self._peer if name == "peername" else None

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


class TestGenerateSelfSignedCert:
    @pytest.mark.asyncio
    async def test_creates_readable_pem_cert_and_key_files(self):
        engine = HoneypotEngine(port=0)
        try:
            await engine._generate_self_signed_cert()
            assert os.path.exists(engine._cert_path)
            assert os.path.exists(engine._key_path)
            with open(engine._cert_path, "rb") as f:
                assert b"BEGIN CERTIFICATE" in f.read()
            with open(engine._key_path, "rb") as f:
                assert b"PRIVATE KEY" in f.read()
        finally:
            if engine._cert_path and os.path.exists(engine._cert_path):
                os.remove(engine._cert_path)
            if engine._key_path and os.path.exists(engine._key_path):
                os.remove(engine._key_path)


class TestHandleClient:
    @pytest.mark.asyncio
    async def test_root_request_gets_200_nginx_welcome_page(self):
        engine = HoneypotEngine(port=0)
        reader = _FakeReader([b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"])
        writer = _FakeWriter()
        await engine.handle_client(reader, writer)
        assert bytes(writer.written).startswith(b"HTTP/1.1 200 OK")
        assert b"Welcome to nginx" in bytes(writer.written)
        assert writer.closed is True

    @pytest.mark.asyncio
    async def test_unknown_path_gets_404(self):
        engine = HoneypotEngine(port=0)
        reader = _FakeReader([b"GET /some/random/path HTTP/1.1\r\n\r\n"])
        writer = _FakeWriter()
        await engine.handle_client(reader, writer)
        assert bytes(writer.written).startswith(b"HTTP/1.1 404 Not Found")

    @pytest.mark.asyncio
    async def test_env_probe_triggers_lethal_ban_and_still_returns_404(self, monkeypatch):
        alert_mock = AsyncMock()
        monkeypatch.setattr("backend.app.core.honeypot.orchestrator.handle_security_alert", alert_mock)

        engine = HoneypotEngine(port=0)
        reader = _FakeReader([b"GET /.env HTTP/1.1\r\n\r\n"])
        writer = _FakeWriter(peer=("203.0.113.99", 1234))
        await engine.handle_client(reader, writer)

        alert_mock.assert_awaited_once()
        call_args = alert_mock.await_args
        assert call_args.args[0] == "203.0.113.99"
        assert "LETHAL_PROBE" in call_args.args[1]
        assert bytes(writer.written).startswith(b"HTTP/1.1 404 Not Found")

    @pytest.mark.asyncio
    async def test_backup_sql_probe_triggers_lethal_ban(self, monkeypatch):
        alert_mock = AsyncMock()
        monkeypatch.setattr("backend.app.core.honeypot.orchestrator.handle_security_alert", alert_mock)

        engine = HoneypotEngine(port=0)
        reader = _FakeReader([b"GET /admin/backup.sql.zip HTTP/1.1\r\n\r\n"])
        writer = _FakeWriter()
        await engine.handle_client(reader, writer)

        alert_mock.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_benign_unknown_path_does_not_trigger_ban(self, monkeypatch):
        alert_mock = AsyncMock()
        monkeypatch.setattr("backend.app.core.honeypot.orchestrator.handle_security_alert", alert_mock)

        engine = HoneypotEngine(port=0)
        reader = _FakeReader([b"GET /favicon.ico HTTP/1.1\r\n\r\n"])
        writer = _FakeWriter()
        await engine.handle_client(reader, writer)

        alert_mock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_read_timeout_is_swallowed_and_writer_still_closed(self, monkeypatch):
        async def _timeout(coro, timeout):
            coro.close()
            raise TimeoutError()

        monkeypatch.setattr("backend.app.core.honeypot.asyncio.wait_for", _timeout)

        engine = HoneypotEngine(port=0)
        writer = _FakeWriter()
        await engine.handle_client(_FakeReader([]), writer)  # must not raise
        assert writer.closed is True

    @pytest.mark.asyncio
    async def test_unexpected_exception_is_logged_and_writer_still_closed(self):
        class _BoomReader:
            async def read(self, n):
                raise RuntimeError("socket exploded")

        engine = HoneypotEngine(port=0)
        writer = _FakeWriter()
        await engine.handle_client(_BoomReader(), writer)  # must not raise
        assert writer.closed is True


class TestStartStop:
    @pytest.mark.asyncio
    async def test_start_generates_cert_and_binds_server(self, monkeypatch):
        engine = HoneypotEngine(host="127.0.0.1", port=8080)
        monkeypatch.setattr(engine, "_generate_self_signed_cert", AsyncMock())
        engine._cert_path = "/tmp/fake.crt"
        engine._key_path = "/tmp/fake.key"

        fake_ssl_context = MagicMock()
        monkeypatch.setattr(
            "backend.app.core.honeypot.ssl.create_default_context", MagicMock(return_value=fake_ssl_context)
        )
        start_server_mock = AsyncMock(return_value=MagicMock())
        monkeypatch.setattr("backend.app.core.honeypot.asyncio.start_server", start_server_mock)

        await engine.start()

        engine._generate_self_signed_cert.assert_awaited_once()
        fake_ssl_context.load_cert_chain.assert_called_once_with(certfile="/tmp/fake.crt", keyfile="/tmp/fake.key")
        start_server_mock.assert_awaited_once()
        assert engine._is_running is True

    @pytest.mark.asyncio
    async def test_start_is_idempotent(self, monkeypatch):
        engine = HoneypotEngine(port=0)
        gen_mock = AsyncMock()
        monkeypatch.setattr(engine, "_generate_self_signed_cert", gen_mock)
        monkeypatch.setattr("backend.app.core.honeypot.ssl.create_default_context", MagicMock())
        monkeypatch.setattr("backend.app.core.honeypot.asyncio.start_server", AsyncMock(return_value=MagicMock()))

        await engine.start()
        await engine.start()  # second call must be a no-op

        gen_mock.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_stop_closes_server_and_removes_temp_certs(self, tmp_path, monkeypatch):
        engine = HoneypotEngine(port=0)
        fake_server = MagicMock()
        fake_server.close = MagicMock()
        fake_server.wait_closed = AsyncMock()
        engine._server = fake_server
        engine._is_running = True

        cert_file = tmp_path / "fake.crt"
        key_file = tmp_path / "fake.key"
        cert_file.write_bytes(b"cert")
        key_file.write_bytes(b"key")
        engine._cert_path = str(cert_file)
        engine._key_path = str(key_file)

        await engine.stop()

        fake_server.close.assert_called_once()
        fake_server.wait_closed.assert_awaited_once()
        assert engine._is_running is False
        assert not cert_file.exists()
        assert not key_file.exists()

    @pytest.mark.asyncio
    async def test_stop_without_start_is_a_noop(self):
        engine = HoneypotEngine(port=0)
        await engine.stop()  # must not raise despite no server/certs
        assert engine._is_running is False
