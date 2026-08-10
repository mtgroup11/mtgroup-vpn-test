"""
MTGroup VPN Ultimate — Privileged Helper Client Test Suite
Tests backend/app/core/privileged_helper.py's request building, response
decoding, and error handling for both the async (`helper_request`) and
sync (`helper_request_sync`) clients — WITHOUT a real Unix socket, since
AF_UNIX isn't available in every dev/CI environment this might run in
(notably: not on this Windows sandbox at all). `asyncio.open_unix_connection`
and `socket.socket` are mocked instead.
"""

from __future__ import annotations

import asyncio
import json
import socket

import pytest

from backend.app.core import privileged_helper as ph


# ---------------------------------------------------------------------------
# Async client
# ---------------------------------------------------------------------------

class _FakeWriter:
    def __init__(self):
        self.written = b""
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written += data

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


class _FakeReader:
    def __init__(self, response: bytes):
        self._response = response

    async def readline(self) -> bytes:
        return self._response


@pytest.mark.asyncio
class TestHelperRequestAsync:
    async def test_sends_well_formed_json_request(self, monkeypatch):
        writer = _FakeWriter()
        reader = _FakeReader(b'{"ok":true,"message":"done"}\n')

        async def _fake_open(path, **kw):
            return reader, writer

        monkeypatch.setattr(asyncio, "open_unix_connection", _fake_open, raising=False)

        resp = await ph.helper_request("service.restart", {"service": "xray"})
        assert resp.ok is True
        assert resp.message == "done"

        sent = json.loads(writer.written.decode().strip())
        assert sent == {"operation": "service.restart", "payload": {"service": "xray"}}
        assert writer.closed is True

    async def test_response_with_data_field_is_parsed(self, monkeypatch):
        writer = _FakeWriter()
        reader = _FakeReader(b'{"ok":true,"message":"","data":{"linked":true}}\n')

        async def _fake_open(path, **kw):
            return reader, writer

        monkeypatch.setattr(asyncio, "open_unix_connection", _fake_open, raising=False)
        resp = await ph.helper_request("killswitch.status")
        assert resp.data == {"linked": True}

    async def test_connection_failure_raises_privileged_helper_error(self, monkeypatch):
        async def _fake_open(path, **kw):
            raise OSError("no such socket")

        monkeypatch.setattr(asyncio, "open_unix_connection", _fake_open, raising=False)
        with pytest.raises(ph.PrivilegedHelperError):
            await ph.helper_request("service.restart", {"service": "xray"})

    async def test_malformed_response_raises_privileged_helper_error(self, monkeypatch):
        writer = _FakeWriter()
        reader = _FakeReader(b"not json at all\n")

        async def _fake_open(path, **kw):
            return reader, writer

        monkeypatch.setattr(asyncio, "open_unix_connection", _fake_open, raising=False)
        with pytest.raises(ph.PrivilegedHelperError):
            await ph.helper_request("service.restart")

    async def test_empty_response_raises_privileged_helper_error(self, monkeypatch):
        writer = _FakeWriter()
        reader = _FakeReader(b"")

        async def _fake_open(path, **kw):
            return reader, writer

        monkeypatch.setattr(asyncio, "open_unix_connection", _fake_open, raising=False)
        with pytest.raises(ph.PrivilegedHelperError):
            await ph.helper_request("service.restart")

    async def test_oversized_request_rejected_before_any_connection(self, monkeypatch):
        called = False

        async def _fake_open(path, **kw):
            nonlocal called
            called = True
            raise AssertionError("should never connect for an oversized request")

        monkeypatch.setattr(asyncio, "open_unix_connection", _fake_open, raising=False)
        huge_payload = {"blob": "x" * (2 * 1024 * 1024)}
        with pytest.raises(ph.PrivilegedHelperError):
            await ph.helper_request("config.install", huge_payload)
        assert called is False


# ---------------------------------------------------------------------------
# Sync client
# ---------------------------------------------------------------------------

class _FakeSocket:
    def __init__(self, response: bytes):
        self._response = response
        self._sent = b""
        self.closed = False

    def settimeout(self, t):
        pass

    def connect(self, path):
        pass

    def sendall(self, data: bytes):
        self._sent += data

    def recv(self, n: int) -> bytes:
        chunk, self._response = self._response[:n], self._response[n:]
        return chunk

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _ensure_af_unix(monkeypatch):
    """AF_UNIX doesn't exist on every platform this test might run on
    (notably: not on Windows Python builds without it). `socket.socket`
    itself is mocked below, so the actual value doesn't matter — it just
    needs to exist as an attribute for `socket.AF_UNIX` to evaluate."""
    monkeypatch.setattr(socket, "AF_UNIX", getattr(socket, "AF_UNIX", 1), raising=False)


class TestHelperRequestSync:
    def test_sends_well_formed_json_request(self, monkeypatch):
        fake_sock = _FakeSocket(b'{"ok":true,"message":"done"}\n')
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: fake_sock)

        resp = ph.helper_request_sync("service.restart", {"service": "xray"})
        assert resp.ok is True
        assert resp.message == "done"
        sent = json.loads(fake_sock._sent.decode().strip())
        assert sent == {"operation": "service.restart", "payload": {"service": "xray"}}
        assert fake_sock.closed is True

    def test_connection_failure_raises_privileged_helper_error(self, monkeypatch):
        class _RefusingSocket(_FakeSocket):
            def connect(self, path):
                raise OSError("connection refused")

        monkeypatch.setattr(socket, "socket", lambda *a, **kw: _RefusingSocket(b""))
        with pytest.raises(ph.PrivilegedHelperError):
            ph.helper_request_sync("service.restart", {"service": "xray"})

    def test_socket_always_closed_even_on_error(self, monkeypatch):
        class _RefusingSocket(_FakeSocket):
            def connect(self, path):
                raise OSError("connection refused")

        sock = _RefusingSocket(b"")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: sock)
        with pytest.raises(ph.PrivilegedHelperError):
            ph.helper_request_sync("service.restart")
        assert sock.closed is True
