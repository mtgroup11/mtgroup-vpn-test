"""
MTGroup VPN Ultimate — SNI Routing Engine Test Suite
Tests backend/app/core/routing_engine.py's TLS ClientHello parser (pure,
byte-level — no mocking needed), SNIRouteTable (pure async, no I/O),
DecoyReverseProxy (httpx mocked via MockTransport, no real network calls),
SNIMultiplexer (asyncio streams faked in-process, no real sockets), and
the pure DPI-evasion preset generator functions.
"""

from __future__ import annotations

import struct
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from backend.app.core.routing_engine import (
    DecoyResponse,
    DecoyReverseProxy,
    RouteAction,
    RouteEntry,
    SNIMultiplexer,
    SNIRouteTable,
    TLSParseError,
    _compute_ja3_string,
    _parse_alpn_extension,
    _parse_sni_extension,
    apply_dpi_evasion_to_outbound,
    generate_fragment_block,
    generate_noise_block,
    get_preset_config,
    parse_client_hello,
)


# ---------------------------------------------------------------------------
# TLS ClientHello builder — constructs real, spec-shaped byte sequences so
# the parser is exercised exactly as it would be against live traffic.
# ---------------------------------------------------------------------------

def _sni_extension(hostname: str) -> bytes:
    name = hostname.encode("ascii")
    entry = struct.pack("!B", 0x00) + struct.pack("!H", len(name)) + name
    server_name_list = struct.pack("!H", len(entry)) + entry
    return struct.pack("!HH", 0x0000, len(server_name_list)) + server_name_list


def _alpn_extension(protocols: list[str]) -> bytes:
    entries = b"".join(struct.pack("!B", len(p)) + p.encode("ascii") for p in protocols)
    proto_list = struct.pack("!H", len(entries)) + entries
    return struct.pack("!HH", 0x0010, len(proto_list)) + proto_list


def build_client_hello(
    *,
    version: int = 0x0303,
    sni: str | None = "example.com",
    cipher_suites: tuple[int, ...] = (0x1301, 0x1302, 0xC02F),
    alpn_protocols: list[str] | None = None,
    extra_extensions: bytes = b"",
    truncate_to: int | None = None,
) -> bytes:
    extensions = b""
    if sni is not None:
        extensions += _sni_extension(sni)
    if alpn_protocols:
        extensions += _alpn_extension(alpn_protocols)
    extensions += extra_extensions

    client_random = b"\x00" * 32
    session_id = b""
    cs_bytes = b"".join(struct.pack("!H", cs) for cs in cipher_suites)
    comp_methods = b"\x00"

    body = (
        struct.pack("!H", version)
        + client_random
        + struct.pack("!B", len(session_id)) + session_id
        + struct.pack("!H", len(cs_bytes)) + cs_bytes
        + struct.pack("!B", len(comp_methods)) + comp_methods
        + struct.pack("!H", len(extensions)) + extensions
    )

    handshake = struct.pack("!B", 0x01) + struct.pack("!I", len(body))[1:] + body
    record = (
        struct.pack("!B", 0x16)
        + struct.pack("!H", version)
        + struct.pack("!H", len(handshake))
        + handshake
    )
    if truncate_to is not None:
        record = record[:truncate_to]
    return record


# ---------------------------------------------------------------------------
# parse_client_hello
# ---------------------------------------------------------------------------

class TestParseClientHello:
    def test_extracts_sni(self):
        info = parse_client_hello(build_client_hello(sni="vpn.example.com"))
        assert info.sni == "vpn.example.com"

    def test_sni_is_lowercased(self):
        info = parse_client_hello(build_client_hello(sni="VPN.Example.COM"))
        assert info.sni == "vpn.example.com"

    def test_no_sni_extension_yields_none(self):
        info = parse_client_hello(build_client_hello(sni=None))
        assert info.sni is None

    def test_extracts_tls_version(self):
        info = parse_client_hello(build_client_hello(version=0x0303))
        assert info.tls_version == 0x0303

    def test_extracts_cipher_suites(self):
        info = parse_client_hello(build_client_hello(cipher_suites=(0x1301, 0x1302)))
        assert info.cipher_suites == (0x1301, 0x1302)

    def test_extracts_alpn_protocols(self):
        info = parse_client_hello(build_client_hello(alpn_protocols=["h2", "http/1.1"]))
        assert info.has_alpn is True
        assert info.alpn_protocols == ("h2", "http/1.1")

    def test_no_alpn_extension(self):
        info = parse_client_hello(build_client_hello(alpn_protocols=None))
        assert info.has_alpn is False
        assert info.alpn_protocols == ()

    def test_ja3_hash_is_32_char_hex(self):
        info = parse_client_hello(build_client_hello())
        assert len(info.ja3_hash) == 32
        int(info.ja3_hash, 16)  # must be valid hex

    def test_same_hello_produces_same_ja3(self):
        a = parse_client_hello(build_client_hello(cipher_suites=(0x1301, 0x1302)))
        b = parse_client_hello(build_client_hello(cipher_suites=(0x1301, 0x1302)))
        assert a.ja3_hash == b.ja3_hash

    def test_different_cipher_suites_produce_different_ja3(self):
        a = parse_client_hello(build_client_hello(cipher_suites=(0x1301,)))
        b = parse_client_hello(build_client_hello(cipher_suites=(0x1301, 0xC02F)))
        assert a.ja3_hash != b.ja3_hash

    def test_raw_length_matches_record_size(self):
        hello = build_client_hello()
        info = parse_client_hello(hello)
        assert info.raw_length == len(hello)

    def test_rejects_too_short_input(self):
        with pytest.raises(TLSParseError):
            parse_client_hello(b"\x16\x03")

    def test_rejects_non_handshake_content_type(self):
        data = bytearray(build_client_hello())
        data[0] = 0x17  # application_data, not handshake
        with pytest.raises(TLSParseError):
            parse_client_hello(bytes(data))

    def test_rejects_incomplete_record(self):
        hello = build_client_hello()
        with pytest.raises(TLSParseError):
            parse_client_hello(hello[:20])  # record header claims more than we give it

    def test_rejects_non_client_hello_handshake_type(self):
        data = bytearray(build_client_hello())
        data[5] = 0x02  # ServerHello, not ClientHello
        with pytest.raises(TLSParseError):
            parse_client_hello(bytes(data))

    def test_handles_extra_unrecognised_extensions_without_error(self):
        # A random, unrecognised extension type must be skipped, not fatal.
        unknown_ext = struct.pack("!HH", 0x002B, 4) + b"\x00\x00\x00\x00"
        info = parse_client_hello(build_client_hello(sni="ok.example.com", extra_extensions=unknown_ext))
        assert info.sni == "ok.example.com"


class TestParseSniExtension:
    def test_returns_none_on_truncated_data(self):
        assert _parse_sni_extension(b"\x00") is None

    def test_returns_none_on_non_ascii(self):
        # name_len says 4 bytes but they're not valid ascii-decodable in a
        # way that matters — use bytes that fail ascii decoding outright.
        ext = struct.pack("!H", 5) + struct.pack("!B", 0x00) + struct.pack("!H", 2) + b"\xff\xfe"
        assert _parse_sni_extension(ext) is None


class TestParseAlpnExtension:
    def test_empty_data_returns_empty_list(self):
        assert _parse_alpn_extension(b"") == []

    def test_stops_gracefully_on_truncated_protocol(self):
        # Declares a protocol longer than the remaining bytes.
        ext = struct.pack("!H", 10) + struct.pack("!B", 20) + b"short"
        assert _parse_alpn_extension(ext) == []


class TestComputeJa3String:
    def test_filters_grease_values(self):
        # GREASE cipher suites follow the 0x?a?a pattern (RFC 8701) and
        # must never leak into the JA3 string — they're randomised per
        # connection and would make the fingerprint useless if included.
        grease_and_real = [0x0A0A, 0x1301, 0x2A2A]
        result = _compute_ja3_string(0x0303, grease_and_real, [])
        assert "2570" not in result  # 0x0A0A = 2570
        assert "10794" not in result  # 0x2A2A = 10794
        assert "4865" in result  # 0x1301 = 4865


# ---------------------------------------------------------------------------
# SNIRouteTable
# ---------------------------------------------------------------------------

class TestSNIRouteTable:
    @pytest.mark.asyncio
    async def test_exact_match_takes_priority_over_wildcard(self):
        table = SNIRouteTable()
        await table.add_route(RouteEntry(sni_pattern="*.example.com", backend_port=1))
        await table.add_route(RouteEntry(sni_pattern="vpn.example.com", backend_port=2))

        match = await table.lookup("vpn.example.com")
        assert match.entry.backend_port == 2

    @pytest.mark.asyncio
    async def test_wildcard_match(self):
        table = SNIRouteTable()
        await table.add_route(RouteEntry(sni_pattern="*.example.com", backend_port=5))

        match = await table.lookup("anything.example.com")
        assert match.action == RouteAction.PROXY_BACKEND
        assert match.entry.backend_port == 5

    @pytest.mark.asyncio
    async def test_unmatched_sni_defaults_to_decoy(self):
        table = SNIRouteTable()
        match = await table.lookup("unknown.example.com")
        assert match.action == RouteAction.DECOY_REVERSE
        assert match.entry is None

    @pytest.mark.asyncio
    async def test_none_sni_defaults_to_decoy(self):
        table = SNIRouteTable()
        match = await table.lookup(None)
        assert match.action == RouteAction.DECOY_REVERSE
        assert match.matched_sni is None

    @pytest.mark.asyncio
    async def test_lookup_is_case_insensitive(self):
        table = SNIRouteTable()
        await table.add_route(RouteEntry(sni_pattern="VPN.Example.com"))
        match = await table.lookup("vpn.example.com")
        assert match.action == RouteAction.PROXY_BACKEND

    @pytest.mark.asyncio
    async def test_connection_limit_deflects_to_decoy(self):
        table = SNIRouteTable()
        await table.add_route(RouteEntry(sni_pattern="limited.example.com", max_connections=1))
        await table.increment_connections("limited.example.com")

        match = await table.lookup("limited.example.com")
        assert match.action == RouteAction.DECOY_REVERSE

    @pytest.mark.asyncio
    async def test_decrement_never_goes_negative(self):
        table = SNIRouteTable()
        await table.decrement_connections("never-incremented.example.com")
        stats = await table.get_stats()
        assert stats["active_connections"] == {}

    @pytest.mark.asyncio
    async def test_remove_route_exact(self):
        table = SNIRouteTable()
        await table.add_route(RouteEntry(sni_pattern="vpn.example.com"))
        assert await table.remove_route("vpn.example.com") is True
        match = await table.lookup("vpn.example.com")
        assert match.action == RouteAction.DECOY_REVERSE

    @pytest.mark.asyncio
    async def test_remove_route_returns_false_when_not_found(self):
        table = SNIRouteTable()
        assert await table.remove_route("nope.example.com") is False

    @pytest.mark.asyncio
    async def test_wildcard_priority_ordering(self):
        table = SNIRouteTable()
        await table.add_route(RouteEntry(sni_pattern="*.example.com", backend_port=1, priority=200))
        await table.add_route(RouteEntry(sni_pattern="*.example.com", backend_port=2, priority=10))
        # Lower priority number wins — both match, the higher-priority
        # (lower number) route must be picked first.
        match = await table.lookup("foo.example.com")
        assert match.entry.backend_port == 2

    @pytest.mark.asyncio
    async def test_get_stats_reports_route_counts(self):
        table = SNIRouteTable()
        await table.add_route(RouteEntry(sni_pattern="exact.example.com"))
        await table.add_route(RouteEntry(sni_pattern="*.wild.example.com"))
        stats = await table.get_stats()
        assert stats["exact_routes"] == 1
        assert stats["wildcard_routes"] == 1


# ---------------------------------------------------------------------------
# DecoyReverseProxy
# ---------------------------------------------------------------------------

class TestDecoyReverseProxy:
    @pytest.mark.asyncio
    async def test_fetch_returns_upstream_response(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Server": "nginx", "X-Powered-By": "PHP"}, content=b"<html>hi</html>")

        proxy = DecoyReverseProxy(target_url="https://decoy.example.com")
        proxy._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            resp = await proxy.fetch_decoy_response("/")
            assert resp.status_code == 200
            assert resp.body == b"<html>hi</html>"
            # Fingerprinting headers must be stripped/replaced. Header keys
            # may come back in whatever casing httpx's Headers object uses
            # internally, so compare case-insensitively.
            lowered = {k.lower(): v for k, v in resp.headers.items()}
            assert lowered["server"] == "Microsoft-IIS/10.0"
            assert "x-powered-by" not in lowered
        finally:
            await proxy._client.aclose()

    @pytest.mark.asyncio
    async def test_response_is_cached_within_ttl(self):
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(200, content=b"cached-body")

        proxy = DecoyReverseProxy(target_url="https://decoy.example.com")
        proxy._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            await proxy.fetch_decoy_response("/")
            await proxy.fetch_decoy_response("/")
            assert call_count == 1  # second call served from cache
        finally:
            await proxy._client.aclose()

    @pytest.mark.asyncio
    async def test_timeout_returns_fallback_not_raise(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("slow upstream")

        proxy = DecoyReverseProxy(target_url="https://decoy.example.com")
        proxy._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            resp = await proxy.fetch_decoy_response("/")
            assert resp.status_code == 503
            assert b"Microsoft" in resp.body
        finally:
            await proxy._client.aclose()

    @pytest.mark.asyncio
    async def test_http_error_returns_fallback_not_raise(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        proxy = DecoyReverseProxy(target_url="https://decoy.example.com")
        proxy._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            resp = await proxy.fetch_decoy_response("/")
            assert resp.status_code == 503
        finally:
            await proxy._client.aclose()

    def test_get_stats_computes_error_rate(self):
        proxy = DecoyReverseProxy()
        proxy._total_requests = 4
        proxy._total_errors = 1
        stats = proxy.get_stats()
        assert stats["error_rate_pct"] == 25.0

    def test_get_stats_with_zero_requests_does_not_divide_by_zero(self):
        proxy = DecoyReverseProxy()
        stats = proxy.get_stats()
        assert stats["error_rate_pct"] == 0.0


# ---------------------------------------------------------------------------
# SNIMultiplexer — fake asyncio streams, no real sockets
# ---------------------------------------------------------------------------

class _FakeReader:
    """Minimal asyncio.StreamReader stand-in fed from a list of chunks."""

    def __init__(self, chunks: list[bytes]):
        self._chunks = list(chunks)

    async def read(self, n: int) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        return b""


class _FakeWriter:
    """Minimal asyncio.StreamWriter stand-in that records what it's sent."""

    def __init__(self, peer: tuple[str, int] | None = ("203.0.113.5", 54321)):
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


def _client_hello_bytes(sni: str = "vpn.example.com") -> bytes:
    return build_client_hello(sni=sni)


class TestSNIMultiplexerBackendManagement:
    @pytest.mark.asyncio
    async def test_add_backend_registers_route(self):
        mux = SNIMultiplexer(listen_port=0)
        await mux.add_backend("vpn.example.com", backend_port=9443, protocol_tag="vless")
        match = await mux._route_table.lookup("vpn.example.com")
        assert match.action == RouteAction.PROXY_BACKEND
        assert match.entry.backend_port == 9443

    @pytest.mark.asyncio
    async def test_remove_backend_unregisters_route(self):
        mux = SNIMultiplexer(listen_port=0)
        await mux.add_backend("vpn.example.com")
        assert await mux.remove_backend("vpn.example.com") is True
        match = await mux._route_table.lookup("vpn.example.com")
        assert match.action == RouteAction.DECOY_REVERSE

    @pytest.mark.asyncio
    async def test_get_stats_reports_counters_and_nested_stats(self):
        mux = SNIMultiplexer(listen_port=0)
        stats = await mux.get_stats()
        assert stats["total_connections"] == 0
        assert "routing" in stats
        assert "decoy" in stats


class TestSNIMultiplexerStartStop:
    @pytest.mark.asyncio
    async def test_start_creates_server_and_initializes_decoy(self, monkeypatch):
        mux = SNIMultiplexer(listen_port=0)
        fake_server = MagicMock()
        fake_sock = MagicMock()
        fake_sock.getsockname.return_value = ("0.0.0.0", 443)
        fake_server.sockets = [fake_sock]

        start_server_mock = AsyncMock(return_value=fake_server)
        monkeypatch.setattr("backend.app.core.routing_engine.asyncio.start_server", start_server_mock)
        monkeypatch.setattr(mux._decoy_proxy, "initialize", AsyncMock())

        await mux.start()

        start_server_mock.assert_awaited_once()
        mux._decoy_proxy.initialize.assert_awaited_once()
        assert mux._server is fake_server

    @pytest.mark.asyncio
    async def test_stop_closes_server_and_decoy(self, monkeypatch):
        mux = SNIMultiplexer(listen_port=0)
        fake_server = MagicMock()
        fake_server.close = MagicMock()
        fake_server.wait_closed = AsyncMock()
        mux._server = fake_server
        monkeypatch.setattr(mux._decoy_proxy, "close", AsyncMock())

        await mux.stop()

        fake_server.close.assert_called_once()
        fake_server.wait_closed.assert_awaited_once()
        mux._decoy_proxy.close.assert_awaited_once()
        assert mux._server is None

    @pytest.mark.asyncio
    async def test_stop_without_start_is_a_noop(self, monkeypatch):
        mux = SNIMultiplexer(listen_port=0)
        monkeypatch.setattr(mux._decoy_proxy, "close", AsyncMock())
        await mux.stop()  # must not raise despite _server being None
        mux._decoy_proxy.close.assert_awaited_once()


class TestSNIMultiplexerPipe:
    @pytest.mark.asyncio
    async def test_pipe_copies_all_chunks_until_eof(self):
        reader = _FakeReader([b"hello ", b"world"])
        writer = _FakeWriter()
        await SNIMultiplexer._pipe(reader, writer, "test")
        assert bytes(writer.written) == b"hello world"

    @pytest.mark.asyncio
    async def test_pipe_swallows_connection_errors(self):
        class _BoomReader:
            async def read(self, n):
                raise ConnectionResetError("peer gone")

        writer = _FakeWriter()
        await SNIMultiplexer._pipe(_BoomReader(), writer, "test")  # must not raise


class TestSNIMultiplexerDeflectAndTarpit:
    @pytest.mark.asyncio
    async def test_deflect_to_decoy_writes_http_response(self, monkeypatch):
        mux = SNIMultiplexer(listen_port=0)
        fake_response = DecoyResponse(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=b"<html>decoy</html>",
            target_url="https://decoy.example.com/",
        )
        monkeypatch.setattr(mux._decoy_proxy, "fetch_decoy_response", AsyncMock(return_value=fake_response))

        writer = _FakeWriter()
        await mux._deflect_to_decoy(writer, "probe-context")

        sent = bytes(writer.written)
        assert sent.startswith(b"HTTP/1.1 200 OK\r\n")
        assert b"<html>decoy</html>" in sent

    @pytest.mark.asyncio
    async def test_deflect_to_decoy_swallows_write_errors(self, monkeypatch):
        mux = SNIMultiplexer(listen_port=0)
        fake_response = DecoyResponse(status_code=200, headers={}, body=b"x", target_url="https://d/")
        monkeypatch.setattr(mux._decoy_proxy, "fetch_decoy_response", AsyncMock(return_value=fake_response))

        writer = _FakeWriter()
        writer.write = MagicMock(side_effect=BrokenPipeError())
        await mux._deflect_to_decoy(writer, "ctx")  # must not raise

    @pytest.mark.asyncio
    async def test_tarpit_drips_bytes_then_closes_with_zero_chunk(self, monkeypatch):
        sleep_mock = AsyncMock()
        monkeypatch.setattr("backend.app.core.routing_engine.asyncio.sleep", sleep_mock)

        writer = _FakeWriter()
        await SNIMultiplexer._tarpit_connection(writer, "scanner-ctx")

        assert sleep_mock.await_count == 12
        assert bytes(writer.written).endswith(b"0\r\n\r\n")
        assert bytes(writer.written).startswith(b"HTTP/1.1 200 OK\r\n")

    @pytest.mark.asyncio
    async def test_tarpit_swallows_connection_errors(self, monkeypatch):
        monkeypatch.setattr("backend.app.core.routing_engine.asyncio.sleep", AsyncMock())
        writer = _FakeWriter()
        writer.write = MagicMock(side_effect=ConnectionResetError())
        await SNIMultiplexer._tarpit_connection(writer, "ctx")  # must not raise


class TestSNIMultiplexerForwardToBackend:
    @pytest.mark.asyncio
    async def test_forwards_replayed_hello_and_pipes_both_directions(self, monkeypatch):
        mux = SNIMultiplexer(listen_port=0)
        entry = RouteEntry(sni_pattern="vpn.example.com", backend_host="127.0.0.1", backend_port=10443)

        backend_reader = _FakeReader([b"backend-reply"])
        backend_writer = _FakeWriter()
        open_connection_mock = AsyncMock(return_value=(backend_reader, backend_writer))
        monkeypatch.setattr("backend.app.core.routing_engine.asyncio.open_connection", open_connection_mock)

        client_reader = _FakeReader([])  # client sends nothing more after the hello
        client_writer = _FakeWriter()

        await mux._forward_to_backend(client_reader, client_writer, b"HELLO-BYTES", entry, "vpn.example.com")

        # The already-consumed ClientHello bytes must be replayed to the backend first.
        assert bytes(backend_writer.written).startswith(b"HELLO-BYTES")
        # And the backend's reply must have been piped back to the client.
        assert bytes(client_writer.written) == b"backend-reply"
        assert backend_writer.closed is True

    @pytest.mark.asyncio
    async def test_connect_failure_falls_back_to_decoy(self, monkeypatch):
        mux = SNIMultiplexer(listen_port=0)
        entry = RouteEntry(sni_pattern="vpn.example.com", backend_host="127.0.0.1", backend_port=10443)

        monkeypatch.setattr(
            "backend.app.core.routing_engine.asyncio.open_connection",
            AsyncMock(side_effect=OSError("connection refused")),
        )
        deflect_mock = AsyncMock()
        monkeypatch.setattr(mux, "_deflect_to_decoy", deflect_mock)

        client_writer = _FakeWriter()
        await mux._forward_to_backend(_FakeReader([]), client_writer, b"HELLO", entry, "vpn.example.com")

        deflect_mock.assert_awaited_once()


class TestSNIMultiplexerHandleConnection:
    @pytest.mark.asyncio
    async def test_empty_connection_returns_early(self):
        mux = SNIMultiplexer(listen_port=0)
        reader = _FakeReader([b""])
        writer = _FakeWriter()
        await mux._handle_connection(reader, writer)
        assert mux._active_connections == 0  # incremented then decremented in finally

    @pytest.mark.asyncio
    async def test_matched_sni_forwards_to_backend(self, monkeypatch):
        mux = SNIMultiplexer(listen_port=0)
        await mux.add_backend("vpn.example.com", backend_port=9443)
        forward_mock = AsyncMock()
        monkeypatch.setattr(mux, "_forward_to_backend", forward_mock)

        reader = _FakeReader([_client_hello_bytes("vpn.example.com")])
        writer = _FakeWriter()
        await mux._handle_connection(reader, writer)

        forward_mock.assert_awaited_once()
        assert mux._total_backend_forwards == 1

    @pytest.mark.asyncio
    async def test_unmatched_sni_deflects_to_decoy(self, monkeypatch):
        mux = SNIMultiplexer(listen_port=0)
        deflect_mock = AsyncMock()
        monkeypatch.setattr(mux, "_deflect_to_decoy", deflect_mock)

        reader = _FakeReader([_client_hello_bytes("unknown.example.com")])
        writer = _FakeWriter()
        await mux._handle_connection(reader, writer)

        deflect_mock.assert_awaited_once()
        assert mux._total_decoy_deflections == 1

    @pytest.mark.asyncio
    async def test_drop_action_increments_drops_without_deflecting(self, monkeypatch):
        mux = SNIMultiplexer(listen_port=0)
        await mux._route_table.add_route(RouteEntry(sni_pattern="banned.example.com", action=RouteAction.DROP))
        deflect_mock = AsyncMock()
        monkeypatch.setattr(mux, "_deflect_to_decoy", deflect_mock)

        reader = _FakeReader([_client_hello_bytes("banned.example.com")])
        writer = _FakeWriter()
        await mux._handle_connection(reader, writer)

        assert mux._total_drops == 1
        deflect_mock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_tarpit_action_invokes_tarpit(self, monkeypatch):
        mux = SNIMultiplexer(listen_port=0)
        await mux._route_table.add_route(RouteEntry(sni_pattern="scanner.example.com", action=RouteAction.TARPIT))
        tarpit_mock = AsyncMock()
        monkeypatch.setattr(mux, "_tarpit_connection", tarpit_mock)

        reader = _FakeReader([_client_hello_bytes("scanner.example.com")])
        writer = _FakeWriter()
        await mux._handle_connection(reader, writer)

        tarpit_mock.assert_awaited_once()
        assert mux._total_drops == 1

    @pytest.mark.asyncio
    async def test_unparseable_data_still_deflects_to_decoy(self, monkeypatch):
        mux = SNIMultiplexer(listen_port=0)
        deflect_mock = AsyncMock()
        monkeypatch.setattr(mux, "_deflect_to_decoy", deflect_mock)

        reader = _FakeReader([b"not a tls client hello at all"])
        writer = _FakeWriter()
        await mux._handle_connection(reader, writer)

        assert mux._total_parse_failures == 1
        deflect_mock.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_read_timeout_increments_parse_failures_and_returns(self, monkeypatch):
        mux = SNIMultiplexer(listen_port=0)

        async def _timeout(coro, timeout):
            coro.close()  # avoid an unawaited-coroutine warning from the real reader.read()
            raise TimeoutError()

        monkeypatch.setattr("backend.app.core.routing_engine.asyncio.wait_for", _timeout)
        reader = _FakeReader([])
        writer = _FakeWriter()
        await mux._handle_connection(reader, writer)
        assert mux._total_parse_failures == 1

    @pytest.mark.asyncio
    async def test_unhandled_exception_is_logged_not_raised(self, monkeypatch):
        mux = SNIMultiplexer(listen_port=0)
        monkeypatch.setattr(
            mux._route_table, "lookup", AsyncMock(side_effect=RuntimeError("boom"))
        )
        reader = _FakeReader([_client_hello_bytes("vpn.example.com")])
        writer = _FakeWriter()
        await mux._handle_connection(reader, writer)  # must not raise
        assert writer.closed is True


# ---------------------------------------------------------------------------
# DPI Evasion Preset Generator (pure functions)
# ---------------------------------------------------------------------------

class TestGenerateFragmentBlock:
    def test_dpi_resistant_preset(self):
        block = generate_fragment_block("DPI_Resistant")
        assert block == {"packets": "1-3", "length": "100-200", "interval": "10-20"}

    def test_low_latency_gaming_preset(self):
        block = generate_fragment_block("Low_Latency_Gaming")
        assert block["packets"] == "tlshello"

    def test_unknown_preset_returns_empty(self):
        assert generate_fragment_block("Ultra_Stable") == {}
        assert generate_fragment_block("nonsense") == {}


class TestGenerateNoiseBlock:
    def test_dpi_resistant_preset(self):
        block = generate_noise_block("DPI_Resistant")
        assert block["type"] == "rand"
        assert block["noise_payload_size"] == "500-1500"

    def test_low_latency_gaming_preset(self):
        block = generate_noise_block("Low_Latency_Gaming")
        assert block["noise_payload_size"] == "100-300"

    def test_unknown_preset_returns_empty(self):
        assert generate_noise_block("Ultra_Stable") == {}


class TestGetPresetConfig:
    def test_dpi_resistant(self):
        cfg = get_preset_config("DPI_Resistant")
        assert cfg["utls"]["enabled"] is True
        assert cfg["mux"]["enabled"] is False

    def test_low_latency_gaming(self):
        cfg = get_preset_config("Low_Latency_Gaming")
        assert cfg["mux"]["enabled"] is True
        assert cfg["udp_priority"] is True

    def test_default_is_ultra_stable(self):
        cfg = get_preset_config("anything-else")
        assert cfg["mode"] == "Ultra_Stable"
        assert cfg["utls"]["enabled"] is False


class TestApplyDpiEvasionToOutbound:
    def test_dpi_resistant_injects_fragment_outbound_and_dialer_proxy(self):
        outbound = {"tag": "main", "streamSettings": {}}
        result = apply_dpi_evasion_to_outbound(outbound, "DPI_Resistant")

        assert len(result) == 2  # main outbound + fragment-out
        assert result[1]["tag"] == "fragment-out"
        assert outbound["streamSettings"]["sockopt"]["dialerProxy"] == "fragment-out"
        assert outbound["noise"]["type"] == "rand"
        assert outbound["streamSettings"]["tlsSettings"]["fingerprint"] == "chrome"

    def test_ultra_stable_leaves_outbound_list_unchanged(self):
        outbound = {"tag": "main", "streamSettings": {}}
        result = apply_dpi_evasion_to_outbound(outbound, "Ultra_Stable")

        assert len(result) == 1  # no fragment outbound injected
        assert "noise" not in outbound
        assert outbound["mux"] == {"enabled": False}

    def test_low_latency_gaming_enables_mux_without_utls(self):
        outbound = {"tag": "main", "streamSettings": {}}
        apply_dpi_evasion_to_outbound(outbound, "Low_Latency_Gaming")
        assert outbound["mux"]["enabled"] is True
        assert "tlsSettings" not in outbound["streamSettings"]
