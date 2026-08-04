"""
MTGroup VPN Ultimate — SNI Multiplexer & Active Probe Deflection Engine

This module implements a production-grade TLS-aware routing engine that:

1. **Parses TLS ClientHello** from raw TCP byte streams to extract the
   Server Name Indication (SNI) extension.
2. **Routes matching SNI** values to the appropriate Xray-core / Sing-box
   backend over a local loopback socket.
3. **Deflects unrecognised SNI / active probes** by reverse-proxying
   them to a legitimate decoy website (default: ``microsoft.com``)
   so that GFW / Filternet active probers see a real webpage, not a
   VPN handshake.

Architecture::

    ┌──────────────┐
    │  Internet    │
    │  (DPI/GFW)   │
    └──────┬───────┘
           │ raw TLS ClientHello
    ┌──────▼───────────────────────────────────────────┐
    │               SNIMultiplexer                     │
    │  ┌────────────────────────────────────────────┐  │
    │  │  TLS ClientHello Parser                    │  │
    │  │  → extract SNI from extension 0x0000       │  │
    │  └────────────────┬───────────────────────────┘  │
    │                   │                              │
    │         ┌─────────▼──────────┐                   │
    │         │  Route Table Lookup │                   │
    │         └──┬──────────────┬──┘                   │
    │   match ✓  │              │  match ✗             │
    │   ┌────────▼──────┐  ┌───▼──────────────────┐   │
    │   │ Backend Proxy  │  │ DecoyReverseProxy    │   │
    │   │ (xray/singbox) │  │ → microsoft.com      │   │
    │   └───────────────┘  └──────────────────────┘   │
    └─────────────────────────────────────────────────┘
"""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Optional

import httpx

logger = logging.getLogger("mtgroup.core.routing_engine")


# ═══════════════════════════════════════════════════════════════════════════
# TLS ClientHello Parser
# ═══════════════════════════════════════════════════════════════════════════

# TLS record & handshake constants
_TLS_CONTENT_TYPE_HANDSHAKE: int = 0x16
_TLS_HANDSHAKE_TYPE_CLIENT_HELLO: int = 0x01
_TLS_EXTENSION_SNI: int = 0x0000
_TLS_SNI_TYPE_HOSTNAME: int = 0x00

# Supported TLS versions in the record layer
_SUPPORTED_TLS_VERSIONS: frozenset[int] = frozenset({
    0x0301,  # TLS 1.0
    0x0302,  # TLS 1.1
    0x0303,  # TLS 1.2
    0x0304,  # TLS 1.3 (record layer still uses 0x0303 usually)
})


@dataclass(frozen=True)
class TLSClientHelloInfo:
    """Parsed metadata from a TLS ClientHello message."""
    sni: Optional[str]
    tls_version: int
    cipher_suites: tuple[int, ...]
    extensions: tuple[int, ...]
    has_alpn: bool
    alpn_protocols: tuple[str, ...]
    ja3_hash: str
    raw_length: int


class TLSParseError(Exception):
    """Raised when the TLS ClientHello cannot be parsed."""


def parse_client_hello(data: bytes) -> TLSClientHelloInfo:
    """
    Parse a TLS ClientHello from raw TCP bytes and extract metadata.

    This parser handles the full TLS record structure:

    - TLS Record Header (5 bytes): content_type, version, length
    - Handshake Header (4 bytes): type, length (3-byte big-endian)
    - ClientHello body: version, random, session_id, cipher_suites,
      compression_methods, extensions

    Within extensions, we specifically extract:
    - **SNI** (0x0000): Server Name Indication
    - **ALPN** (0x0010): Application-Layer Protocol Negotiation

    Args:
        data: Raw bytes from the TCP stream (minimum ~43 bytes for a
              bare-minimum ClientHello).

    Returns:
        A ``TLSClientHelloInfo`` with all parsed fields.

    Raises:
        TLSParseError: If the bytes do not form a valid ClientHello.
    """
    if len(data) < 5:
        raise TLSParseError(
            f"Data too short for TLS record header: {len(data)} bytes"
        )

    # ── TLS Record Header ─────────────────────────────────────────────
    content_type = data[0]
    if content_type != _TLS_CONTENT_TYPE_HANDSHAKE:
        raise TLSParseError(
            f"Not a TLS Handshake record: content_type=0x{content_type:02X}"
        )

    struct.unpack("!H", data[1:3])[0]
    record_length = struct.unpack("!H", data[3:5])[0]

    if len(data) < 5 + record_length:
        raise TLSParseError(
            f"Incomplete TLS record: need {5 + record_length} bytes, "
            f"have {len(data)}"
        )

    payload = data[5 : 5 + record_length]
    pos = 0

    # ── Handshake Header ──────────────────────────────────────────────
    if len(payload) < 4:
        raise TLSParseError("Handshake header too short")

    handshake_type = payload[0]
    if handshake_type != _TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
        raise TLSParseError(
            f"Not a ClientHello: handshake_type=0x{handshake_type:02X}"
        )

    handshake_length = struct.unpack("!I", b"\x00" + payload[1:4])[0]
    pos = 4

    if len(payload) < 4 + handshake_length:
        raise TLSParseError("Incomplete ClientHello body")

    # ── Client Version ────────────────────────────────────────────────
    if pos + 2 > len(payload):
        raise TLSParseError("Cannot read client version")
    client_version = struct.unpack("!H", payload[pos : pos + 2])[0]
    pos += 2

    # ── Client Random (32 bytes) ──────────────────────────────────────
    if pos + 32 > len(payload):
        raise TLSParseError("Cannot read client random")
    payload[pos : pos + 32]
    pos += 32

    # ── Session ID ────────────────────────────────────────────────────
    if pos + 1 > len(payload):
        raise TLSParseError("Cannot read session ID length")
    session_id_len = payload[pos]
    pos += 1
    if pos + session_id_len > len(payload):
        raise TLSParseError("Session ID extends past payload")
    pos += session_id_len  # skip session ID bytes

    # ── Cipher Suites ─────────────────────────────────────────────────
    if pos + 2 > len(payload):
        raise TLSParseError("Cannot read cipher suites length")
    cipher_suites_len = struct.unpack("!H", payload[pos : pos + 2])[0]
    pos += 2
    if pos + cipher_suites_len > len(payload):
        raise TLSParseError("Cipher suites extend past payload")

    cipher_suites: list[int] = []
    cs_end = pos + cipher_suites_len
    while pos + 2 <= cs_end:
        suite = struct.unpack("!H", payload[pos : pos + 2])[0]
        cipher_suites.append(suite)
        pos += 2

    # ── Compression Methods ───────────────────────────────────────────
    if pos + 1 > len(payload):
        raise TLSParseError("Cannot read compression methods length")
    comp_methods_len = payload[pos]
    pos += 1
    if pos + comp_methods_len > len(payload):
        raise TLSParseError("Compression methods extend past payload")
    pos += comp_methods_len

    # ── Extensions ────────────────────────────────────────────────────
    sni: Optional[str] = None
    has_alpn = False
    alpn_protocols: list[str] = []
    extension_ids: list[int] = []

    if pos + 2 <= len(payload):
        extensions_len = struct.unpack("!H", payload[pos : pos + 2])[0]
        pos += 2
        ext_end = pos + extensions_len

        while pos + 4 <= ext_end:
            ext_type = struct.unpack("!H", payload[pos : pos + 2])[0]
            ext_len = struct.unpack("!H", payload[pos + 2 : pos + 4])[0]
            ext_data = payload[pos + 4 : pos + 4 + ext_len]
            extension_ids.append(ext_type)

            if ext_type == _TLS_EXTENSION_SNI and len(ext_data) >= 5:
                sni = _parse_sni_extension(ext_data)

            if ext_type == 0x0010 and len(ext_data) >= 2:
                has_alpn = True
                alpn_protocols = _parse_alpn_extension(ext_data)

            pos += 4 + ext_len

    # ── JA3 Fingerprint ───────────────────────────────────────────────
    ja3_string = _compute_ja3_string(
        client_version, cipher_suites, extension_ids,
    )
    import hashlib
    ja3_hash = hashlib.md5(ja3_string.encode("ascii")).hexdigest()

    return TLSClientHelloInfo(
        sni=sni,
        tls_version=client_version,
        cipher_suites=tuple(cipher_suites),
        extensions=tuple(extension_ids),
        has_alpn=has_alpn,
        alpn_protocols=tuple(alpn_protocols),
        ja3_hash=ja3_hash,
        raw_length=5 + record_length,
    )


def _parse_sni_extension(ext_data: bytes) -> Optional[str]:
    """
    Parse the SNI extension data.

    SNI extension format::

        ┌───────────────────────────┐
        │ SNI List Length  (2 bytes)│
        ├───────────────────────────┤
        │ SNI Type         (1 byte) │  ← 0x00 = hostname
        │ Name Length      (2 bytes)│
        │ Name             (N bytes)│
        └───────────────────────────┘
    """
    pos = 0
    if pos + 2 > len(ext_data):
        return None

    sni_list_len = struct.unpack("!H", ext_data[pos : pos + 2])[0]
    pos += 2

    end = pos + sni_list_len
    while pos + 3 <= end:
        sni_type = ext_data[pos]
        name_len = struct.unpack("!H", ext_data[pos + 1 : pos + 3])[0]
        pos += 3

        if pos + name_len > len(ext_data):
            return None

        if sni_type == _TLS_SNI_TYPE_HOSTNAME:
            try:
                return ext_data[pos : pos + name_len].decode("ascii").lower()
            except UnicodeDecodeError:
                return None
        pos += name_len

    return None


def _parse_alpn_extension(ext_data: bytes) -> list[str]:
    """
    Parse the ALPN extension data.

    Format::

        ┌─────────────────────────────┐
        │ ALPN List Length  (2 bytes)  │
        ├─────────────────────────────┤
        │ Protocol Length   (1 byte)   │
        │ Protocol Name     (N bytes)  │
        │ ... repeat ...               │
        └─────────────────────────────┘
    """
    protocols: list[str] = []
    pos = 0

    if pos + 2 > len(ext_data):
        return protocols

    alpn_list_len = struct.unpack("!H", ext_data[pos : pos + 2])[0]
    pos += 2
    end = pos + alpn_list_len

    while pos + 1 <= end:
        proto_len = ext_data[pos]
        pos += 1
        if pos + proto_len > len(ext_data):
            break
        try:
            protocols.append(
                ext_data[pos : pos + proto_len].decode("ascii")
            )
        except UnicodeDecodeError:
            pass
        pos += proto_len

    return protocols


def _compute_ja3_string(
    version: int,
    cipher_suites: list[int],
    extensions: list[int],
) -> str:
    """
    Compute a simplified JA3 fingerprint string.

    Full JA3 = ``TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats``

    We compute a partial JA3 with version, ciphers, and extensions.
    Elliptic curves and EC point formats would require deeper parsing
    of the respective extensions (0x000A, 0x000B) which is deferred.
    """
    # Filter out GREASE values (0x?a?a pattern)
    def is_grease(val: int) -> bool:
        return (val & 0x0F0F) == 0x0A0A

    filtered_ciphers = [c for c in cipher_suites if not is_grease(c)]
    filtered_exts = [e for e in extensions if not is_grease(e)]

    version_str = str(version)
    ciphers_str = "-".join(str(c) for c in filtered_ciphers)
    exts_str = "-".join(str(e) for e in filtered_exts)

    return f"{version_str},{ciphers_str},{exts_str},,"


# ═══════════════════════════════════════════════════════════════════════════
# SNI Route Table
# ═══════════════════════════════════════════════════════════════════════════

class RouteAction(Enum):
    """What to do with a matched (or unmatched) connection."""
    PROXY_BACKEND = auto()   # Forward to Xray/Sing-box backend
    DECOY_REVERSE = auto()   # Reverse-proxy to decoy website
    DROP = auto()            # Silently drop (for known scanner IPs)
    TARPIT = auto()          # Slow-drip response to waste scanner time


@dataclass
class RouteEntry:
    """A single SNI routing rule."""
    sni_pattern: str                        # exact hostname or "*.example.com"
    action: RouteAction = RouteAction.PROXY_BACKEND
    backend_host: str = "127.0.0.1"         # loopback to Xray/Sing-box
    backend_port: int = 443
    protocol_tag: str = "vless-reality"     # label for logging
    priority: int = 100                     # lower = higher priority
    max_connections: int = 0                # 0 = unlimited


@dataclass
class RouteMatch:
    """Result of a routing lookup."""
    entry: Optional[RouteEntry]
    action: RouteAction
    matched_sni: Optional[str]
    lookup_time_us: float                   # microseconds


class SNIRouteTable:
    """
    Thread-safe SNI routing table with exact and wildcard matching.

    Supports:
    - Exact match: ``www.google.com``
    - Wildcard: ``*.google.com`` matches ``foo.google.com``
    - Default route for unmatched SNI (active probe deflection)
    """

    def __init__(self) -> None:
        self._exact: dict[str, RouteEntry] = {}
        self._wildcard: list[tuple[str, RouteEntry]] = []
        self._default_action: RouteAction = RouteAction.DECOY_REVERSE
        self._connection_counts: dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def add_route(self, entry: RouteEntry) -> None:
        """Register a new SNI routing rule."""
        async with self._lock:
            pattern = entry.sni_pattern.lower()
            if pattern.startswith("*."):
                suffix = pattern[1:]  # keep the dot: ".google.com"
                self._wildcard.append((suffix, entry))
                self._wildcard.sort(key=lambda x: x[1].priority)
                logger.info(
                    "Route added: %s → %s:%d [%s] (wildcard)",
                    pattern, entry.backend_host, entry.backend_port,
                    entry.action.name,
                )
            else:
                self._exact[pattern] = entry
                logger.info(
                    "Route added: %s → %s:%d [%s] (exact)",
                    pattern, entry.backend_host, entry.backend_port,
                    entry.action.name,
                )

    async def remove_route(self, sni_pattern: str) -> bool:
        """Remove a routing rule. Returns True if found and removed."""
        async with self._lock:
            pattern = sni_pattern.lower()
            if pattern in self._exact:
                del self._exact[pattern]
                logger.info("Route removed: %s (exact)", pattern)
                return True

            original_len = len(self._wildcard)
            suffix = pattern[1:] if pattern.startswith("*.") else pattern
            self._wildcard = [
                (s, e) for s, e in self._wildcard if s != suffix
            ]
            if len(self._wildcard) < original_len:
                logger.info("Route removed: %s (wildcard)", pattern)
                return True

            return False

    async def lookup(self, sni: Optional[str]) -> RouteMatch:
        """
        Look up the routing action for an SNI hostname.

        Exact matches take priority, then wildcard matches (sorted
        by priority), and finally the default action (DECOY_REVERSE).
        """
        start = time.monotonic()

        if sni is None:
            elapsed_us = (time.monotonic() - start) * 1_000_000
            return RouteMatch(
                entry=None,
                action=self._default_action,
                matched_sni=None,
                lookup_time_us=elapsed_us,
            )

        hostname = sni.lower()

        # 1. Exact match
        if hostname in self._exact:
            entry = self._exact[hostname]
            if entry.max_connections > 0:
                count = self._connection_counts.get(hostname, 0)
                if count >= entry.max_connections:
                    elapsed_us = (time.monotonic() - start) * 1_000_000
                    logger.warning(
                        "Connection limit reached for SNI %s (%d/%d)",
                        hostname, count, entry.max_connections,
                    )
                    return RouteMatch(
                        entry=None,
                        action=RouteAction.DECOY_REVERSE,
                        matched_sni=hostname,
                        lookup_time_us=elapsed_us,
                    )
            elapsed_us = (time.monotonic() - start) * 1_000_000
            return RouteMatch(
                entry=entry,
                action=entry.action,
                matched_sni=hostname,
                lookup_time_us=elapsed_us,
            )

        # 2. Wildcard match
        for suffix, entry in self._wildcard:
            if hostname.endswith(suffix):
                elapsed_us = (time.monotonic() - start) * 1_000_000
                return RouteMatch(
                    entry=entry,
                    action=entry.action,
                    matched_sni=hostname,
                    lookup_time_us=elapsed_us,
                )

        # 3. Default: deflect to decoy
        elapsed_us = (time.monotonic() - start) * 1_000_000
        return RouteMatch(
            entry=None,
            action=self._default_action,
            matched_sni=hostname,
            lookup_time_us=elapsed_us,
        )

    async def increment_connections(self, sni: str) -> None:
        """Track active connection count for an SNI."""
        async with self._lock:
            key = sni.lower()
            self._connection_counts[key] = (
                self._connection_counts.get(key, 0) + 1
            )

    async def decrement_connections(self, sni: str) -> None:
        """Decrement active connection count for an SNI."""
        async with self._lock:
            key = sni.lower()
            count = self._connection_counts.get(key, 0)
            if count > 0:
                self._connection_counts[key] = count - 1
            else:
                self._connection_counts.pop(key, None)

    async def get_stats(self) -> dict[str, Any]:
        """Return routing table statistics."""
        return {
            "exact_routes": len(self._exact),
            "wildcard_routes": len(self._wildcard),
            "active_connections": dict(self._connection_counts),
            "default_action": self._default_action.name,
            "routes": [
                {
                    "sni": pattern,
                    "action": entry.action.name,
                    "backend": f"{entry.backend_host}:{entry.backend_port}",
                    "protocol": entry.protocol_tag,
                    "priority": entry.priority,
                }
                for pattern, entry in self._exact.items()
            ] + [
                {
                    "sni": f"*{suffix}",
                    "action": entry.action.name,
                    "backend": f"{entry.backend_host}:{entry.backend_port}",
                    "protocol": entry.protocol_tag,
                    "priority": entry.priority,
                }
                for suffix, entry in self._wildcard
            ],
        }


# ═══════════════════════════════════════════════════════════════════════════
# Decoy Reverse Proxy (Active Probe Deflection)
# ═══════════════════════════════════════════════════════════════════════════

class DecoyReverseProxy:
    """
    Reverse-proxies unrecognised connections to a legitimate website
    so that active probes from GFW/Filternet see a real web page
    instead of a connection reset or VPN handshake.

    This defeats the standard "connect to suspect IP and see what
    responds" active probing technique.

    The proxy:
    - Fetches the decoy page via ``httpx.AsyncClient``
    - Injects realistic response headers
    - Supports streaming for large pages
    - Logs all probe attempts with JA3 fingerprint
    """

    # Common decoy targets that are very unlikely to be blocked
    KNOWN_DECOY_TARGETS: list[str] = [
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.bing.com",
        "https://learn.microsoft.com",
        "https://www.office.com",
    ]

    def __init__(
        self,
        target_url: str = "https://www.microsoft.com",
        timeout_seconds: float = 10.0,
        max_response_bytes: int = 2 * 1024 * 1024,  # 2 MB
    ) -> None:
        self._target_url = target_url.rstrip("/")
        self._timeout = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._client: Optional[httpx.AsyncClient] = None

        # Statistics
        self._total_requests: int = 0
        self._total_errors: int = 0
        self._total_bytes_served: int = 0
        
        # Cache (10 minutes)
        self._cache_ttl: float = 600.0
        self._cached_response: Optional[DecoyResponse] = None
        self._last_fetch_time: float = 0.0

    async def initialize(self) -> None:
        """Create the HTTPX async client with realistic browser headers."""
        if self._client is not None:
            return

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
            follow_redirects=True,
            limits=httpx.Limits(
                max_connections=50,
                max_keepalive_connections=10,
                keepalive_expiry=30,
            ),
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/125.0.0.0 Safari/537.36"
                ),
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;"
                    "q=0.9,image/avif,image/webp,*/*;q=0.8"
                ),
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
            },
            http2=True,
        )
        logger.info(
            "DecoyReverseProxy initialized → %s", self._target_url,
        )

    async def close(self) -> None:
        """Close the HTTPX client and release connections."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
            logger.info("DecoyReverseProxy closed")

    async def fetch_decoy_response(
        self,
        path: str = "/",
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
    ) -> "DecoyResponse":
        """
        Fetch a page from the decoy target and return it.

        Args:
            path: URL path to request (e.g. ``/en-us/`` for microsoft.com).
            method: HTTP method (GET, HEAD, etc.).
            headers: Extra headers to forward.

        Returns:
            A ``DecoyResponse`` with status, headers, and body bytes.
        """
        now = time.monotonic()
        if self._cached_response and (now - self._last_fetch_time) < self._cache_ttl:
            self._total_requests += 1
            self._total_bytes_served += len(self._cached_response.body)
            return self._cached_response

        if self._client is None:
            await self.initialize()

        assert self._client is not None  # for type checker

        url = f"{self._target_url}{path}"
        self._total_requests += 1

        try:
            response = await self._client.request(
                method=method,
                url=url,
                headers=headers or {},
            )

            body = response.content[: self._max_response_bytes]
            self._total_bytes_served += len(body)

            # Build sanitised response headers
            safe_headers = self._sanitise_response_headers(
                dict(response.headers),
            )

            logger.debug(
                "Decoy fetch OK: %s %s → %d (%d bytes)",
                method, url, response.status_code, len(body),
            )

            final_response = DecoyResponse(
                status_code=response.status_code,
                headers=safe_headers,
                body=body,
                target_url=url,
            )
            self._cached_response = final_response
            self._last_fetch_time = time.monotonic()
            
            return final_response

        except httpx.TimeoutException:
            self._total_errors += 1
            logger.warning("Decoy fetch timeout: %s", url)
            return self._generate_fallback_response()

        except httpx.HTTPError as exc:
            self._total_errors += 1
            logger.error("Decoy fetch error: %s — %s", url, exc)
            return self._generate_fallback_response()

    @staticmethod
    def _sanitise_response_headers(
        headers: dict[str, str],
    ) -> dict[str, str]:
        """
        Remove headers that could leak the proxy's presence.

        Strips ``X-Forwarded-*``, ``Via``, ``Server`` (replaces with
        a realistic Microsoft IIS value), and other fingerprinting
        headers.
        """
        strip_headers = {
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "via",
            "x-powered-by",
            "x-aspnet-version",
            "x-request-id",
            "x-correlation-id",
        }

        sanitised: dict[str, str] = {}
        for key, value in headers.items():
            lower_key = key.lower()
            if lower_key in strip_headers:
                continue
            if lower_key == "server":
                sanitised[key] = "Microsoft-IIS/10.0"
                continue
            sanitised[key] = value

        return sanitised

    def _generate_fallback_response(self) -> "DecoyResponse":
        """
        Generate a realistic-looking Microsoft-style error page when
        the upstream decoy target is unreachable.
        """
        body = (
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n"
            "<head>\n"
            "  <meta charset=\"utf-8\">\n"
            "  <meta name=\"viewport\" content=\"width=device-width, "
            "initial-scale=1.0\">\n"
            "  <title>Microsoft – Service Temporarily Unavailable</title>\n"
            "  <style>\n"
            "    body {\n"
            "      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, "
            "sans-serif;\n"
            "      background: #f3f3f3;\n"
            "      color: #333;\n"
            "      display: flex;\n"
            "      justify-content: center;\n"
            "      align-items: center;\n"
            "      min-height: 100vh;\n"
            "      margin: 0;\n"
            "    }\n"
            "    .container {\n"
            "      text-align: center;\n"
            "      max-width: 600px;\n"
            "      padding: 40px;\n"
            "    }\n"
            "    .logo {\n"
            "      width: 108px;\n"
            "      height: 24px;\n"
            "      margin-bottom: 24px;\n"
            "    }\n"
            "    h1 { font-size: 20px; font-weight: 600; }\n"
            "    p { font-size: 14px; color: #666; line-height: 1.6; }\n"
            "    a { color: #0067b8; text-decoration: none; }\n"
            "    a:hover { text-decoration: underline; }\n"
            "  </style>\n"
            "</head>\n"
            "<body>\n"
            "  <div class=\"container\">\n"
            "    <h1>Service Temporarily Unavailable</h1>\n"
            "    <p>We're sorry, but the service you're trying to reach "
            "is temporarily unavailable. Please try again later.</p>\n"
            "    <p>If this problem persists, please visit "
            "<a href=\"https://support.microsoft.com\">Microsoft Support"
            "</a>.</p>\n"
            "    <p style=\"margin-top:32px;font-size:12px;color:#999;\">"
            "Ref: MTGVPN-DECOY-FALLBACK</p>\n"
            "  </div>\n"
            "</body>\n"
            "</html>"
        ).encode("utf-8")

        return DecoyResponse(
            status_code=503,
            headers={
                "Content-Type": "text/html; charset=utf-8",
                "Content-Length": str(len(body)),
                "Server": "Microsoft-IIS/10.0",
                "X-Powered-By": "ASP.NET",
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Connection": "close",
            },
            body=body,
            target_url=self._target_url,
        )

    def get_stats(self) -> dict[str, Any]:
        """Return proxy statistics."""
        return {
            "target_url": self._target_url,
            "total_requests": self._total_requests,
            "total_errors": self._total_errors,
            "total_bytes_served": self._total_bytes_served,
            "error_rate_pct": (
                round(self._total_errors / max(self._total_requests, 1) * 100, 2)
            ),
            "client_active": self._client is not None,
        }


@dataclass
class DecoyResponse:
    """Response from the decoy reverse proxy."""
    status_code: int
    headers: dict[str, str]
    body: bytes
    target_url: str


# ═══════════════════════════════════════════════════════════════════════════
# SNI Multiplexer — Ties Everything Together
# ═══════════════════════════════════════════════════════════════════════════

class SNIMultiplexer:
    """
    Production SNI multiplexer that binds to a TCP port, peeks at
    the TLS ClientHello to extract SNI, routes to the appropriate
    backend, or deflects to the decoy reverse proxy.

    Lifecycle::

        mux = SNIMultiplexer(listen_port=443)
        await mux.add_backend("www.google.com", "127.0.0.1", 10443, "vless")
        await mux.add_backend("*.bing.com", "127.0.0.1", 10444, "hysteria2")
        await mux.start()
        # ...
        await mux.stop()
    """

    # Maximum bytes to peek from a ClientHello
    MAX_PEEK_BYTES: int = 8192

    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 443,
        decoy_target: Optional[str] = None,
    ) -> None:
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._route_table = SNIRouteTable()
        self._server: Optional[asyncio.AbstractServer] = None

        # Lazy import to avoid circular dependency at module level
        from backend.app.core.config import settings
        target_url = decoy_target or settings.DECOY_REVERSE_PROXY_TARGET
        self._decoy_proxy = DecoyReverseProxy(target_url=target_url)

        # Statistics
        self._total_connections: int = 0
        self._active_connections: int = 0
        self._total_backend_forwards: int = 0
        self._total_decoy_deflections: int = 0
        self._total_drops: int = 0
        self._total_parse_failures: int = 0

    async def add_backend(
        self,
        sni_pattern: str,
        backend_host: str = "127.0.0.1",
        backend_port: int = 443,
        protocol_tag: str = "vless-reality",
        priority: int = 100,
        max_connections: int = 0,
    ) -> None:
        """
        Register a backend for a specific SNI pattern.

        Args:
            sni_pattern: Exact hostname or ``*.domain.com`` wildcard.
            backend_host: Where to forward matching connections.
            backend_port: Backend port.
            protocol_tag: Label for logging/metrics.
            priority: Lower number = higher priority for wildcards.
            max_connections: Max concurrent connections (0 = unlimited).
        """
        entry = RouteEntry(
            sni_pattern=sni_pattern,
            action=RouteAction.PROXY_BACKEND,
            backend_host=backend_host,
            backend_port=backend_port,
            protocol_tag=protocol_tag,
            priority=priority,
            max_connections=max_connections,
        )
        await self._route_table.add_route(entry)

    async def remove_backend(self, sni_pattern: str) -> bool:
        """Remove a previously registered backend route."""
        return await self._route_table.remove_route(sni_pattern)

    async def start(self) -> None:
        """Start the SNI multiplexer TCP server."""
        await self._decoy_proxy.initialize()

        self._server = await asyncio.start_server(
            self._handle_connection,
            host=self._listen_host,
            port=self._listen_port,
            reuse_address=True,
            reuse_port=True,
        )

        addrs = ", ".join(
            str(sock.getsockname()) for sock in self._server.sockets
        )
        logger.info(
            "SNI Multiplexer listening on %s (decoy → %s)",
            addrs,
            self._decoy_proxy._target_url,
        )

    async def stop(self) -> None:
        """Stop the multiplexer and clean up resources."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        await self._decoy_proxy.close()
        logger.info("SNI Multiplexer stopped")

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Handle a single inbound TCP connection:

        1. Peek at the first bytes to parse TLS ClientHello
        2. Extract SNI
        3. Route or deflect
        """
        peer = writer.get_extra_info("peername")
        peer_str = f"{peer[0]}:{peer[1]}" if peer else "unknown"

        self._total_connections += 1
        self._active_connections += 1

        try:
            # ── Step 1: Read the ClientHello ──────────────────────────
            try:
                initial_data = await asyncio.wait_for(
                    reader.read(self.MAX_PEEK_BYTES),
                    timeout=5.0,
                )
            except asyncio.TimeoutError:
                logger.debug("Timeout reading ClientHello from %s", peer_str)
                self._total_parse_failures += 1
                return

            if not initial_data:
                logger.debug("Empty connection from %s", peer_str)
                return

            # ── Step 2: Parse SNI ─────────────────────────────────────
            sni: Optional[str] = None
            ja3: Optional[str] = None
            try:
                hello = parse_client_hello(initial_data)
                sni = hello.sni
                ja3 = hello.ja3_hash
            except TLSParseError as exc:
                logger.debug(
                    "TLS parse failed for %s: %s — deflecting to decoy",
                    peer_str, exc,
                )
                self._total_parse_failures += 1

            # ── Step 3: Route lookup ──────────────────────────────────
            route = await self._route_table.lookup(sni)

            logger.info(
                "Connection %s → SNI=%s JA3=%s → %s (%.1f µs)",
                peer_str,
                sni or "<none>",
                ja3 or "<n/a>",
                route.action.name,
                route.lookup_time_us,
            )

            # ── Step 4: Execute action ────────────────────────────────
            if route.action == RouteAction.PROXY_BACKEND and route.entry:
                await self._forward_to_backend(
                    reader, writer, initial_data, route.entry, sni,
                )
                self._total_backend_forwards += 1

            elif route.action == RouteAction.DROP:
                logger.info("Dropping connection from %s (SNI=%s)", peer_str, sni)
                self._total_drops += 1

            elif route.action == RouteAction.TARPIT:
                await self._tarpit_connection(writer, peer_str)
                self._total_drops += 1

            else:
                # DECOY_REVERSE or fallback
                await self._deflect_to_decoy(writer, peer_str)
                self._total_decoy_deflections += 1

        except ConnectionResetError:
            logger.debug("Connection reset by %s", peer_str)
        except Exception as exc:
            logger.error(
                "Unhandled error for %s: %s", peer_str, exc,
                exc_info=True,
            )
        finally:
            self._active_connections -= 1
            if sni:
                await self._route_table.decrement_connections(sni)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _forward_to_backend(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        initial_data: bytes,
        entry: RouteEntry,
        sni: Optional[str],
    ) -> None:
        """
        Forward the connection (including the already-read ClientHello)
        to the Xray/Sing-box backend over a local loopback socket.

        We replay ``initial_data`` first, then bidirectionally pipe
        data between the client and backend until either side closes.
        """
        if sni:
            await self._route_table.increment_connections(sni)

        try:
            backend_reader, backend_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    entry.backend_host,
                    entry.backend_port,
                ),
                timeout=5.0,
            )
        except (asyncio.TimeoutError, OSError) as exc:
            logger.error(
                "Cannot connect to backend %s:%d for SNI=%s: %s",
                entry.backend_host, entry.backend_port, sni, exc,
            )
            # Fallback to decoy on backend failure
            await self._deflect_to_decoy(
                client_writer,
                f"backend-fail({entry.backend_host}:{entry.backend_port})",
            )
            return

        try:
            # Replay the ClientHello to the backend
            backend_writer.write(initial_data)
            await backend_writer.drain()

            # Bidirectional pipe
            await asyncio.gather(
                self._pipe(client_reader, backend_writer, "client→backend"),
                self._pipe(backend_reader, client_writer, "backend→client"),
            )
        except Exception as exc:
            logger.debug("Pipe closed for SNI=%s: %s", sni, exc)
        finally:
            try:
                backend_writer.close()
                await backend_writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    async def _pipe(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        label: str,
    ) -> None:
        """
        Copy data from reader to writer until EOF or error.

        Uses a 32 KB buffer for optimal throughput without excessive
        memory usage.
        """
        buf_size = 32768
        try:
            while True:
                data = await reader.read(buf_size)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

    async def _deflect_to_decoy(
        self,
        writer: asyncio.StreamWriter,
        context: str,
    ) -> None:
        """
        Fetch the decoy page and send it back to the prober as if
        this server were the legitimate decoy website.
        """
        response = await self._decoy_proxy.fetch_decoy_response(path="/")

        # Build a raw HTTP/1.1 response
        status_line = f"HTTP/1.1 {response.status_code} OK\r\n"
        header_lines = "".join(
            f"{k}: {v}\r\n" for k, v in response.headers.items()
        )
        raw_response = (
            status_line.encode("ascii")
            + header_lines.encode("ascii")
            + b"\r\n"
            + response.body
        )

        try:
            writer.write(raw_response)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass

        logger.info(
            "Decoy deflection → %s (%d bytes to %s)",
            response.target_url,
            len(response.body),
            context,
        )

    @staticmethod
    async def _tarpit_connection(
        writer: asyncio.StreamWriter,
        context: str,
    ) -> None:
        """
        Slowly drip bytes to waste the scanner's time and resources.

        Sends one byte every 5 seconds for up to 60 seconds, then
        drops the connection.  This ties up the prober's socket and
        makes large-scale scanning impractically slow.
        """
        logger.info("Tarpitting connection from %s", context)
        drip_bytes = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
        )
        try:
            writer.write(drip_bytes)
            await writer.drain()

            for _ in range(12):  # 12 × 5 sec = 60 sec
                await asyncio.sleep(5.0)
                # Send a tiny chunk to keep the connection alive
                writer.write(b"1\r\n \r\n")
                await writer.drain()

            # End with a zero-length chunk
            writer.write(b"0\r\n\r\n")
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        logger.debug("Tarpit complete for %s", context)

    async def get_stats(self) -> dict[str, Any]:
        """Return comprehensive multiplexer statistics."""
        route_stats = await self._route_table.get_stats()
        decoy_stats = self._decoy_proxy.get_stats()

        return {
            "listen": f"{self._listen_host}:{self._listen_port}",
            "total_connections": self._total_connections,
            "active_connections": self._active_connections,
            "backend_forwards": self._total_backend_forwards,
            "decoy_deflections": self._total_decoy_deflections,
            "drops": self._total_drops,
            "parse_failures": self._total_parse_failures,
            "routing": route_stats,
            "decoy": decoy_stats,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Helper: Build ClientHello for Testing
# ═══════════════════════════════════════════════════════════════════════════

def build_test_client_hello(sni: str = "www.google.com") -> bytes:
    """
    Build a minimal but valid TLS 1.2 ClientHello with the given SNI.

    This is used exclusively for unit testing the parser and
    multiplexer routing logic.  It is NOT a real TLS implementation.

    Args:
        sni: The hostname to embed in the SNI extension.

    Returns:
        Raw bytes that ``parse_client_hello`` can parse.
    """
    import os

    sni_bytes = sni.encode("ascii")

    # SNI extension
    sni_entry = (
        struct.pack("!B", _TLS_SNI_TYPE_HOSTNAME)
        + struct.pack("!H", len(sni_bytes))
        + sni_bytes
    )
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = (
        struct.pack("!H", _TLS_EXTENSION_SNI)
        + struct.pack("!H", len(sni_list))
        + sni_list
    )

    # ALPN extension (h2, http/1.1)
    alpn_h2 = b"\x02h2"
    alpn_h1 = b"\x08http/1.1"
    alpn_list = alpn_h2 + alpn_h1
    alpn_ext = (
        struct.pack("!H", 0x0010)   # extension type
        + struct.pack("!H", len(alpn_list) + 2)
        + struct.pack("!H", len(alpn_list))
        + alpn_list
    )

    # Supported versions extension (TLS 1.3, 1.2)
    sv_data = b"\x03\x03\x04\x03\x03"  # length=3, TLS 1.3, TLS 1.2
    sv_ext = (
        struct.pack("!H", 0x002B)  # supported_versions
        + struct.pack("!H", len(sv_data))
        + sv_data
    )

    all_extensions = sni_ext + alpn_ext + sv_ext
    extensions_block = struct.pack("!H", len(all_extensions)) + all_extensions

    # Cipher suites (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
    # TLS_CHACHA20_POLY1305_SHA256)
    ciphers = struct.pack("!HHH", 0x1301, 0x1302, 0x1303)
    cipher_block = struct.pack("!H", len(ciphers)) + ciphers

    # Compression methods (null only)
    comp_methods = b"\x01\x00"

    # ClientHello body
    client_hello_body = (
        struct.pack("!H", 0x0303)       # ClientVersion: TLS 1.2
        + os.urandom(32)                 # Random (32 bytes)
        + b"\x00"                        # Session ID length: 0
        + cipher_block
        + comp_methods
        + extensions_block
    )

    # Handshake header
    handshake = (
        struct.pack("!B", _TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
        + struct.pack("!I", len(client_hello_body))[1:]  # 3-byte length
        + client_hello_body
    )

    # TLS record
    tls_record = (
        struct.pack("!B", _TLS_CONTENT_TYPE_HANDSHAKE)
        + struct.pack("!H", 0x0301)         # Record version: TLS 1.0
        + struct.pack("!H", len(handshake))
        + handshake
    )

    return tls_record

# ═══════════════════════════════════════════════════════════════════════════
# DPI Evasion & Preset Generator (Autonomous Config Engine)
# ═══════════════════════════════════════════════════════════════════════════

def generate_fragment_block(preset: str) -> dict[str, str]:
    """
    Generate Xray compatible fragment settings based on the selected profile.
    This slices the TLS ClientHello to evade DPI SNI sniffing.
    """
    if preset == "DPI_Resistant":
        return {
            "packets": "1-3",
            "length": "100-200",
            "interval": "10-20"
        }
    elif preset == "Low_Latency_Gaming":
        return {
            "packets": "tlshello",
            "length": "50-100",
            "interval": "5-10"
        }
    # Ultra_Stable or default: no fragmentation
    return {}


def generate_noise_block(preset: str) -> dict[str, Any]:
    """
    Generate Hysteria2/Reality compatible noise injection blocks.
    Masks the traffic signature to avoid heuristic protocol detection.
    """
    if preset == "DPI_Resistant":
        return {
            "noise_payload_size": "500-1500",
            "noise_delay": "10-30",
            "type": "rand"
        }
    elif preset == "Low_Latency_Gaming":
        return {
            "noise_payload_size": "100-300",
            "noise_delay": "0-5",
            "type": "rand"
        }
    # Ultra_Stable or default: no noise
    return {}


def get_preset_config(preset_name: str) -> dict[str, Any]:
    """
    Return the base infrastructure profile for the selected mode.
    
    a) 'Ultra_Stable': Standard routing, min latency, no fragment.
    b) 'DPI_Resistant': Aggressive TLS ClientHello splitting, uTLS active.
    c) 'Low_Latency_Gaming': Mux active, optimized noise, UDP priority.
    """
    if preset_name == "DPI_Resistant":
        return {
            "mode": "DPI_Resistant",
            "mux": {"enabled": False},
            "utls": {"enabled": True, "fingerprint": "chrome"},
            "udp_priority": False
        }
    elif preset_name == "Low_Latency_Gaming":
        return {
            "mode": "Low_Latency_Gaming",
            "mux": {"enabled": True, "concurrency": 8},
            "utls": {"enabled": False},
            "udp_priority": True
        }
    
    # Ultra_Stable default
    return {
        "mode": "Ultra_Stable",
        "mux": {"enabled": False},
        "utls": {"enabled": False},
        "udp_priority": False
    }


def apply_dpi_evasion_to_outbound(outbound_config: dict[str, Any], preset_name: str) -> list[dict[str, Any]]:
    """
    Dynamically injects fragment and noise blocks into an existing Xray 
    outbound JSON configuration dictionary based on the selected preset.
    
    Args:
        outbound_config: The raw Xray outbound dict (e.g. vless or trojan).
        preset_name: The target evasion preset.
        
    Returns:
        A list of outbounds (the mutated outbound_config + any proxy outbounds like fragment).
    """
    fragment_block = generate_fragment_block(preset_name)
    noise_block = generate_noise_block(preset_name)
    base_preset = get_preset_config(preset_name)
    
    stream_settings = outbound_config.get("streamSettings", {})
    outbounds = [outbound_config]
    
    # Inject Fragment if applicable
    # In Xray, fragment must be a separate freedom outbound, and the main
    # outbound links to it via dialerProxy.
    if fragment_block:
        sockopt = stream_settings.get("sockopt", {})
        sockopt["dialerProxy"] = "fragment-out"
        stream_settings["sockopt"] = sockopt
        
        fragment_outbound = {
            "tag": "fragment-out",
            "protocol": "freedom",
            "settings": {
                "fragment": fragment_block
            }
        }
        outbounds.append(fragment_outbound)
        
    # Inject Noise (Hysteria2/Reality)
    # WARNING: Standard xray-core does not support 'noise' at the outbound root.
    # This might require a custom fork or sing-box. We leave it as requested
    # but be aware `xray run -test` will reject it if strictly using xray-core.
    if noise_block:
        outbound_config["noise"] = noise_block
        
    # Apply UTLS & Mux
    if base_preset["utls"]["enabled"]:
        tls_settings = stream_settings.get("tlsSettings", {})
        tls_settings["fingerprint"] = base_preset["utls"]["fingerprint"]
        stream_settings["tlsSettings"] = tls_settings
        
    outbound_config["mux"] = base_preset.get("mux", {"enabled": False})
    outbound_config["streamSettings"] = stream_settings
    
    return outbounds
