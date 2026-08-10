"""
MTGroup VPN Ultimate — Privileged Helper Client
Thin client for the root-owned privileged helper daemon
(backend/app/privileged_helper_daemon.py).

The FastAPI backend process should never call iptables/nft/systemctl
directly and never needs NET_ADMIN/SYS_ADMIN capabilities. Instead it sends
small JSON requests over a root-owned Unix socket to the helper daemon,
which validates every operation against a fixed allowlist before executing
anything. This mirrors the privilege-separation pattern used by other
VPN panels (e.g. a root-owned helper reachable only over a local socket)
reimplemented here for mtgroup's own async/sync call sites.

Two entrypoints are provided:
- `helper_request()` — async, for use from the FastAPI event loop.
- `helper_request_sync()` — blocking, for use from background threads
  (e.g. the killswitch watchdog thread) where there is no running event loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from backend.app.core.config import settings

logger = logging.getLogger("mtgroup.privileged_helper")

_MAX_MESSAGE_BYTES = 1_048_576  # 1 MiB


class PrivilegedHelperError(RuntimeError):
    """Raised when the privileged helper is unreachable or returns a fatal error."""


@dataclass(frozen=True)
class HelperResponse:
    ok: bool
    message: str = ""
    data: Optional[Mapping[str, Any]] = None


def _build_request(operation: str, payload: Optional[Mapping[str, Any]]) -> bytes:
    request = json.dumps(
        {"operation": operation, "payload": dict(payload or {})},
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    if len(request) > _MAX_MESSAGE_BYTES:
        raise PrivilegedHelperError("helper request exceeds 1 MiB")
    return request


def _decode_response(raw: bytes) -> HelperResponse:
    if not raw or len(raw) > _MAX_MESSAGE_BYTES:
        raise PrivilegedHelperError("invalid privileged helper response")
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PrivilegedHelperError("malformed privileged helper response") from exc
    return HelperResponse(
        ok=bool(result.get("ok")),
        message=str(result.get("message", "")),
        data=result.get("data") if isinstance(result.get("data"), dict) else None,
    )


async def helper_request(
    operation: str,
    payload: Optional[Mapping[str, Any]] = None,
    *,
    timeout: float = 15.0,
) -> HelperResponse:
    """Send one operation to the privileged helper and wait for its reply."""
    request = _build_request(operation, payload)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(settings.PRIVILEGED_HELPER_SOCKET),
            timeout=3.0,
        )
    except (OSError, asyncio.TimeoutError) as exc:
        raise PrivilegedHelperError(
            f"privileged helper unavailable at {settings.PRIVILEGED_HELPER_SOCKET}"
        ) from exc

    try:
        writer.write(request)
        await writer.drain()
        raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
    except (OSError, asyncio.TimeoutError) as exc:
        raise PrivilegedHelperError("privileged helper request timed out") from exc
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    return _decode_response(raw)


def helper_request_sync(
    operation: str,
    payload: Optional[Mapping[str, Any]] = None,
    *,
    timeout: float = 15.0,
) -> HelperResponse:
    """Blocking client for contexts without a running event loop
    (e.g. the killswitch watchdog thread)."""
    request = _build_request(operation, payload)

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(settings.PRIVILEGED_HELPER_SOCKET)
        client.sendall(request)
        chunks = bytearray()
        while not chunks.endswith(b"\n"):
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > _MAX_MESSAGE_BYTES:
                raise PrivilegedHelperError("invalid privileged helper response")
    except (OSError, TimeoutError) as exc:
        raise PrivilegedHelperError(
            f"privileged helper unavailable at {settings.PRIVILEGED_HELPER_SOCKET}"
        ) from exc
    finally:
        client.close()

    return _decode_response(bytes(chunks))
