"""
MTGroup VPN Ultimate — Privileged Helper Daemon
Root-owned allowlisted helper for firewall/killswitch/service operations.

Runs as its own systemd service (see scripts/mtgroup-privileged-helper.service),
completely separate from the FastAPI backend. The backend talks to it over a
Unix domain socket (backend/app/core/privileged_helper.py is the client) so
the backend process itself never needs NET_ADMIN/SYS_ADMIN and can never be
tricked into running an arbitrary shell command — every operation here is a
fixed, allowlisted function with its own input validation, and commands are
always executed as argv lists (subprocess, never shell=True).

NOTE: the exact `nft` CLI syntax used in _ensure_ban_infra()/_firewall_*
below has not been exercised against a live nftables installation in this
environment (Windows dev sandbox) — verify on a real Linux host before
relying on it in production.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import socket
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, Union

logger = logging.getLogger("mtgroup.privileged_helper_daemon")
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

SOCKET_PATH = Path(os.environ.get("MTG_PRIVILEGED_HELPER_SOCKET", "/run/mtgroup/helper.sock"))
PANEL_USER = os.environ.get("MTG_PANEL_USER", "mtgroup")
PANEL_GROUP = os.environ.get("MTG_PANEL_GROUP", "mtgroup")
MAX_REQUEST = 1_048_576

SERVICES = {"xray", "sing-box", "mtgroup-backend"}
KILLSWITCH_CHAIN = "MTG_KILLSWITCH"
NFT_TABLE = "mtgroup"
NFT_BAN_CHAIN = "banned_ips"
NFT_SET_V4 = "banned_ip4_set"
NFT_SET_V6 = "banned_ip6_set"


# ─────────────────────────────────────────────────────────────────────────
#  Command execution — always argv lists, never shell=True
# ─────────────────────────────────────────────────────────────────────────

def _run(argv: list[str], timeout: int = 15) -> dict[str, Any]:
    """Execute a fixed argv list. Never builds a shell string."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        return {"ok": False, "message": f"{type(exc).__name__}: {exc}"}
    output = (proc.stderr or proc.stdout or "").strip()[-2000:]
    return {"ok": proc.returncode == 0, "message": output, "code": proc.returncode}


def _run_ok(argv: list[str], timeout: int = 15) -> bool:
    return _run(argv, timeout=timeout)["ok"]


# ─────────────────────────────────────────────────────────────────────────
#  Killswitch — iptables chain + blackhole route
#  (ported from backend/app/core/killswitch.py, now argv-list based)
# ─────────────────────────────────────────────────────────────────────────

def _killswitch_apply(payload: dict[str, Any]) -> dict[str, Any]:
    ports_raw = payload.get("whitelist_ports", [])
    if not isinstance(ports_raw, list):
        return {"ok": False, "message": "whitelist_ports must be a list"}
    ports: list[int] = []
    for p in ports_raw:
        if not isinstance(p, int) or not (1 <= p <= 65535):
            return {"ok": False, "message": f"invalid whitelist port: {p!r}"}
        ports.append(p)

    _killswitch_release({})  # idempotent: flush any stale chain/route first

    _run_ok(["iptables", "-N", KILLSWITCH_CHAIN])
    _run_ok(["iptables", "-I", "OUTPUT", "1", "-j", KILLSWITCH_CHAIN])
    _run_ok(["iptables", "-I", "FORWARD", "1", "-j", KILLSWITCH_CHAIN])
    _run_ok(["iptables", "-A", KILLSWITCH_CHAIN, "-o", "lo", "-j", "RETURN"])
    for port in ports:
        _run_ok(["iptables", "-A", KILLSWITCH_CHAIN, "-p", "tcp", "--dport", str(port), "-j", "RETURN"])
        _run_ok(["iptables", "-A", KILLSWITCH_CHAIN, "-p", "tcp", "--sport", str(port), "-j", "RETURN"])
    _run_ok([
        "iptables", "-A", KILLSWITCH_CHAIN,
        "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN",
    ])
    drop_result = _run(["iptables", "-A", KILLSWITCH_CHAIN, "-j", "DROP"])
    route_result = _run(["ip", "route", "add", "blackhole", "default", "metric", "50"])

    return {
        "ok": drop_result["ok"],
        "message": "killswitch applied" if drop_result["ok"] else drop_result["message"],
        "data": {"route_applied": route_result["ok"]},
    }


def _killswitch_release(payload: dict[str, Any]) -> dict[str, Any]:
    _run_ok(["iptables", "-D", "OUTPUT", "-j", KILLSWITCH_CHAIN])
    _run_ok(["iptables", "-D", "FORWARD", "-j", KILLSWITCH_CHAIN])
    _run_ok(["iptables", "-F", KILLSWITCH_CHAIN])
    _run_ok(["iptables", "-X", KILLSWITCH_CHAIN])
    _run_ok(["ip", "route", "del", "blackhole", "default", "metric", "50"])
    return {"ok": True, "message": "killswitch released"}


def _killswitch_status(payload: dict[str, Any]) -> dict[str, Any]:
    result = _run(["iptables", "-C", "OUTPUT", "-j", KILLSWITCH_CHAIN])
    return {"ok": True, "message": "checked", "data": {"linked": result["ok"]}}


# ─────────────────────────────────────────────────────────────────────────
#  Firewall — single-IP ban/unban via a named nftables set
#
#  Using a named set (rather than one ad-hoc "add rule ... drop" per IP, as
#  the old backend/app/ebpf/nftables_manager.py did) is what makes unban
#  possible: `nft delete element` removes exactly one address from the set
#  without needing to know/re-derive the original rule text.
# ─────────────────────────────────────────────────────────────────────────

def _ensure_ban_infra() -> None:
    """Idempotently create the mtgroup table/sets/chain/rule used for bans.
    `nft add ...` is a no-op (not an error) if the object already exists."""
    _run(["nft", "add", "table", "inet", NFT_TABLE])
    _run(["nft", "add", "set", "inet", NFT_TABLE, NFT_SET_V4, "{", "type", "ipv4_addr;", "}"])
    _run(["nft", "add", "set", "inet", NFT_TABLE, NFT_SET_V6, "{", "type", "ipv6_addr;", "}"])
    _run([
        "nft", "add", "chain", "inet", NFT_TABLE, NFT_BAN_CHAIN,
        "{", "type", "filter;", "hook", "input;", "priority", "-10;", "policy", "accept;", "}",
    ])
    _run([
        "nft", "add", "rule", "inet", NFT_TABLE, NFT_BAN_CHAIN,
        "ip", "saddr", f"@{NFT_SET_V4}", "counter", "drop",
    ])
    _run([
        "nft", "add", "rule", "inet", NFT_TABLE, NFT_BAN_CHAIN,
        "ip6", "saddr", f"@{NFT_SET_V6}", "counter", "drop",
    ])


def _validate_ip(payload: dict[str, Any]) -> Union["ipaddress.IPv4Address", "ipaddress.IPv6Address", dict[str, Any]]:
    raw = payload.get("ip", "")
    if not isinstance(raw, str):
        return {"ok": False, "message": "ip must be a string"}
    try:
        return ipaddress.ip_address(raw.strip())
    except ValueError:
        return {"ok": False, "message": "invalid IP address"}


def _firewall_ban_ip(payload: dict[str, Any]) -> dict[str, Any]:
    ip = _validate_ip(payload)
    if isinstance(ip, dict):
        return ip
    _ensure_ban_infra()
    set_name = NFT_SET_V4 if ip.version == 4 else NFT_SET_V6
    # `ip` is an ipaddress object, not attacker text — str(ip) is always a
    # clean, single, well-formed address with no room for extra nft tokens.
    return _run([
        "nft", "add", "element", "inet", NFT_TABLE, set_name, "{", str(ip), "}",
    ])


def _firewall_unban_ip(payload: dict[str, Any]) -> dict[str, Any]:
    ip = _validate_ip(payload)
    if isinstance(ip, dict):
        return ip
    _ensure_ban_infra()
    set_name = NFT_SET_V4 if ip.version == 4 else NFT_SET_V6
    result = _run(["nft", "delete", "element", "inet", NFT_TABLE, set_name, "{", str(ip), "}"])
    # Deleting an element that was never present is not a real failure.
    if not result["ok"] and "does not exist" in result["message"].lower():
        return {"ok": True, "message": "ip was not banned"}
    return result


# ─────────────────────────────────────────────────────────────────────────
#  Service management
# ─────────────────────────────────────────────────────────────────────────

def _service_restart(payload: dict[str, Any]) -> dict[str, Any]:
    service = payload.get("service")
    if service not in SERVICES:
        return {"ok": False, "message": "service is not allowlisted"}
    return _run(["systemctl", "restart", service])


# ─────────────────────────────────────────────────────────────────────────
#  Dispatch
# ─────────────────────────────────────────────────────────────────────────

_OPERATIONS = {
    "killswitch.apply": _killswitch_apply,
    "killswitch.release": _killswitch_release,
    "killswitch.status": _killswitch_status,
    "firewall.ban_ip": _firewall_ban_ip,
    "firewall.unban_ip": _firewall_unban_ip,
    "service.restart": _service_restart,
}


def _dispatch(operation: str, payload: dict[str, Any]) -> dict[str, Any]:
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return {"ok": False, "message": "operation is not allowlisted"}
    try:
        return handler(payload)
    except Exception as exc:  # noqa: BLE001 - never let a handler bug crash the daemon
        logger.exception("handler for %s raised", operation)
        return {"ok": False, "message": f"internal error: {type(exc).__name__}"}


# ─────────────────────────────────────────────────────────────────────────
#  Peer authentication (SO_PEERCRED on Linux)
# ─────────────────────────────────────────────────────────────────────────

def _peer_allowed(writer: asyncio.StreamWriter) -> bool:
    if not hasattr(socket, "SO_PEERCRED"):
        # SO_PEERCRED is Linux-only. Non-Linux platforms fall back to the
        # socket file's own permission bits (0660, group-owned below) as
        # the sole access control — fine for local dev, never acceptable
        # for a production deployment (which is always Linux here).
        logger.warning("SO_PEERCRED unavailable on this platform; relying on socket file permissions only")
        return True
    sock = writer.get_extra_info("socket")
    if sock is None:
        return False
    try:
        import grp
        import pwd
        pid, uid, gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        del pid
        expected_uid = pwd.getpwnam(PANEL_USER).pw_uid
        expected_gid = grp.getgrnam(PANEL_GROUP).gr_gid
        return uid == expected_uid or gid == expected_gid
    except (KeyError, OSError) as exc:
        logger.error("peer credential check failed: %s", exc)
        return False


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        if not _peer_allowed(writer):
            result: dict[str, Any] = {"ok": False, "message": "unauthorized peer"}
        else:
            raw = await asyncio.wait_for(reader.readline(), timeout=5)
            if not raw or len(raw) > MAX_REQUEST:
                result = {"ok": False, "message": "invalid request size"}
            else:
                request = json.loads(raw)
                operation = request.get("operation")
                payload = request.get("payload", {})
                if not isinstance(operation, str) or not isinstance(payload, dict):
                    result = {"ok": False, "message": "invalid request"}
                else:
                    result = await asyncio.to_thread(_dispatch, operation, payload)
    except (ValueError, json.JSONDecodeError, asyncio.TimeoutError, subprocess.SubprocessError) as exc:
        result = {"ok": False, "message": type(exc).__name__}
    try:
        writer.write(json.dumps(result, separators=(",", ":")).encode() + b"\n")
        await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def main() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise SystemExit("privileged helper must run as root")

    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if SOCKET_PATH.exists():
        SOCKET_PATH.unlink()

    server = await asyncio.start_unix_server(_handle, path=str(SOCKET_PATH))

    try:
        import grp
        os.chown(SOCKET_PATH, 0, grp.getgrnam(PANEL_GROUP).gr_gid)
    except (KeyError, OSError, AttributeError) as exc:
        logger.warning("could not chown socket to group %s: %s", PANEL_GROUP, exc)
    try:
        os.chmod(SOCKET_PATH, 0o660)
    except OSError as exc:
        logger.warning("could not chmod socket: %s", exc)

    logger.info("privileged helper listening on %s", SOCKET_PATH)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
