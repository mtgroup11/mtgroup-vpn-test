"""
MTGroup VPN Ultimate — Remote Node Daemon
═══════════════════════════════════════════════════════════════════
Lightweight background agent for remote servers.
Receives commands from the Master panel over ``POST /api/v1/sync``,
verifies HMAC-SHA256 + a ±30s replay window, applies them to the local
Xray/Sing-box config, and restarts the service.
Reports health metrics over ``GET /api/v1/health``, including per-user
traffic when available: ``amnezia_peer_traffic`` (keyed by WireGuard
public key, from ``awg show transfer``) and ``xray_user_traffic`` (keyed
by the client ``email`` set in ``proxy_manager.build_vless_reality_config``,
from Xray's StatsService). Both are best-effort and simply absent from the
response when that protocol isn't provisioned on this node.

Command protocol (``action`` lives inside ``payload``; absent means
``sync``)::

    sync         payload IS the complete config → written wholesale.
                 Xray/Sing-box: payload is the config JSON.
                 AmneziaWG:     payload["config"] is the rendered .conf text.
    drop_user    {"action": "drop_user",   "user_uuid": "<id|email|name>"}
    update_port  {"action": "update_port", "new_port": 8443}
    add_peer     {"action": "add_peer",    "public_key": "...",
                  "allowed_ips": "10.8.0.7/32", "preshared_key": "..."}
    remove_peer  {"action": "remove_peer", "public_key": "..."}

Everything except ``sync`` is *surgical*: it loads the existing config,
mutates it, and writes it back. It never replaces it.

``add_peer``/``remove_peer`` are AmneziaWG-only and are applied to the
running interface with ``awg set`` rather than by restarting the service —
a restart tears down every established tunnel, so adding one user would
disconnect everyone else on the node. The config file is written either
way, so a failed live update still takes effect on the next restart.

Anything with an unrecognised ``action``, and any ``sync`` whose payload
doesn't structurally look like a proxy config, is rejected with 400 and
the on-disk config is left untouched.

This matters because the master multiplexes all of the above through one
endpoint. The previous implementation ignored ``action`` entirely and
wrote whatever arrived straight over ``config.json`` before restarting —
so a ``{"action": "drop_user", ...}`` command (2 keys) replaced the
node's entire configuration and took every user on that node offline.
Writes are atomic (temp file + ``os.replace``) so a crash mid-write can't
leave a truncated config either.

Every AmneziaWG-mutating write (``sync``, ``add_peer``, ``remove_peer``)
arms the local Anti-Lockout Watchdog first (``agent/watchdog_client.py``,
talking to the same daemon ``install.sh`` sets up for Xray/iptables) and
disarms it right after. If this process crashes or hangs mid-change, the
watchdog's own timeout restores the pre-change config on its own.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import subprocess
import tempfile
import time

from aiohttp import web
import psutil

from agent import watchdog_client

# Configuration
API_KEY = os.environ.get("MTGROUP_NODE_API_KEY", "")
PORT = int(os.environ.get("MTGROUP_NODE_PORT", "8443"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("node_daemon")


def verify_signature(api_key: str, signature: str, body_bytes: bytes) -> bool:
    """Verifies the HMAC-SHA256 signature."""
    if not api_key:
        logger.warning("No API_KEY set on the node! Rejecting request.")
        return False
        
    expected_mac = hmac.new(
        api_key.encode("utf-8"),
        body_bytes,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_mac, signature)


# AmneziaWG interface name and its on-disk config. `awg-quick@awg0` is the
# systemd unit template AmneziaWG ships, mirroring wg-quick@.
AWG_INTERFACE = os.environ.get("MTGROUP_AWG_INTERFACE", "awg0")
AWG_CONFIG_PATH = f"/etc/amnezia/amneziawg/{AWG_INTERFACE}.conf"

XRAY_CONFIG_PATH = "/usr/local/etc/xray/config.json"
SINGBOX_CONFIG_PATH = "/etc/sing-box/config.json"

# Loopback-only port Xray's StatsService API listens on, matching
# proxy_manager.build_vless_reality_config's XRAY_API_PORT. Overridable in
# case a node's Xray config was hand-tuned to a different port.
XRAY_API_PORT = int(os.environ.get("MTGROUP_XRAY_API_PORT", "10085"))
XRAY_BIN = os.environ.get("MTGROUP_XRAY_BIN", "xray")


def is_amnezia(config_type: str) -> bool:
    lowered = (config_type or "").lower()
    return "amnezia" in lowered or lowered in {"awg", "wg", "wireguard"}


def resolve_target(config_type: str) -> tuple[str, str]:
    """Map a config_type label to its on-disk config path and systemd unit."""
    lowered = (config_type or "").lower()
    if is_amnezia(lowered):
        return AWG_CONFIG_PATH, f"awg-quick@{AWG_INTERFACE}"
    if "singbox" in lowered or "sing-box" in lowered:
        return SINGBOX_CONFIG_PATH, "sing-box"
    if "xray" in lowered or "vless" in lowered or "trojan" in lowered:
        return XRAY_CONFIG_PATH, "xray"
    logger.warning("Unknown config_type %r — defaulting to xray.", config_type)
    return XRAY_CONFIG_PATH, "xray"


# ── AmneziaWG / WireGuard config editing ──────────────────────────────
#
# wg configs are INI-shaped but `configparser` can't be used: a real config
# has *repeated* [Peer] sections, which configparser collapses. They're also
# whitespace/comment sensitive in ways operators care about, and the
# [Interface] block carries the Amnezia obfuscation parameters (Jc/Jmin/H1…)
# that must survive untouched — losing them silently turns the tunnel back
# into plain detectable WireGuard.

def parse_wg_config(text: str) -> tuple[list[str], list[list[str]]]:
    """
    Split a wg config into (interface_lines, peer_blocks).

    Everything before the first [Peer] is the interface part and is
    preserved verbatim, comments and all.
    """
    interface: list[str] = []
    peers: list[list[str]] = []
    current: list[str] | None = None

    for line in text.splitlines():
        if line.strip().lower().startswith("[peer]"):
            current = [line]
            peers.append(current)
        elif current is None:
            interface.append(line)
        else:
            current.append(line)

    return interface, peers


def render_wg_config(interface: list[str], peers: list[list[str]]) -> str:
    parts: list[str] = []
    body = "\n".join(interface).rstrip()
    if body:
        parts.append(body)
    for peer in peers:
        block = "\n".join(peer).rstrip()
        if block:
            parts.append(block)
    return "\n\n".join(parts) + "\n"


def peer_public_key(block: list[str]) -> str | None:
    for line in block:
        stripped = line.strip()
        if stripped.lower().startswith("publickey"):
            _, _, value = stripped.partition("=")
            return value.strip()
    return None


def build_peer_block(public_key: str, allowed_ips: str, preshared_key: str | None = None) -> list[str]:
    block = ["[Peer]", f"PublicKey = {public_key}"]
    if preshared_key:
        block.append(f"PresharedKey = {preshared_key}")
    block.append(f"AllowedIPs = {allowed_ips}")
    return block


def upsert_peer(
    peers: list[list[str]],
    public_key: str,
    allowed_ips: str,
    preshared_key: str | None = None,
) -> tuple[list[list[str]], bool]:
    """Add or replace a peer. Returns (peers, changed)."""
    new_block = build_peer_block(public_key, allowed_ips, preshared_key)
    for index, block in enumerate(peers):
        if peer_public_key(block) == public_key:
            if block == new_block:
                return peers, False  # already exactly right — don't churn
            peers[index] = new_block
            return peers, True
    peers.append(new_block)
    return peers, True


def remove_peer_block(peers: list[list[str]], public_key: str) -> tuple[list[list[str]], int]:
    """Drop every peer with this public key. Returns (peers, removed_count)."""
    kept = [b for b in peers if peer_public_key(b) != public_key]
    return kept, len(peers) - len(kept)


def read_text_config(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""
    except OSError as exc:
        logger.error("Could not read %s: %s", path, exc)
        return ""


def atomic_write_text(path: str, text: str) -> None:
    """Atomic counterpart to atomic_write_config for non-JSON configs."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".mtgroup-awg-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)  # contains the server private key
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


async def apply_peer_live(public_key: str, allowed_ips: str | None, remove: bool = False) -> bool:
    """
    Apply a peer change to the *running* interface with `awg set`.

    Deliberately avoids restarting the service for peer changes: a restart
    tears down every existing tunnel, so adding one user would disconnect
    everyone else on the node. `awg set` applies live with no disruption.

    Returns True if the live update succeeded. A False here is not fatal —
    the config file has already been written, so the change takes effect on
    the next interface restart; the caller just reports it.
    """
    args = ["awg", "set", AWG_INTERFACE, "peer", public_key]
    if remove:
        args.append("remove")
    elif allowed_ips:
        args += ["allowed-ips", allowed_ips]

    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await proc.communicate()
        if proc.returncode == 0:
            return True
        logger.warning(
            "Live peer update failed (%s): %s — change persisted to %s and "
            "will apply on next interface restart.",
            " ".join(args), stderr.decode(errors="replace").strip(), AWG_CONFIG_PATH,
        )
    except (OSError, FileNotFoundError) as exc:
        logger.warning(
            "Could not run `awg set` (%s) — change persisted to %s and will "
            "apply on next interface restart.", exc, AWG_CONFIG_PATH,
        )
    return False


def looks_like_full_config(payload: object) -> bool:
    """
    Guard against overwriting a live proxy config with something that
    plainly isn't one.

    This exists because of a real incident class: the master sends
    partial-update commands like ``{"action": "drop_user", ...}`` through
    the same endpoint, and the old handler wrote *whatever* it received
    straight over ``config.json`` and restarted the service — taking the
    whole node down for every user on it. Actions are dispatched properly
    now, but this stays as defence in depth: a full sync must at least
    look like an Xray/Sing-box config.
    """
    if not isinstance(payload, dict) or not payload:
        return False
    return any(key in payload for key in ("inbounds", "outbounds", "log", "route", "routing"))


def load_config(path: str) -> dict:
    """Read the current on-disk config. Returns {} when absent/unreadable."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Could not read existing config at %s: %s", path, exc)
        return {}


def atomic_write_config(path: str, config: dict) -> None:
    """
    Write `config` to `path` atomically (temp file in the same directory,
    then `os.replace`). A crash or full disk mid-write must never leave a
    truncated config.json behind — the service would fail to start and the
    node would be down with no easy remote recovery.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    directory = os.path.dirname(path)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".mtgroup-cfg-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _iter_user_lists(config: dict):
    """
    Yield every per-inbound user/client list, across both config dialects.

    Xray:     inbounds[].settings.clients[]
    Sing-box: inbounds[].users[]
    """
    for inbound in config.get("inbounds", []) or []:
        if not isinstance(inbound, dict):
            continue
        clients = (inbound.get("settings") or {}).get("clients")
        if isinstance(clients, list):
            yield inbound["settings"], "clients", clients
        users = inbound.get("users")
        if isinstance(users, list):
            yield inbound, "users", users


# Identity fields a user entry may be keyed by, across both dialects.
# The master currently sends a *username* in the `user_uuid` field (see
# accounting._drop_user_from_nodes), so match broadly rather than assuming
# the value is a UUID.
_USER_IDENTITY_FIELDS = ("id", "uuid", "email", "name", "username")


def drop_user_from_config(config: dict, identifier: str) -> int:
    """Remove a user from every inbound. Returns how many entries were removed."""
    removed = 0
    for container, key, entries in _iter_user_lists(config):
        kept = [
            e for e in entries
            if not (
                isinstance(e, dict)
                and any(str(e.get(f, "")) == identifier for f in _USER_IDENTITY_FIELDS)
            )
        ]
        removed += len(entries) - len(kept)
        container[key] = kept
    return removed


def set_port_in_config(config: dict, new_port: int) -> int:
    """Repoint every inbound at `new_port`. Returns how many were changed."""
    changed = 0
    for inbound in config.get("inbounds", []) or []:
        if not isinstance(inbound, dict):
            continue
        for port_key in ("port", "listen_port"):
            if port_key in inbound and inbound[port_key] != new_port:
                inbound[port_key] = new_port
                changed += 1
    return changed


async def restart_service(service_name: str):
    """Restarts a systemd service asynchronously."""
    try:
        logger.info(f"Restarting service: {service_name}")
        process = await asyncio.create_subprocess_exec(
            "systemctl", "restart", service_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            logger.error(f"Failed to restart {service_name}: {stderr.decode()}")
        else:
            logger.info(f"Successfully restarted {service_name}")
    except Exception as e:
        logger.error(f"Error restarting {service_name}: {e}")


async def sync_handler(request: web.Request) -> web.Response:
    """
    POST /api/v1/sync
    Receives JSON configuration, validates signature, writes to disk,
    and restarts the appropriate service.
    """
    signature = request.headers.get("X-MTGroup-Signature", "")
    request.headers.get("X-MTGroup-Timestamp", "")
    
    body_bytes = await request.read()
    
    # Verify Signature
    if not verify_signature(API_KEY, signature, body_bytes):
        logger.warning("Invalid signature on sync request.")
        return web.json_response({"error": "Unauthorized"}, status=401)
        
    try:
        data = json.loads(body_bytes)
        # Prevent replay attacks (Strict ±30s Sliding Time Window)
        req_ts = int(data.get("_ts", 0))
        now = int(time.time())
        time_diff = abs(now - req_ts)
        if time_diff > 30:
            logger.warning(f"Request rejected: time drift of {time_diff}s outside ±30s window (ts: {req_ts}, now: {now}).")
            return web.json_response({"error": "Unauthorized - Request expired"}, status=401)
            
        config_type = data.get("config_type", "")
        payload = data.get("payload", {})
        if not isinstance(payload, dict):
            return web.json_response({"error": "payload must be an object"}, status=400)

        target_file, service = resolve_target(config_type)

        # ── Action dispatch ────────────────────────────────────────────
        # The master multiplexes several command types over this one
        # endpoint. `action` is carried inside `payload` (see
        # accounting._drop_user_from_nodes / port_hopper._hopping_loop);
        # accepted at the top level too for forward compatibility.
        # A full config push has no action at all.
        action = data.get("action") or payload.get("action") or "sync"

        if action == "sync":
            if is_amnezia(config_type):
                # AmneziaWG configs are INI text, not JSON — a full sync
                # carries the rendered file in `payload["config"]`. Writing a
                # JSON blob here would leave awg-quick unable to parse its own
                # config and the interface down.
                rendered = payload.get("config")
                if not isinstance(rendered, str) or "[Interface]" not in rendered:
                    logger.error(
                        "Refusing AmneziaWG sync: payload.config must be the "
                        "rendered .conf text containing an [Interface] section. "
                        "Node config left untouched.",
                    )
                    return web.json_response(
                        {"error": "amnezia sync requires payload.config as rendered .conf text"},
                        status=400,
                    )
                watchdog_client.arm_and_snapshot(target_file)
                atomic_write_text(target_file, rendered)
                logger.info("Wrote full AmneziaWG config to %s", target_file)
                asyncio.create_task(restart_service(service))
                watchdog_client.disarm()
                return web.json_response({"status": "synced"})

            if not looks_like_full_config(payload):
                # Refuse rather than clobber a working config with a blob
                # that isn't one. Returning 400 makes the master's retry
                # queue surface it instead of silently bricking the node.
                logger.error(
                    "Refusing full sync for %s: payload does not look like a "
                    "proxy config (keys=%s). Node config left untouched.",
                    config_type, sorted(payload)[:10],
                )
                return web.json_response(
                    {"error": "payload does not look like a full proxy config"},
                    status=400,
                )
            atomic_write_config(target_file, payload)
            logger.info("Wrote full %s config to %s", config_type, target_file)
            asyncio.create_task(restart_service(service))
            return web.json_response({"status": "synced"})

        if action == "drop_user":
            identifier = str(payload.get("user_uuid") or payload.get("username") or "")
            if not identifier:
                return web.json_response({"error": "drop_user requires user_uuid"}, status=400)

            config = load_config(target_file)
            if not config:
                logger.warning("drop_user: no existing config at %s — nothing to do.", target_file)
                return web.json_response({"status": "noop", "reason": "no config on disk"})

            removed = drop_user_from_config(config, identifier)
            if removed == 0:
                # Not an error: the user may already be gone, or was never
                # provisioned here. Do not rewrite or restart for nothing.
                logger.info("drop_user: %s not present in %s — no change.", identifier, target_file)
                return web.json_response({"status": "noop", "removed": 0})

            atomic_write_config(target_file, config)
            logger.info("drop_user: removed %d entr(ies) for %s from %s", removed, identifier, target_file)
            asyncio.create_task(restart_service(service))
            return web.json_response({"status": "applied", "action": action, "removed": removed})

        if action == "update_port":
            raw_port = payload.get("new_port")
            try:
                new_port = int(raw_port)
            except (TypeError, ValueError):
                return web.json_response({"error": "update_port requires an integer new_port"}, status=400)
            if not (1 <= new_port <= 65535):
                return web.json_response({"error": f"new_port {new_port} out of range"}, status=400)

            config = load_config(target_file)
            if not config:
                logger.warning("update_port: no existing config at %s — nothing to do.", target_file)
                return web.json_response({"status": "noop", "reason": "no config on disk"})

            changed = set_port_in_config(config, new_port)
            if changed == 0:
                logger.info("update_port: %s already on port %d — no change.", target_file, new_port)
                return web.json_response({"status": "noop", "changed": 0})

            atomic_write_config(target_file, config)
            logger.info("update_port: repointed %d inbound(s) to %d in %s", changed, new_port, target_file)
            asyncio.create_task(restart_service(service))
            return web.json_response({"status": "applied", "action": action, "changed": changed})

        if action in ("add_peer", "remove_peer"):
            if not is_amnezia(config_type):
                return web.json_response(
                    {"error": f"{action} is only valid for amnezia_wg nodes, got {config_type!r}"},
                    status=400,
                )

            # Validate the request fully before looking at node state, so a
            # malformed command is rejected the same way regardless of
            # whether the interface happens to be provisioned yet.
            public_key = str(payload.get("public_key") or "")
            if not public_key:
                return web.json_response({"error": f"{action} requires public_key"}, status=400)

            allowed_ips = str(payload.get("allowed_ips") or "")
            if action == "add_peer" and not allowed_ips:
                return web.json_response({"error": "add_peer requires allowed_ips"}, status=400)

            existing = read_text_config(target_file)
            if not existing.strip():
                logger.warning(
                    "%s: no AmneziaWG config at %s — the interface has not been "
                    "provisioned on this node.", action, target_file,
                )
                return web.json_response(
                    {"status": "noop", "reason": "no amneziawg config on disk"},
                )

            interface, peers = parse_wg_config(existing)

            if action == "add_peer":
                peers, changed = upsert_peer(
                    peers, public_key, allowed_ips, payload.get("preshared_key"),
                )
                if not changed:
                    return web.json_response({"status": "noop", "reason": "peer already present"})
                watchdog_client.arm_and_snapshot(target_file)
                atomic_write_text(target_file, render_wg_config(interface, peers))
                live = await apply_peer_live(public_key, allowed_ips)
                watchdog_client.disarm()
                logger.info("add_peer: %s -> %s (live=%s)", public_key[:16], allowed_ips, live)
                return web.json_response({"status": "applied", "action": action, "live": live})

            peers, removed = remove_peer_block(peers, public_key)
            if removed == 0:
                return web.json_response({"status": "noop", "removed": 0})
            watchdog_client.arm_and_snapshot(target_file)
            atomic_write_text(target_file, render_wg_config(interface, peers))
            live = await apply_peer_live(public_key, None, remove=True)
            watchdog_client.disarm()
            logger.info("remove_peer: %s (removed=%d, live=%s)", public_key[:16], removed, live)
            return web.json_response(
                {"status": "applied", "action": action, "removed": removed, "live": live}
            )

        # Unknown action: never fall through to writing the config.
        logger.error("Rejecting unknown action %r — node config left untouched.", action)
        return web.json_response({"error": f"unknown action: {action}"}, status=400)

    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        logger.error(f"Error in sync_handler: {e}")
        return web.json_response({"error": "Internal Server Error"}, status=500)


def get_active_connections() -> int:
    """Counts active connections (ESTABLISHED) on common VPN ports."""
    try:
        output = subprocess.check_output(
            "ss -tn state established '( sport = :443 or sport = :80 or sport = :8443 )' | wc -l",
            shell=True
        )
        # ss output includes a header line, so we subtract 1 (handled if wc -l > 1)
        # Using a simple count via psutil might be safer across OSes
        count = int(output.decode().strip())
        return max(0, count - 1)
    except Exception:
        # Fallback to psutil
        try:
            count = sum(1 for conn in psutil.net_connections(kind='tcp') 
                        if conn.status == 'ESTABLISHED' and conn.laddr.port in (80, 443, 8443, 8080))
            return count
        except Exception:
            return 0


# ── Per-user traffic collection ────────────────────────────────────────
#
# Both functions below are best-effort telemetry: neither raises, and both
# return {} whenever the relevant protocol isn't provisioned on this node
# or its stats source isn't reachable. Callers (health_handler) only
# include the corresponding key in the response when it's non-empty, so
# an unconfigured protocol doesn't clutter every health check on nodes
# that don't run it.

def parse_awg_transfer(output: str) -> dict[str, dict[str, int]]:
    """
    Parse `awg show <iface> transfer` output: one
    `public_key\trx_bytes\ttx_bytes` line per peer (wg-tools' standard
    machine-readable dump format, which awg is CLI-compatible with).
    """
    traffic: dict[str, dict[str, int]] = {}
    for line in output.splitlines():
        parts = line.strip().split("\t")
        if len(parts) != 3:
            continue
        public_key, rx, tx = parts
        try:
            traffic[public_key] = {"rx_bytes": int(rx), "tx_bytes": int(tx)}
        except ValueError:
            continue
    return traffic


async def get_amnezia_peer_traffic() -> dict[str, dict[str, int]]:
    """
    Per-peer cumulative rx/tx byte counters for the local AmneziaWG
    interface, keyed by public key — matches `WireGuardPeer.public_key`
    on the master, so no extra identity mapping is needed there.
    """
    if not os.path.exists(AWG_CONFIG_PATH):
        return {}
    try:
        proc = await asyncio.create_subprocess_exec(
            "awg", "show", AWG_INTERFACE, "transfer",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            logger.warning(
                "`awg show %s transfer` failed: %s",
                AWG_INTERFACE, stderr.decode(errors="replace").strip(),
            )
            return {}
        return parse_awg_transfer(stdout.decode(errors="replace"))
    except (OSError, FileNotFoundError) as exc:
        logger.warning("Could not run `awg show transfer`: %s", exc)
        return {}


def parse_xray_stats(raw_json: str) -> dict[str, int]:
    """
    Parse `xray api statsquery` JSON output into {email: total_bytes},
    summing each user's uplink+downlink. Stat names look like
    `user>>>{email}>>>traffic>>>uplink` / `...>>>downlink` — see
    proxy_manager.build_vless_reality_config, which is what tags clients
    with `email` in the first place.
    """
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return {}

    totals: dict[str, int] = {}
    for entry in data.get("stat", []) or []:
        if not isinstance(entry, dict):
            continue
        parts = str(entry.get("name", "")).split(">>>")
        if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
            continue
        email = parts[1]
        try:
            totals[email] = totals.get(email, 0) + int(entry.get("value", 0))
        except (TypeError, ValueError):
            continue
    return totals


async def get_xray_user_traffic() -> dict[str, int]:
    """
    Per-user cumulative traffic (uplink+downlink bytes) from Xray's
    StatsService, keyed by client `email`. Returns {} on any older config
    that predates the stats/api inbound (see proxy_manager.py) as much as
    on a missing xray binary — both are "no data available", not errors.
    """
    if not os.path.exists(XRAY_CONFIG_PATH):
        return {}
    try:
        proc = await asyncio.create_subprocess_exec(
            XRAY_BIN, "api", "statsquery",
            f"--server=127.0.0.1:{XRAY_API_PORT}", "-pattern", "user>>>",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            logger.warning(
                "`xray api statsquery` failed (API inbound may not be "
                "configured on this node's config): %s",
                stderr.decode(errors="replace").strip(),
            )
            return {}
        return parse_xray_stats(stdout.decode(errors="replace"))
    except (OSError, FileNotFoundError) as exc:
        logger.warning("Could not run `xray api statsquery`: %s", exc)
        return {}


async def health_handler(request: web.Request) -> web.Response:
    """
    GET /api/v1/health
    Returns system metrics.
    """
    signature = request.headers.get("X-MTGroup-Signature", "")
    
    # GET requests have their _ts reconstructed from headers or we expect a signed body with just _ts
    # As per orchestrator.py, it sends GET with body {"_ts": ts} but httpx doesn't send body on GET!
    # Let's check orchestrator.py line 153:
    # "GET: body not sent over wire, but Node reconstructs {"_ts":<ts>} from header to verify"
    ts = request.headers.get("X-MTGroup-Timestamp", "0")
    
    reconstructed_body = json.dumps({"_ts": int(ts)}, separators=(',', ':')).encode("utf-8")
    
    if not verify_signature(API_KEY, signature, reconstructed_body):
        logger.warning("Invalid signature on health request.")
        return web.json_response({"error": "Unauthorized"}, status=401)
        
    try:
        # Prevent replay attacks (Strict ±30s Sliding Time Window)
        now = int(time.time())
        req_ts = int(ts)
        time_diff = abs(now - req_ts)
        if time_diff > 30:
            logger.warning(f"Health request rejected: time drift of {time_diff}s outside ±30s window (ts: {req_ts}, now: {now}).")
            return web.json_response({"error": "Unauthorized - Request expired"}, status=401)
            
        cpu_usage = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        active_conns = get_active_connections()

        response = {
            "status": "healthy",
            "current_connections": active_conns,
            "cpu_usage": cpu_usage,
            "ram_usage_percent": mem.percent,
            "ram_free_mb": mem.available // (1024 * 1024)
        }

        amnezia_traffic = await get_amnezia_peer_traffic()
        if amnezia_traffic:
            response["amnezia_peer_traffic"] = amnezia_traffic

        xray_traffic = await get_xray_user_traffic()
        if xray_traffic:
            response["xray_user_traffic"] = xray_traffic

        return web.json_response(response)
    except Exception as e:
        logger.error(f"Error in health_handler: {e}")
        return web.json_response({"error": "Internal Server Error"}, status=500)


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_post("/api/v1/sync", sync_handler)
    app.router.add_get("/api/v1/health", health_handler)
    return app


if __name__ == "__main__":
    if not API_KEY:
        logger.warning("Starting WITHOUT API_KEY. All requests will be rejected!")
    else:
        logger.info("Starting MTGroup Node Daemon...")
        
    app = create_app()
    # SSL context can be added here if needed, but orchestrator uses verify=False
    # so we can run behind a local reverse proxy or expose directly over HTTP/HTTPS
    web.run_app(app, host="0.0.0.0", port=PORT, access_log=logger)  # nosec B104 - node daemon must be reachable by the master panel over the network
