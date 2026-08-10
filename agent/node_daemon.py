"""
MTGroup VPN Ultimate — Remote Node Daemon
═══════════════════════════════════════════════════════════════════
Lightweight background agent for remote servers.
Receives commands from the Master panel over ``POST /api/v1/sync``,
verifies HMAC-SHA256 + a ±30s replay window, applies them to the local
Xray/Sing-box config, and restarts the service.
Reports health metrics over ``GET /api/v1/health``.

Command protocol (``action`` lives inside ``payload``; absent means
``sync``)::

    sync         payload IS the complete proxy config → written wholesale
    drop_user    {"action": "drop_user",   "user_uuid": "<id|email|name>"}
    update_port  {"action": "update_port", "new_port": 8443}

``drop_user`` and ``update_port`` are *surgical*: they load the existing
config, mutate it, and write it back. They never replace it.

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


def resolve_target(config_type: str) -> tuple[str, str]:
    """Map a config_type label to its on-disk config path and systemd unit."""
    lowered = (config_type or "").lower()
    if "singbox" in lowered or "sing-box" in lowered:
        return "/etc/sing-box/config.json", "sing-box"
    if "xray" in lowered or "vless" in lowered or "trojan" in lowered:
        return "/usr/local/etc/xray/config.json", "xray"
    logger.warning("Unknown config_type %r — defaulting to xray.", config_type)
    return "/usr/local/etc/xray/config.json", "xray"


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
        
        return web.json_response({
            "status": "healthy",
            "current_connections": active_conns,
            "cpu_usage": cpu_usage,
            "ram_usage_percent": mem.percent,
            "ram_free_mb": mem.available // (1024 * 1024)
        })
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
