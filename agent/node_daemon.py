"""
MTGroup VPN Ultimate — Remote Node Daemon
═══════════════════════════════════════════════════════════════════
Lightweight background agent for remote servers.
Receives sync requests from the Master panel, verifies HMAC-SHA256,
applies configs (Xray/Sing-box), and restarts services.
Reports health metrics (CPU, RAM, active connections).
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import subprocess
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
        
        # Determine path and service based on config type
        if "singbox" in config_type.lower() or "sing-box" in config_type.lower():
            target_file = "/etc/sing-box/config.json"
            service = "sing-box"
        elif "xray" in config_type.lower() or "vless" in config_type.lower():
            target_file = "/usr/local/etc/xray/config.json"
            service = "xray"
        else:
            logger.warning(f"Unknown config_type: {config_type}. Defaulting to xray.")
            target_file = "/usr/local/etc/xray/config.json"
            service = "xray"
            
        # Ensure directory exists
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        
        # Write config to disk
        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            
        logger.info(f"Successfully wrote {config_type} config to {target_file}")
        
        # Async restart service
        asyncio.create_task(restart_service(service))
        
        return web.json_response({"status": "synced"})
        
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
    web.run_app(app, host="0.0.0.0", port=PORT, access_log=logger)
