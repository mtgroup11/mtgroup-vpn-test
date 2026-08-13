import contextlib
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import logging
import asyncio
import hmac
import os

from backend.app.core.killswitch import killswitch
from backend.app.core.config import settings
from backend.app.core.honeypot import honeypot
from backend.app.generators.port_hopper import AsyncPortHoppingEngine
from backend.app.core.ai_detector import AnomalyPredictor
from backend.app.core.auto_cdn import SingularityAutoCDN
from backend.app.core.routing_engine import SNIMultiplexer
from backend.app.core.accounting import TrafficAccountingEngine
from backend.app.orchestrator import orchestrator
from backend.app.models import create_db_engine, create_session_factory, init_db
from backend.app.api.auth import get_db
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from bcc import BPF  # type: ignore
    HAS_BCC = True
except ImportError:
    HAS_BCC = False

bpf_instance = None
hopper_engine = None
ai_engine = None
db_session_factory = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global bpf_instance, hopper_engine, ai_engine, db_session_factory
    logging.info("🚀 XDP-Spectre Central Orchestrator Booting...")
    
    if not settings.DEBUG:
        if not settings.DB_ENCRYPTION_KEY or settings.DB_ENCRYPTION_KEY == "mtgroup-vpn-ultimate-default-dev-key-CHANGE-ME":
            raise RuntimeError("CRITICAL: DB_ENCRYPTION_KEY is empty or default in PRODUCTION (DEBUG=False). Set a secure key to start.")
        if not settings.ADMIN_PASSWORD or settings.ADMIN_PASSWORD == "MTGroup@2024!Secure":
            raise RuntimeError("CRITICAL: ADMIN_PASSWORD is empty or default in PRODUCTION (DEBUG=False). Set a secure password to start.")
        if not settings.STEALTH_TOKEN:
            raise RuntimeError("CRITICAL: STEALTH_TOKEN is empty in PRODUCTION (DEBUG=False). Set a secure token to start.")
    
    if HAS_BCC and getattr(settings, 'EBPF_ENABLED', False):
        try:
            xdp_path = os.path.join(os.path.dirname(__file__), "ebpf", "xdp_drop.c")
            with open(xdp_path, "r") as f:
                bpf_text = f.read()
                
            logging.info("Compiling and loading XDP-Spectre BPF module...")
            bpf_instance = BPF(text=bpf_text)
            
            # Attach to dummy interface for now, in real deployment use config.settings.IFACE
            iface = getattr(settings, 'IFACE', "eth0")
            try:
                fn = bpf_instance.load_func("xdp_spectre_prog", BPF.XDP)
                bpf_instance.attach_xdp(iface, fn, 0)
                logging.info(f"XDP program attached to {iface}")
            except Exception as e:
                logging.warning(f"Could not attach XDP to {iface}: {e}. Running in simulation mode.")
        except Exception as e:
            logging.error(f"Failed to load BPF module: {e}")
    elif not getattr(settings, 'EBPF_ENABLED', False):
        logging.warning("eBPF Disabled in configuration. XDP-Spectre running in basic functional mode (Graceful Degradation).")
    else:
        logging.warning("BCC not installed but EBPF_ENABLED is true. XDP-Spectre running in simulation mode.")

    # Initialize Database
    engine = create_db_engine(settings.DATABASE_URL)
    await init_db(engine)
    logging.info("SQLite Async Database initialized.")

    db_session_factory = create_session_factory(engine)

    # Wire up the real DB session dependency. `get_db` in api/auth.py is a
    # placeholder that raises NotImplementedError by design — every
    # DB-backed endpoint depends on it, so without this override the
    # production app 500s on first DB access.
    async def _get_db() -> AsyncGenerator[AsyncSession, None]:
        async with db_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _get_db

    # Initialize Engines
    hopper_engine = AsyncPortHoppingEngine(db_session_factory=db_session_factory)
    if bpf_instance:
        hopper_engine._bpf = bpf_instance
        
    ai_engine = AnomalyPredictor()

    # XDP stats exporter. /run/mtgroup/xdp_stats.json (read by cli.py and
    # the Telegram bot's eBPF panel) had no writer anywhere before this —
    # both displays were permanently zero. Only meaningful alongside real
    # eBPF, so gated the same way as hopper_engine/ai_engine below.
    from backend.app.api.metrics import xdp_loader
    from backend.app.core.xdp_stats_exporter import XDPStatsExporter
    xdp_stats_exporter = XDPStatsExporter(xdp_loader)

    # Auto-CDN / Smart SNI engine. Its two hooks now do real work
    # (_check_sni_health probes every active node's Reality SNI with a real
    # TLS handshake; _manage_auto_cdn tests fallback Cloudflare candidates),
    # so — per the standing instruction in CLAUDE.md — it's gated on
    # `settings.CDN_ENABLED` rather than starting unconditionally the way it
    # did while both hooks were still `pass` stubs. Operators who haven't
    # opted into CDN fronting get none of this on a routine upgrade.
    autocdn_engine = SingularityAutoCDN(session_factory=db_session_factory)

    # SNI Multiplexer / active-probe deflection. Backend routes are
    # registered from the DB's active nodes (node.sni -> node.address:port)
    # so a matching ClientHello SNI is forwarded straight to that node
    # instead of falling through to the decoy — see _sni_mux_sync_loop
    # below, which also re-syncs periodically so added/removed/renamed
    # nodes are picked up without a restart.
    sni_mux = SNIMultiplexer(
        listen_port=settings.SNI_MULTIPLEXER_PORT,
        decoy_target=settings.DECOY_REVERSE_PROXY_TARGET,
    )

    async def _sni_mux_sync_loop():
        """Keep the mux's backend routes in sync with active nodes.

        Runs once immediately (so routes exist before the first connection
        arrives) and then every SNI_MUX_SYNC_INTERVAL_SEC. Nodes without a
        `sni` set are skipped — there's nothing to route on.
        """
        from sqlalchemy import select as _select
        from backend.app.models import Node as _Node

        known_patterns: set[str] = set()
        while True:
            try:
                async with db_session_factory() as session:
                    result = await session.execute(
                        _select(_Node).where(_Node.is_active)
                    )
                    nodes = list(result.scalars().all())

                current_patterns: set[str] = set()
                for node in nodes:
                    if not node.sni:
                        continue
                    current_patterns.add(node.sni)
                    await sni_mux.add_backend(
                        sni_pattern=node.sni,
                        backend_host=node.address,
                        backend_port=node.port,
                        protocol_tag=node.protocol.value if node.protocol else "vless-reality",
                    )

                for stale_pattern in known_patterns - current_patterns:
                    await sni_mux.remove_backend(stale_pattern)

                known_patterns = current_patterns
            except asyncio.CancelledError:
                raise
            except Exception:
                logging.exception("SNI multiplexer node-route sync failed; will retry next cycle.")

            await asyncio.sleep(getattr(settings, "SNI_MUX_SYNC_INTERVAL_SEC", 60))

    # Traffic accounting / quota enforcement. Runs live (dry_run=False) —
    # see the ACCOUNTING_ENABLED comment in core/config.py for the
    # audit-before-enabling checklist.
    accounting_engine = TrafficAccountingEngine(
        db_session_factory=db_session_factory, dry_run=False
    )
    orchestrator.set_accounting_engine(accounting_engine)

    # Inject db_session_factory to orchestrator
    orchestrator._db_session_factory = db_session_factory

    # Start background tasks conditionally
    logging.info("Starting background engines...")
    # orchestrator.start() launches its retry-queue worker and node
    # health-poll loop. Previously never called anywhere — the
    # db_session_factory injection above was the only wiring that existed,
    # so failed config pushes never actually retried and node health was
    # never polled in production; only tests exercised these loops.
    tasks = [honeypot.start(), orchestrator.start()]  # App-level decoy + Node Orchestrator always start
    if getattr(settings, 'CDN_ENABLED', False):
        tasks.append(autocdn_engine.start())
        logging.info("CDN fronting enabled. Auto-CDN & Smart SNI engine started.")
    else:
        logging.info("CDN_ENABLED is false. Auto-CDN & Smart SNI engine bypassed.")
    sni_mux_sync_task = None
    if getattr(settings, 'SNI_MULTIPLEXER_ENABLED', False):
        tasks.append(sni_mux.start())
        # _sni_mux_sync_loop() runs forever, so it's backgrounded via
        # create_task rather than placed in `tasks` (which is awaited via
        # asyncio.gather below and would block startup forever otherwise).
        sni_mux_sync_task = asyncio.create_task(_sni_mux_sync_loop())
        logging.info("SNI_MULTIPLEXER_ENABLED. SNI multiplexer / probe deflection started on :%s.", settings.SNI_MULTIPLEXER_PORT)
    else:
        logging.info("SNI_MULTIPLEXER_ENABLED is false. SNI multiplexer bypassed.")
    if getattr(settings, 'ACCOUNTING_ENABLED', False):
        tasks.append(accounting_engine.start())
        logging.info("ACCOUNTING_ENABLED. Traffic accounting engine started LIVE (dry_run=False) — over-quota users/agents will be suspended.")
    else:
        logging.info("ACCOUNTING_ENABLED is false. Traffic accounting engine bypassed.")
    if getattr(settings, 'EBPF_ENABLED', False):
        tasks.append(hopper_engine.start())
        tasks.append(ai_engine.start())
        tasks.append(xdp_stats_exporter.start())
        logging.info("AI Detector, Port Hopper, and XDP stats exporter started.")
    else:
        logging.warning("eBPF Disabled. AI Detector, Port Hopper, and XDP stats exporter are fully bypassed to save resources.")

    await asyncio.gather(*tasks)

    yield

    logging.info(" Shutting down gracefully...")
    stop_tasks = [honeypot.stop(), orchestrator.stop()]
    if getattr(settings, 'CDN_ENABLED', False):
        stop_tasks.append(autocdn_engine.stop())
    if getattr(settings, 'SNI_MULTIPLEXER_ENABLED', False):
        if sni_mux_sync_task is not None:
            sni_mux_sync_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sni_mux_sync_task
        stop_tasks.append(sni_mux.stop())
    if getattr(settings, 'ACCOUNTING_ENABLED', False):
        stop_tasks.append(accounting_engine.stop())
    if getattr(settings, 'EBPF_ENABLED', False):
        stop_tasks.append(hopper_engine.stop())
        stop_tasks.append(ai_engine.stop())
        stop_tasks.append(xdp_stats_exporter.stop())

    await asyncio.gather(*stop_tasks)
    
    if HAS_BCC and bpf_instance:
        try:
            iface = getattr(settings, 'IFACE', "eth0")
            bpf_instance.remove_xdp(iface, 0)
            logging.info(f"Detached XDP program from {iface}")
        except Exception:
            pass

# Zero-UI FastAPI Setup
app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

# Global middleware. These were defined in api/rate_limiter.py but never
# actually registered — meaning there was no rate limiting or security
# headers on any response except the per-endpoint checks auth.py does
# itself. BannedIPMiddleware is intentionally NOT registered here: it
# needs a db_session_factory that only exists once the lifespan has run,
# and orchestrator.is_app_banned() (checked in stealth_middleware below)
# already covers the same app-level ban set without that ordering problem.
from backend.app.api.rate_limiter import RateLimitMiddleware, SecurityHeadersMiddleware  # noqa: E402

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)

# Register API Routers
from backend.app.api.auth import router as auth_router  # noqa: E402
from backend.app.api.users import router as users_router  # noqa: E402
from backend.app.api.nodes import router as nodes_router  # noqa: E402
from backend.app.api.subscriptions import router as subscriptions_router  # noqa: E402
from backend.app.api.system import router as system_router  # noqa: E402
from backend.app.api.metrics import router as metrics_router  # noqa: E402
from backend.app.api.resellers import router as resellers_router  # noqa: E402

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(nodes_router)
app.include_router(subscriptions_router)
app.include_router(system_router)
app.include_router(metrics_router)
app.include_router(resellers_router) 

# Stealth Middleware
@app.middleware("http")
async def stealth_middleware(request: Request, call_next):
    # App-level IP Ban kontrolü (eBPF kapalıysa Honeypot cezası buraya düşer)
    if orchestrator.is_app_banned(request.client.host):
        return JSONResponse(status_code=403, content={"detail": "Forbidden (App-Level Ban)"})
        
    # Gelen isteklerde 'X-Stealth-Token' header kontrolü (config'den, sabit değil)
    token = request.headers.get("X-Stealth-Token") or ""
    if not settings.STEALTH_TOKEN or not hmac.compare_digest(token, settings.STEALTH_TOKEN):
        # Sıradan projelere ve tarayıcılara kendini gizle
        logging.warning(f"Unauthorized access attempt from {request.client.host}")
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    return await call_next(request)

@app.post("/api/v1/system/killswitch/trigger")
async def api_trigger_killswitch():
    await killswitch.trigger_lockdown()
    return {"status": "lockdown_active", "message": "All non-VPN traffic is now DROPPED at XDP layer."}

@app.post("/api/v1/system/killswitch/release")
async def api_release_killswitch():
    await killswitch.release_lockdown()
    return {"status": "lockdown_released", "message": "Traffic flowing normally."}

@app.post("/api/v1/system/porthop/trigger")
async def api_trigger_porthop():
    if not hopper_engine:
        return {"status": "error", "message": "Hopper engine not running"}
    new_port = hopper_engine.hopper.force_hop()
    return {"status": "porthop_active", "new_port": new_port, "message": f"Global port hop triggered. New port: {new_port}"}

@app.get("/health")
@app.get("/api/v1/health")
async def health_check():
    import random
    # Return mock telemetry data blended with real killswitch state
    return {
        "status": "healthy",
        "killswitch_active": killswitch.active,
        "nodes": [
            {"name": "Node-IR-01 (Tehran)", "traffic": f"{random.randint(400, 500)} Mbps", "percent": random.randint(40, 50), "color": "blue"},
            {"name": "Node-CN-04 (Beijing)", "traffic": f"{random.randint(50, 100)} Mbps", "percent": random.randint(10, 20), "color": "blue"},
            {"name": "Node-RU-02 (Moscow)", "traffic": f"1.{random.randint(1, 4)} Gbps", "percent": random.randint(85, 95), "color": "red"}
        ],
        "anomalies": [
            {"ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}", "score": round(random.uniform(0.85, 0.99), 2), "action": "BLOCKED"}
        ]
    }
