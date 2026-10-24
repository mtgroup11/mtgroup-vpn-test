import contextlib
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
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
from backend.app.api.auth import get_db, require_admin
from backend.app.core.logging_config import audit_logger
from backend.app.core.stealth import nginx_404 as _nginx_404
from sqlalchemy.ext.asyncio import AsyncSession

# Client-facing subscription URLs. VPN clients (v2rayN, Clash, sing-box,
# Streisand, ...) fetch these with a plain GET and cannot attach custom
# headers, so they must bypass the X-Stealth-Token gate — the unguessable
# 256-bit subscription token in the path is their credential instead.
# Must match the literal prefix used by api/subscriptions.py's routes.
_SUBSCRIPTION_PUBLIC_PREFIX = "/sub/"


def _enforce_production_secrets() -> None:
    """Refuse to boot with missing/weak secrets when DEBUG is off.

    Each of these, left at its default, is a full compromise on its own:
    DB_ENCRYPTION_KEY protects every encrypted column, ADMIN_PASSWORD is
    the seeded admin login, STEALTH_TOKEN is the only thing hiding the API,
    and JWT_SECRET_KEY signs every session. JWT_SECRET_KEY's default is a
    random per-process value — "secure" but useless in production, because
    every restart logs everyone out and each uvicorn worker would sign with
    a different key, so tokens fail at random depending on which worker
    serves the request.
    """
    if settings.DEBUG:
        return
    problems: list[str] = []

    def _placeholder(value: str) -> bool:
        # .env.example ships `CHANGE_ME...` values that are long enough to
        # pass every length check below — and are public in the repo. A
        # README-style `cp .env.example .env` used to boot in production
        # with a known JWT secret, i.e. anyone could mint admin tokens.
        return value.strip().upper().startswith("CHANGE_ME")

    if (not settings.DB_ENCRYPTION_KEY
            or settings.DB_ENCRYPTION_KEY == "mtgroup-vpn-ultimate-default-dev-key-CHANGE-ME"
            or _placeholder(settings.DB_ENCRYPTION_KEY)):
        problems.append("DB_ENCRYPTION_KEY is empty or the shipped default")
    if (not settings.ADMIN_PASSWORD or settings.ADMIN_PASSWORD == "MTGroup@2024!Secure"
            or _placeholder(settings.ADMIN_PASSWORD)):
        problems.append("ADMIN_PASSWORD is empty or the shipped default")
    elif len(settings.ADMIN_PASSWORD) < 12:
        problems.append("ADMIN_PASSWORD must be at least 12 characters")
    if not settings.STEALTH_TOKEN or _placeholder(settings.STEALTH_TOKEN):
        problems.append("STEALTH_TOKEN is empty or the shipped placeholder")
    elif len(settings.STEALTH_TOKEN) < 24:
        problems.append("STEALTH_TOKEN must be at least 24 characters")
    if "JWT_SECRET_KEY" not in settings.model_fields_set:
        problems.append("JWT_SECRET_KEY is not set (a random per-process key breaks sessions across restarts/workers)")
    elif _placeholder(settings.JWT_SECRET_KEY):
        problems.append("JWT_SECRET_KEY is the shipped placeholder")
    elif len(settings.JWT_SECRET_KEY) < 32:
        problems.append("JWT_SECRET_KEY must be at least 32 characters")
    if problems:
        raise RuntimeError(
            "CRITICAL: refusing to start in PRODUCTION (DEBUG=False): "
            + "; ".join(problems)
            + ". Fix your .env (see .env.example) and restart."
        )

try:
    from bcc import BPF  # type: ignore
    HAS_BCC = True
except ImportError:
    HAS_BCC = False

bpf_instance = None
hopper_engine = None
ai_engine = None
db_session_factory = None
telegram_engine = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global bpf_instance, hopper_engine, ai_engine, db_session_factory, telegram_engine
    logging.info("🚀 XDP-Spectre Central Orchestrator Booting...")

    _enforce_production_secrets()
    
    if HAS_BCC and getattr(settings, 'EBPF_ENABLED', False):
        try:
            xdp_path = os.path.join(os.path.dirname(__file__), "ebpf", "xdp_drop.c")
            with open(xdp_path, "r") as f:
                bpf_text = f.read()
                
            logging.info("Compiling and loading XDP-Spectre BPF module...")
            bpf_instance = BPF(text=bpf_text)
            
            iface = settings.EBPF_INTERFACE
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

    from backend.app.core import node_user_sync
    if settings.NODE_USER_SYNC_ENABLED:
        node_user_sync.user_sync = node_user_sync.NodeUserSync(
            db_session_factory, orchestrator, interval_sec=settings.NODE_USER_SYNC_INTERVAL_SEC,
        )

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
    if node_user_sync.user_sync is not None:
        tasks.append(node_user_sync.user_sync.start())
        logging.info("NODE_USER_SYNC_ENABLED. Provisioning users onto VLESS-Reality nodes.")
    else:
        logging.info("NODE_USER_SYNC_ENABLED is false. Node Xray configs are not managed by the panel.")
    if getattr(settings, 'EBPF_ENABLED', False):
        tasks.append(hopper_engine.start())
        tasks.append(ai_engine.start())
        tasks.append(xdp_stats_exporter.start())
        logging.info("AI Detector, Port Hopper, and XDP stats exporter started.")
    else:
        logging.warning("eBPF Disabled. AI Detector, Port Hopper, and XDP stats exporter are fully bypassed to save resources.")

    await asyncio.gather(*tasks)

    # Telegram bot. Started last and isolated: a bad token or Telegram
    # being unreachable from this host (common in censored networks) must
    # never take the panel down with it.
    from backend.app.telegram_bot import SingularityTelegramBot
    telegram_engine = SingularityTelegramBot(db_session_factory)
    try:
        await telegram_engine.start()
    except Exception:
        logging.exception("Telegram bot failed to start; continuing without it.")

    yield

    if telegram_engine is not None:
        try:
            await telegram_engine.stop()
        except Exception:
            logging.exception("Telegram bot failed to stop cleanly.")

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
    if node_user_sync.user_sync is not None:
        stop_tasks.append(node_user_sync.user_sync.stop())
        node_user_sync.user_sync = None
    if getattr(settings, 'EBPF_ENABLED', False):
        stop_tasks.append(hopper_engine.stop())
        stop_tasks.append(ai_engine.stop())
        stop_tasks.append(xdp_stats_exporter.stop())

    await asyncio.gather(*stop_tasks)
    
    if HAS_BCC and bpf_instance:
        try:
            iface = settings.EBPF_INTERFACE
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

# Subscription URLs bypass the stealth gate (see above), so any framework-
# generated error under /sub/ would otherwise leak FastAPI's JSON body —
# `GET /sub/<random>` returning `{"detail": ...}` while every other path
# returns nginx HTML is a one-request fingerprint. "No such token / no such
# route / wrong method / malformed path" all collapse into the nginx 404.
# Errors that need a *valid* token to reach (expired, over quota, no nodes)
# keep their JSON detail — only the token's holder can see those.
_SUB_STEALTH_STATUSES = {404, 405, 422}


@app.exception_handler(StarletteHTTPException)
async def _http_exception_handler(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith(_SUBSCRIPTION_PUBLIC_PREFIX) and exc.status_code in _SUB_STEALTH_STATUSES:
        return _nginx_404()
    from fastapi.exception_handlers import http_exception_handler
    return await http_exception_handler(request, exc)


@app.exception_handler(RequestValidationError)
async def _validation_exception_handler(request: Request, exc: RequestValidationError):
    if request.url.path.startswith(_SUBSCRIPTION_PUBLIC_PREFIX):
        return _nginx_404()
    from fastapi.exception_handlers import request_validation_exception_handler
    return await request_validation_exception_handler(request, exc)


# Stealth Middleware (registered last => outermost => runs first)
@app.middleware("http")
async def stealth_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"

    # App-level IP ban (honeypot / manual bans land here when eBPF is off).
    # Banned clients get the same nginx 404 as everyone else rather than a
    # telltale 403 that confirms they were detected.
    if orchestrator.is_app_banned(client_ip):
        return _nginx_404()

    # Subscription URLs are authenticated by their own path token.
    if request.url.path.startswith(_SUBSCRIPTION_PUBLIC_PREFIX):
        return await call_next(request)

    token = request.headers.get("X-Stealth-Token") or ""
    if not settings.STEALTH_TOKEN or not hmac.compare_digest(
        token.encode("utf-8"), settings.STEALTH_TOKEN.encode("utf-8")
    ):
        logging.debug("Stealth gate rejected %s %s from %s", request.method, request.url.path, client_ip)
        return _nginx_404()
    return await call_next(request)


# Kernel-level kill switch / global port hop. These can drop every non-VPN
# packet on the host, so they require an authenticated admin JWT on top of
# the stealth token — the stealth token alone is a shared secret that also
# lives in the frontend container and must not be sufficient to cut traffic.
@app.post("/api/v1/system/killswitch/trigger")
async def api_trigger_killswitch(admin=Depends(require_admin)):
    await killswitch.trigger_lockdown()
    audit_logger.log_admin_action(admin_username=admin.username, action="killswitch_trigger", target="host")
    return {"status": "lockdown_active", "message": "All non-VPN traffic is now DROPPED at XDP layer."}

@app.post("/api/v1/system/killswitch/release")
async def api_release_killswitch(admin=Depends(require_admin)):
    await killswitch.release_lockdown()
    audit_logger.log_admin_action(admin_username=admin.username, action="killswitch_release", target="host")
    return {"status": "lockdown_released", "message": "Traffic flowing normally."}

@app.post("/api/v1/system/porthop/trigger")
async def api_trigger_porthop(admin=Depends(require_admin)):
    if not hopper_engine or not settings.EBPF_ENABLED:
        return {"status": "error", "message": "Hopper engine not running (EBPF_ENABLED is false)"}
    new_port = hopper_engine.hopper.force_hop()
    audit_logger.log_admin_action(admin_username=admin.username, action="porthop_trigger", target=str(new_port))
    return {"status": "porthop_active", "new_port": new_port, "message": f"Global port hop triggered. New port: {new_port}"}

@app.get("/health")
@app.get("/api/v1/health")
async def health_check():
    """Liveness probe. Deliberately reveals nothing beyond "up" — node
    telemetry lives behind admin auth at /api/metrics/dashboard."""
    return {"status": "healthy"}
