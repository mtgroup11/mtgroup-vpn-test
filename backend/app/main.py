from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
import logging
import asyncio
import os

from backend.app.core.killswitch import killswitch
from backend.app.core.config import settings
from backend.app.core.honeypot import honeypot
from backend.app.generators.port_hopper import AsyncPortHoppingEngine
from backend.app.core.ai_detector import AnomalyPredictor
from backend.app.orchestrator import orchestrator
from backend.app.models import Base
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

try:
    from bcc import BPF  # type: ignore
    HAS_BCC = True
except ImportError:
    HAS_BCC = False

bpf_instance = None
hopper_engine = None
ai_engine = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global bpf_instance, hopper_engine, ai_engine
    logging.info("🚀 XDP-Spectre Central Orchestrator Booting...")
    
    if not settings.DEBUG:
        if not settings.DB_ENCRYPTION_KEY or settings.DB_ENCRYPTION_KEY == "mtgroup-vpn-ultimate-default-dev-key-CHANGE-ME":
            raise RuntimeError("CRITICAL: DB_ENCRYPTION_KEY is empty or default in PRODUCTION (DEBUG=False). Set a secure key to start.")
        if not settings.ADMIN_PASSWORD or settings.ADMIN_PASSWORD == "MTGroup@2024!Secure":
            raise RuntimeError("CRITICAL: ADMIN_PASSWORD is empty or default in PRODUCTION (DEBUG=False). Set a secure password to start.")
    
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
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logging.info("SQLite Async Database initialized.")
    
    db_session_factory = async_sessionmaker(engine, expire_on_commit=False)

    # Initialize Engines
    hopper_engine = AsyncPortHoppingEngine(db_session_factory=db_session_factory)
    if bpf_instance:
        hopper_engine._bpf = bpf_instance
        
    ai_engine = AnomalyPredictor()
    
    # Inject db_session_factory to orchestrator
    orchestrator._db_session_factory = db_session_factory

    # Start background tasks conditionally
    logging.info("Starting background engines...")
    tasks = [honeypot.start()]  # App-level decoy always starts
    if getattr(settings, 'EBPF_ENABLED', False):
        tasks.append(hopper_engine.start())
        tasks.append(ai_engine.start())
        logging.info("AI Detector and Port Hopper engines started.")
    else:
        logging.warning("eBPF Disabled. AI Detector and Port Hopper are fully bypassed to save resources.")
        
    await asyncio.gather(*tasks)
    
    yield
    
    logging.info(" Shutting down gracefully...")
    stop_tasks = [honeypot.stop()]
    if getattr(settings, 'EBPF_ENABLED', False):
        stop_tasks.append(hopper_engine.stop())
        stop_tasks.append(ai_engine.stop())
        
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

# Register API Routers
from backend.app.api.auth import router as auth_router
from backend.app.api.users import router as users_router
from backend.app.api.nodes import router as nodes_router
from backend.app.api.subscriptions import router as subscriptions_router
from backend.app.api.system import router as system_router
from backend.app.api.metrics import router as metrics_router
from backend.app.api.resellers import router as resellers_router

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
        
    # Gelen isteklerde 'X-Stealth-Token' header kontrolü
    token = request.headers.get("X-Stealth-Token")
    if token != "SUPER_SECRET_NOC_TOKEN_2026": # In real app, load from config
        # Sıradan projelere ve tarayıcılara kendini gizle
        logging.warning(f"Unauthorized access attempt from {request.client.host}")
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    return await call_next(request)

@app.post("/api/v1/system/killswitch/trigger")
async def api_trigger_killswitch():
    killswitch.trigger_lockdown()
    return {"status": "lockdown_active", "message": "All non-VPN traffic is now DROPPED at XDP layer."}

@app.post("/api/v1/system/killswitch/release")
async def api_release_killswitch():
    killswitch.release_lockdown()
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
