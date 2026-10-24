"""
MTGroup VPN Ultimate — Node Deployment & Sync Engine (Orchestrator)
═══════════════════════════════════════════════════════════════════
Master panel tarafında çalışan, uzak Node'lara (sunuculara) asenkron 
olarak konfigürasyon basan ve sağlık durumlarını denetleyen motor.

Tüm iletişim HMAC-SHA256 ile şifrelenir ve imzalanır. Başarısız istekler
bellek içi (in-memory) asyncio.Queue mekanizmasıyla arka planda zarifçe
(graceful retry) yeniden denenir.

===================================================================
BEKLENEN NODE AGENT API DÖKÜMANTASYONU (Receiver Side)
===================================================================
Uzak sunucularda (Node) çalışacak olan ajanın sunması gereken uç noktalar:

1. POST /api/v1/sync
   - Amaç: Master'dan gelen güncel JSON/YAML VPN konfigürasyonlarını alır 
     ve Xray/Sing-box/WireGuard servislerine uygular.
   - Header: X-MTGroup-Signature (HMAC-SHA256 imzası)
   - Body: 
     {
         "timestamp": 1718223400,
         "config_type": "singbox_multiplex",
         "payload": { ... config data ... }
     }
   - Yanıt: 200 OK, { "status": "synced" }

2. GET /api/v1/health
   - Amaç: Node'un anlık durumunu, aktif bağlantı sayısını, CPU/RAM
     durumunu ve (varsa) kullanıcı bazlı trafik verisini Master'a raporlar.
   - Header: X-MTGroup-Signature (HMAC-SHA256 imzası)
   - Yanıt: 200 OK,
     {
         "status": "healthy",
         "current_connections": 142,
         "cpu_usage": 12.4,
         "amnezia_peer_traffic": {"<public_key>": {"rx_bytes": N, "tx_bytes": N}, ...},
         "xray_user_traffic": {"<email>": N, ...}
     }
     Trafik alanları sadece o protokol node'da kuruluysa gönderilir; ikisi
     de yoksa hiç bulunmazlar. `check_node_health` bunları
     `NodeOrchestrator.get_traffic_snapshot(node_id)` ile erişilebilir
     şekilde bellekte tutar — kümülatif sayaçlardır (delta değil), bir
     sonraki adımda (kota takibi) bunları `TrafficAccountingEngine`'e
     beslemek üzere kalan iş, node/servis yeniden başlarsa sayaçların
     sıfırlanabileceğini hesaba katmak zorunda.

`NodeOrchestrator.start()`, health-poll loop'unu da başlatır: aktif her
node'u `HEALTH_POLL_INTERVAL_SECONDS` aralıklarla sorgular. Bu, bu motorun
üretimde çalışan ilk periyodik health-check mekanizmasıdır — önceden
`check_node_health` yalnızca testlerden çağrılıyordu, hiçbir zaman
otomatik tetiklenmiyordu.

`NodeOrchestrator.set_accounting_engine(engine)`, `check_node_health()`'in
trafik verisini `engine.ingest_node_traffic(node, traffic)`'e ilettiği
opsiyonel bir bağlantı noktasıdır — enjekte edilmediği sürece (bugünkü hal,
`main.py` hiçbir şey enjekte etmiyor) trafik sadece `get_traffic_snapshot()`
üzerinden bellekte tutulur, hiçbir yere aktarılmaz. `TrafficAccountingEngine`
kendisi hâlâ `lifespan()`'a bağlanmadı — bkz. CLAUDE.md.
===================================================================
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import ssl
import time
from dataclasses import dataclass
from typing import Any

import httpx

# Models ve Logger importları
from backend.app.core.logging_config import audit_logger
from backend.app.models import Node

logger = logging.getLogger("mtgroup.orchestrator")

# How often the health-poll loop re-checks every active node. 60s balances
# staying reasonably current against not hammering nodes with signed HTTP
# requests — traffic accounting (task #7, not this loop) has its own,
# separate cadence via TrafficAccountingEngine once that's wired up.
HEALTH_POLL_INTERVAL_SECONDS = 60

# Consecutive failed health checks before a node that has been healthy at
# least once is reported "offline" (and dropped from subscriptions until it
# answers again). One lost poll is not an outage.
OFFLINE_AFTER_FAILURES = 3


@dataclass
class RetryTask:
    """Kuyruğa eklenecek yeniden deneme (retry) görev modeli."""
    node_id: int
    node_address: str
    node_port: int  # the node *agent's* port, not the VPN port
    api_key: str
    endpoint: str
    method: str
    payload: dict[str, Any] | None
    attempt: int
    next_retry_at: float
    cert_pem: str | None = None


def _pinned_ssl_context(cert_pem: str) -> ssl.SSLContext:
    """Trust exactly this node's certificate and nothing else.

    The agent's cert is self-signed and marked CA:TRUE (see
    agent/node_daemon.py ensure_tls_material), so loading it as the only
    trust anchor makes the handshake fail against any other certificate —
    including a valid public one an on-path attacker might present. Host
    name checking is off because the pin, not the name, is the identity.
    """
    ctx = ssl.create_default_context(cadata=cert_pem)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class NodeOrchestrator:
    """
    Node Senkronizasyon ve Sağlık Kontrol Motoru.
    Asenkron httpx istemcisi ve asyncio.Queue tabanlı retry döngüsü kullanır.
    """

    def __init__(self, db_session_factory=None):
        self._db_session_factory = db_session_factory
        self._retry_queue: asyncio.Queue[RetryTask] = asyncio.Queue()
        # One httpx client per pinned agent certificate (keyed by the PEM's
        # SHA-256). This replaced a single `verify=False` client: HMAC kept
        # payloads unforgeable, but anyone on-path could still *read* them,
        # and full Xray syncs carry the Reality private key.
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._worker_task: asyncio.Task | None = None
        self._health_poll_task: asyncio.Task | None = None
        self._is_running = False
        self._app_banned_ips: set[str] = set()
        # Consecutive health-check failures per node.id, reset on success.
        self._health_failures: dict[int, int] = {}
        # Latest per-node traffic snapshot from /api/v1/health, keyed by
        # node.id. Cumulative counters as reported by the node, not deltas.
        self._traffic_snapshots: dict[int, dict[str, Any]] = {}
        # Optional TrafficAccountingEngine reference. Deliberately NOT
        # constructed or injected here, nor in main.py's lifespan() —
        # whether TrafficAccountingEngine actually runs (and therefore
        # whether it ever suspends anyone) remains the user's own decision
        # (see CLAUDE.md's "Known deferred decisions"). Not importing
        # TrafficAccountingEngine at module level also avoids a circular
        # import: accounting.py already imports `orchestrator` from here.
        # Typed as Any rather than importing the class just for a hint.
        self._accounting_engine: Any | None = None

    def set_accounting_engine(self, engine: Any) -> None:
        """
        Injects the object that receives node traffic snapshots (expected
        to expose an async `ingest_node_traffic(node, traffic)` — see
        TrafficAccountingEngine). Call this only once that engine has
        actually been enabled; check_node_health() only forwards traffic
        when this has been set.
        """
        self._accounting_engine = engine

    async def start(self):
        """Arka plan worker döngülerini başlatır (retry kuyruğu + health-poll)."""
        if self._is_running:
            return
        self._is_running = True
        self._worker_task = asyncio.create_task(self._background_worker_loop())
        self._health_poll_task = asyncio.create_task(self._health_poll_loop())
        logger.info("Node Orchestrator background worker started.")

    async def stop(self):
        """Motoru güvenli bir şekilde durdurur."""
        self._is_running = False
        for task in (self._worker_task, self._health_poll_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()
        logger.info("Node Orchestrator background worker stopped.")

    def get_traffic_snapshot(self, node_id: int) -> dict[str, Any] | None:
        """Latest traffic payload reported by `node_id`'s last successful health check, or None if never seen/no traffic data available."""
        return self._traffic_snapshots.get(node_id)

    def _generate_signature(self, api_key: str, body_bytes: bytes) -> str:
        """
        Payload'ı (veya boş request'i) Node'un api_key'i ile HMAC-SHA256 kullanarak imzalar.
        """
        return hmac.new(
            api_key.encode("utf-8"),
            body_bytes,
            hashlib.sha256
        ).hexdigest()

    def _client_for(self, cert_pem: str | None) -> httpx.AsyncClient:
        if not cert_pem:
            # Never fall back to an unverified connection.
            raise httpx.ConnectError("no pinned TLS certificate for this node agent")
        key = hashlib.sha256(cert_pem.encode("utf-8")).hexdigest()
        client = self._clients.get(key)
        if client is None:
            client = httpx.AsyncClient(timeout=10.0, verify=_pinned_ssl_context(cert_pem))
            self._clients[key] = client
        return client

    async def _agent_cert(self, node: Node) -> str | None:
        """The node agent's pinned certificate, recording it on first contact.

        Preferred: the admin pastes the PEM the agent printed at install
        (`python -m agent.node_daemon --print-cert`). Otherwise trust on
        first use: fetch it once, store it, and pin it from then on — a
        later certificate change then fails closed instead of silently
        talking to whoever answers.
        """
        pem = getattr(node, "agent_cert_pem", None)
        if pem:
            return pem
        port = getattr(node, "agent_port", None) or 8443
        try:
            pem = await asyncio.to_thread(ssl.get_server_certificate, (node.address, port), timeout=5)
        except (OSError, ssl.SSLError) as e:
            logger.debug("Could not fetch agent certificate from node %s: %s", node.id, e)
            return None
        logger.warning(
            "Pinning node %s (%s) agent certificate on first use. For a "
            "verified pin, paste the agent's --print-cert output into the node instead.",
            node.id, node.name,
        )
        if self._db_session_factory:
            try:
                from sqlalchemy import select
                async with self._db_session_factory() as session:
                    db_node = (await session.execute(select(Node).where(Node.id == node.id))).scalar_one_or_none()
                    if db_node is not None and not db_node.agent_cert_pem:
                        db_node.agent_cert_pem = pem
                        await session.commit()
            except Exception as e:
                logger.error("Failed to store agent certificate for node %s: %s", node.id, e)
        try:
            node.agent_cert_pem = pem
        except AttributeError:
            pass
        return pem

    async def _send_request(
        self,
        address: str,
        port: int,
        api_key: str,
        method: str,
        endpoint: str,
        payload: dict[str, Any] | None = None,
        *,
        cert_pem: str | None = None,
    ) -> httpx.Response:
        """
        Send a signed request to a node agent over pinned TLS.

        Signature = HMAC-SHA256(api_key, METHOD\nPATH\nTS\nNONCE\nBODY).
        Must match agent/node_daemon.py's verify_request — the two sides
        share no code. Signing method and path stops a captured request
        being re-aimed at another endpoint; the single-use nonce stops it
        being replayed inside the ±30s window. (The old scheme signed only
        the body, and for GET only the timestamp.)
        """
        method = method.upper()
        if method not in ("GET", "POST"):
            raise ValueError(f"Unsupported HTTP method: {method}")

        url = f"https://{address}:{port}{endpoint}"
        ts = str(int(time.time()))
        nonce = secrets.token_urlsafe(16)
        body_bytes = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        message = f"{method}\n{endpoint}\n{ts}\n{nonce}\n".encode("utf-8") + body_bytes

        headers = {
            "Content-Type": "application/json",
            "X-MTGroup-Signature": self._generate_signature(api_key, message),
            "X-MTGroup-Timestamp": ts,
            "X-MTGroup-Nonce": nonce,
        }
        client = self._client_for(cert_pem)
        if method == "GET":
            return await client.get(url, headers=headers)
        return await client.post(url, content=body_bytes, headers=headers)

    async def _record_health_failure(self, node_id: int):
        """Record that `node_id` could not be reached.

        Only `health_status` changes. This used to set `is_active = False`,
        which is the *admin's* enable/disable switch: the poll loop only
        checks active nodes and subscriptions only list active nodes, so a
        single dropped poll removed a node from every user's subscription
        permanently, with nothing ever re-checking it.

        Now: after OFFLINE_AFTER_FAILURES consecutive failures a node that
        has answered at least once becomes "offline" (excluded from
        subscriptions, still polled, restored automatically on the next
        success). A node that has *never* answered becomes "unreachable"
        and stays in subscriptions — that is a node without a reachable
        agent (e.g. configured by hand), not evidence the VPN is down.
        """
        failures = self._health_failures.get(node_id, 0) + 1
        self._health_failures[node_id] = failures
        if not self._db_session_factory:
            return
        try:
            from sqlalchemy import select
            async with self._db_session_factory() as session:
                result = await session.execute(select(Node).where(Node.id == node_id))
                node = result.scalar_one_or_none()
                if node is None:
                    return
                if node.last_health_check is None:
                    new_status = "unreachable"
                elif failures >= OFFLINE_AFTER_FAILURES:
                    new_status = "offline"
                else:
                    new_status = "degraded"
                if node.health_status != new_status:
                    node.health_status = new_status
                    await session.commit()
                    if new_status == "offline":
                        audit_logger.log_node_event(
                            node.name, "offline",
                            f"No response to {failures} consecutive health checks; "
                            "excluded from subscriptions until it answers again.",
                        )
        except Exception as e:
            logger.error("Failed to record health failure for node %s: %s", node_id, e)

    async def send_command(self, node: Node, config_payload: dict[str, Any]) -> bool:
        """Send one signed command to the node's agent, without queuing a
        retry. For callers that retry themselves by recomputing what to send
        (NodeUserSync): a queued full config could otherwise land *after* a
        newer one and roll the node back."""
        cert_pem = await self._agent_cert(node)
        try:
            response = await self._send_request(
                address=node.address,
                port=getattr(node, "agent_port", None) or 8443,
                api_key=node.api_key,
                method="POST",
                endpoint="/api/v1/sync",
                payload=config_payload,
                cert_pem=cert_pem,
            )
            response.raise_for_status()
            return True
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.warning("Command to Node %s (%s) failed: %s", node.id, node.name, e)
            await self._record_health_failure(node.id)
            return False

    async def sync_node_config(self, node: Node, config_payload: dict[str, Any]) -> bool:
        """
        Node'a güncel VPN konfigürasyonunu pushlar (Deployment).
        Eğer başarısız olursa Retry kuyruğuna atar.

        Returns True when the node accepted the command. Callers that must
        know whether it actually landed — peer registration, for instance,
        where handing the user a config the node hasn't been told about
        produces a tunnel that silently never connects — check this rather
        than assuming success.
        """
        agent_port = getattr(node, "agent_port", None) or 8443
        cert_pem = await self._agent_cert(node)
        try:
            response = await self._send_request(
                address=node.address,
                port=agent_port,
                api_key=node.api_key,
                method="POST",
                endpoint="/api/v1/sync",
                payload=config_payload,
                cert_pem=cert_pem,
            )
            response.raise_for_status()
            logger.info("Successfully synced config to Node %s (%s)", node.id, node.name)
            return True
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.warning("Failed to sync Node %s (%s): %s. Queuing for retry.", node.id, node.name, e)
            await self._record_health_failure(node.id)

            # İlk başarısızlıkta kuyruğa at (30 saniye sonra dene)
            task = RetryTask(
                node_id=node.id,
                node_address=node.address,
                node_port=agent_port,
                api_key=node.api_key,
                endpoint="/api/v1/sync",
                method="POST",
                payload=config_payload,
                attempt=1,
                next_retry_at=time.time() + 30.0,
                cert_pem=cert_pem,
            )
            await self._retry_queue.put(task)
            return False

    async def check_node_health(self, node: Node):
        """
        Node sağlık durumunu sorgular.
        Başarılıysa veritabanını günceller, başarısızsa mark_offline tetikler.
        """
        cert_pem = await self._agent_cert(node)
        try:
            response = await self._send_request(
                address=node.address,
                port=getattr(node, "agent_port", None) or 8443,
                api_key=node.api_key,
                method="GET",
                endpoint="/api/v1/health",
                cert_pem=cert_pem,
            )
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("health response is not a JSON object")

            # Cumulative per-user traffic, if this node reported any.
            # Stored regardless of whether a DB session factory is
            # configured — this is an in-memory cache, not persisted.
            traffic = {
                key: data[key]
                for key in ("amnezia_peer_traffic", "xray_user_traffic")
                if key in data
            }
            if traffic:
                self._traffic_snapshots[node.id] = traffic
                if self._accounting_engine is not None:
                    # Fire-and-forget: ingest_node_traffic() is best-effort
                    # telemetry processing (never raises) and must not
                    # delay the health-check response handling below.
                    asyncio.create_task(self._accounting_engine.ingest_node_traffic(node, traffic))

            # Veritabanını güncelle
            if self._db_session_factory:
                from sqlalchemy import select
                async with self._db_session_factory() as session:
                    result = await session.execute(select(Node).where(Node.id == node.id))
                    db_node = result.scalar_one_or_none()
                    if db_node:
                        # is_active is the admin's switch — never flipped here.
                        if db_node.health_status == "offline":
                            audit_logger.log_node_event(db_node.name, "online", "Health checks succeeding again.")
                        db_node.health_status = data.get("status", "healthy")
                        db_node.current_connections = data.get("current_connections", 0)
                        from datetime import datetime, timezone
                        db_node.last_health_check = datetime.now(timezone.utc)
                        await session.commit()
                        
            self._health_failures.pop(node.id, None)
            logger.debug("Node %s is healthy.", node.name)
            
        except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as e:
            # ValueError: a 200 whose body isn't the agent's JSON (wrong
            # service on that port, captive portal) — not a healthy agent.
            logger.warning("Health check failed for Node %s: %s", node.name, e)
            await self._record_health_failure(node.id)

    async def apply_ip_ban(self, ip_address: str) -> None:
        """Applies enforcement only (XDP blacklist, or the app-level ban set
        when eBPF is disabled) — does NOT touch the database. Callers that
        need a persistent record (audit trail, admin-visible ban list, TTL)
        manage their own `BannedIP` row; this is the shared low-level
        primitive both the AI fast-track path and the admin ban API use."""
        from backend.app.core.config import settings
        if getattr(settings, 'EBPF_ENABLED', False):
            from backend.app.api.metrics import xdp_loader
            xdp_loader.blacklist_ip(ip_address)
        else:
            self._app_banned_ips.add(ip_address)
            logger.info("eBPF Disabled: App-level blacklist applied for %s.", ip_address)

    async def lift_ip_ban(self, ip_address: str) -> None:
        """Reverses `apply_ip_ban`. Does not touch the database."""
        from backend.app.core.config import settings
        if getattr(settings, 'EBPF_ENABLED', False):
            from backend.app.api.metrics import xdp_loader
            xdp_loader.unblacklist_ip(ip_address)
        else:
            self._app_banned_ips.discard(ip_address)

    async def handle_security_alert(self, ip_address: str, reason: str):
        """
        AI tarafından tetiklenen geçici (Fast-Track Defense) uyarısını işler.
        XDP üzerinden IP'yi 300 saniyeliğine banlar.
        Veritabanında BannedIP tablosuna asenkron olarak kaydeder.
        """
        logger.warning("SecurityAlert from AI for IP %s: %s", ip_address, reason)
        try:
            await self.apply_ip_ban(ip_address)

            # Veritabanına asenkron kaydet
            if self._db_session_factory:
                from backend.app.models import BannedIP, BanReason
                from datetime import datetime, timedelta, timezone
                import hashlib
                
                async with self._db_session_factory() as session:
                    ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()
                    expires = datetime.now(timezone.utc) + timedelta(seconds=300)
                    new_ban = BannedIP(
                        ip_address=ip_address,
                        ip_hash=ip_hash,
                        reason=BanReason.TRAFFIC_ANOMALY,
                        details=reason,
                        expires_at=expires
                    )
                    session.add(new_ban)
                    await session.commit()
                    logger.debug("Logged banned IP %s to database.", ip_address)
            
            # Arka planda TTL süresi bitince banı kaldır
            asyncio.create_task(self._remove_ban_after_ttl(ip_address, 300))
        except Exception as e:
            logger.error("Failed to handle security alert for %s: %s", ip_address, e)
            
    async def _remove_ban_after_ttl(self, ip_address: str, ttl: int):
        await asyncio.sleep(ttl)
        try:
            await self.lift_ip_ban(ip_address)
            logger.info("Temporary ban lifted for %s after %ds TTL.", ip_address, ttl)
        except Exception as e:
            logger.error("Failed to lift temporary ban for %s: %s", ip_address, e)

    def is_app_banned(self, ip_address: str) -> bool:
        """App-level block kontrolü."""
        return ip_address in self._app_banned_ips

    async def broadcast_mesh_peers(self):
        """
        Aktif tüm Node'lara, diğer Node'ların (peer) listesini dağıtır.
        Böylece Node'lar %85 yük altında kendi aralarında Mesh Multipath tünelleri kurabilir.
        """
        if not self._db_session_factory:
            return
            
        try:
            from sqlalchemy import select
            async with self._db_session_factory() as session:
                result = await session.execute(select(Node).where(Node.is_active.is_(True)))
                active_nodes = result.scalars().all()
                
            if len(active_nodes) < 2:
                return # Mesh için en az 2 node lazım
                
            peers_data = [
                {"id": n.id, "address": n.address, "port": n.port} 
                for n in active_nodes
            ]
            
            for node in active_nodes:
                payload = {
                    "action": "update_mesh_peers",
                    "peers": [p for p in peers_data if p["id"] != node.id]
                }
                
                # Arka planda pushla
                asyncio.create_task(
                    self._send_request(
                        address=node.address,
                        port=getattr(node, "agent_port", None) or 8443,
                        api_key=node.api_key,
                        method="POST",
                        endpoint="/api/v1/sync_mesh",
                        payload=payload,
                        cert_pem=getattr(node, "agent_cert_pem", None),
                    )
                )
            logger.info("Broadcasted Mesh peer list to %d nodes.", len(active_nodes))
        except Exception as e:
            logger.error("Failed to broadcast mesh peers: %s", e)

    async def _background_worker_loop(self):
        """
        Bellek içi retry kuyruğunu işleyen ve belirli aralıklarla hata alan 
        istekleri zarifçe (graceful) yeniden deneyen arka plan döngüsü.
        """
        while self._is_running:
            try:
                # Kuyruk boşsa 1 saniye bekle
                if self._retry_queue.empty():
                    await asyncio.sleep(1.0)
                    continue

                # Görevi al
                task: RetryTask = await self._retry_queue.get()
                
                # Henüz zamanı gelmediyse geri koy ve bekle
                now = time.time()
                if now < task.next_retry_at:
                    await self._retry_queue.put(task)
                    self._retry_queue.task_done()  # Balance the .get() above
                    await asyncio.sleep(0.5)
                    continue
                
                # Retry işlemi
                try:
                    response = await self._send_request(
                        address=task.node_address,
                        port=task.node_port,
                        api_key=task.api_key,
                        method=task.method,
                        endpoint=task.endpoint,
                        payload=task.payload,
                        cert_pem=task.cert_pem,
                    )
                    response.raise_for_status()
                    logger.info("Retry SUCCESS for Node %s on endpoint %s (attempt %s)", 
                                task.node_id, task.endpoint, task.attempt)
                    
                    # Başarılı olduğunda logla
                    audit_logger.log_node_event(f"ID:{task.node_id}", "retry_success", "Node configuration synced successfully after retry.")
                    
                except (httpx.RequestError, httpx.HTTPStatusError) as e:
                    logger.warning("Retry FAILED for Node %s (attempt %s): %s", task.node_id, task.attempt, e)
                    
                    # Max 5 deneme, logaritmik bekleme (backoff)
                    if task.attempt < 5:
                        task.attempt += 1
                        # Backoff: 30s -> 60s -> 120s -> 240s
                        backoff_delay = 30.0 * (2 ** (task.attempt - 1))
                        task.next_retry_at = time.time() + backoff_delay
                        await self._retry_queue.put(task)
                    else:
                        logger.error("Max retries reached for Node %s. Dropping sync task.", task.node_id)
                        audit_logger.log_node_event(f"ID:{task.node_id}", "sync_failed_max_retries", "Dropped configuration sync task after 5 failed attempts.")

                # Görevin işlendiğini bildir
                self._retry_queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Unexpected error in Orchestrator worker loop: %s", e)
                await asyncio.sleep(5.0)

    async def _health_poll_loop(self):
        """
        Periodically calls check_node_health() for every active node.

        This did not exist before: `Node.health_status`/`current_connections`/
        `last_health_check` were only ever updated by tests calling
        check_node_health() directly, never in production. Runs every
        HEALTH_POLL_INTERVAL_SECONDS; a failure for one node (network error,
        node down) must not stop the rest from being checked, so each is
        awaited individually inside its own try/except rather than
        asyncio.gather-ed in a way where one exception could cancel siblings.
        """
        while self._is_running:
            try:
                await asyncio.sleep(HEALTH_POLL_INTERVAL_SECONDS)
                if not self._is_running:
                    break
                if not self._db_session_factory:
                    continue

                from sqlalchemy import select
                async with self._db_session_factory() as session:
                    result = await session.execute(select(Node).where(Node.is_active.is_(True)))
                    active_nodes = result.scalars().all()

                for node in active_nodes:
                    try:
                        await self.check_node_health(node)
                    except Exception as e:
                        logger.error("Health poll failed for Node %s: %s", node.id, e)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Unexpected error in Orchestrator health-poll loop: %s", e)
                await asyncio.sleep(5.0)

# ---------------------------------------------------------------------------
# Global Singleton
# ---------------------------------------------------------------------------
orchestrator = NodeOrchestrator()
