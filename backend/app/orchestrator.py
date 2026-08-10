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
   - Amaç: Node'un anlık durumunu, aktif bağlantı sayısını ve CPU/RAM 
     durumunu Master'a raporlar.
   - Header: X-MTGroup-Signature (HMAC-SHA256 imzası)
   - Yanıt: 200 OK, 
     {
         "status": "healthy",
         "current_connections": 142,
         "cpu_usage": 12.4
     }
===================================================================
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx

# Models ve Logger importları
from backend.app.core.logging_config import audit_logger
from backend.app.models import Node

logger = logging.getLogger("mtgroup.orchestrator")


@dataclass
class RetryTask:
    """Kuyruğa eklenecek yeniden deneme (retry) görev modeli."""
    node_id: int
    node_address: str
    node_port: int
    api_key: str
    endpoint: str
    method: str
    payload: dict[str, Any] | None
    attempt: int
    next_retry_at: float


class NodeOrchestrator:
    """
    Node Senkronizasyon ve Sağlık Kontrol Motoru.
    Asenkron httpx istemcisi ve asyncio.Queue tabanlı retry döngüsü kullanır.
    """

    def __init__(self, db_session_factory=None):
        self._db_session_factory = db_session_factory
        self._retry_queue: asyncio.Queue[RetryTask] = asyncio.Queue()
        self._client = httpx.AsyncClient(timeout=10.0, verify=False)  # nosec B501 - nodes use self-signed certs; payload integrity is instead guaranteed by the HMAC-SHA256 signature on every request (see _generate_signature)
        self._worker_task: asyncio.Task | None = None
        self._is_running = False
        self._app_banned_ips: set[str] = set()

    async def start(self):
        """Arka plan worker döngüsünü başlatır."""
        if self._is_running:
            return
        self._is_running = True
        self._worker_task = asyncio.create_task(self._background_worker_loop())
        logger.info("Node Orchestrator background worker started.")

    async def stop(self):
        """Motoru güvenli bir şekilde durdurur."""
        self._is_running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        await self._client.aclose()
        logger.info("Node Orchestrator background worker stopped.")

    def _generate_signature(self, api_key: str, body_bytes: bytes) -> str:
        """
        Payload'ı (veya boş request'i) Node'un api_key'i ile HMAC-SHA256 kullanarak imzalar.
        """
        return hmac.new(
            api_key.encode("utf-8"),
            body_bytes,
            hashlib.sha256
        ).hexdigest()

    async def _send_request(
        self, 
        address: str, 
        port: int, 
        api_key: str, 
        method: str, 
        endpoint: str, 
        payload: dict[str, Any] | None = None
    ) -> httpx.Response:
        """
        İmzalanmış asenkron HTTP isteğini Node'a fırlatır.
        """
        url = f"https://{address}:{port}{endpoint}"
        
        ts = str(int(time.time()))
        
        body_bytes = b""
        if payload is not None:
            # Deep-copy to prevent mutation of the original dict
            send_payload = payload.copy()
            send_payload["_ts"] = int(ts)
            body_bytes = json.dumps(send_payload, separators=(',', ':')).encode("utf-8")
        else:
            # GET istekleri için timestamp'li boş body imzası
            body_bytes = json.dumps({"_ts": int(ts)}, separators=(',', ':')).encode("utf-8")

        signature = self._generate_signature(api_key, body_bytes)
        
        headers = {
            "Content-Type": "application/json",
            "X-MTGroup-Signature": signature,
            "X-MTGroup-Timestamp": ts,
        }

        if method.upper() == "GET":
            # GET: body not sent over wire, but Node reconstructs {"_ts":<ts>} from header to verify
            return await self._client.get(url, headers=headers)
        elif method.upper() == "POST":
            return await self._client.post(url, content=body_bytes, headers=headers)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

    async def _mark_node_offline(self, node_id: int):
        """Veritabanında Node'u offline olarak işaretler."""
        if not self._db_session_factory:
            return
        try:
            from sqlalchemy import select
            async with self._db_session_factory() as session:
                result = await session.execute(select(Node).where(Node.id == node_id))
                node = result.scalar_one_or_none()
                if node and node.is_active:
                    node.is_active = False
                    node.health_status = "offline"
                    await session.commit()
                    audit_logger.log_node_event(node.name, "offline", "Node marked offline due to connection failure.")
        except Exception as e:
            logger.error("Failed to mark node %s offline: %s", node_id, e)

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
        try:
            response = await self._send_request(
                address=node.address,
                port=node.port,
                api_key=node.api_key,
                method="POST",
                endpoint="/api/v1/sync",
                payload=config_payload
            )
            response.raise_for_status()
            logger.info("Successfully synced config to Node %s (%s)", node.id, node.name)
            return True
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.warning("Failed to sync Node %s (%s): %s. Queuing for retry.", node.id, node.name, e)
            await self._mark_node_offline(node.id)

            # İlk başarısızlıkta kuyruğa at (30 saniye sonra dene)
            task = RetryTask(
                node_id=node.id,
                node_address=node.address,
                node_port=node.port,
                api_key=node.api_key,
                endpoint="/api/v1/sync",
                method="POST",
                payload=config_payload,
                attempt=1,
                next_retry_at=time.time() + 30.0
            )
            await self._retry_queue.put(task)
            return False

    async def check_node_health(self, node: Node):
        """
        Node sağlık durumunu sorgular.
        Başarılıysa veritabanını günceller, başarısızsa mark_offline tetikler.
        """
        try:
            response = await self._send_request(
                address=node.address,
                port=node.port,
                api_key=node.api_key,
                method="GET",
                endpoint="/api/v1/health"
            )
            response.raise_for_status()
            data = response.json()
            
            # Veritabanını güncelle
            if self._db_session_factory:
                from sqlalchemy import select
                async with self._db_session_factory() as session:
                    result = await session.execute(select(Node).where(Node.id == node.id))
                    db_node = result.scalar_one_or_none()
                    if db_node:
                        db_node.is_active = True
                        db_node.health_status = data.get("status", "healthy")
                        db_node.current_connections = data.get("current_connections", 0)
                        from datetime import datetime, timezone
                        db_node.last_health_check = datetime.now(timezone.utc)
                        await session.commit()
                        
            logger.debug("Node %s is healthy.", node.name)
            
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.warning("Health check failed for Node %s: %s", node.name, e)
            await self._mark_node_offline(node.id)

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
                        port=node.port,
                        api_key=node.api_key,
                        method="POST",
                        endpoint="/api/v1/sync_mesh",
                        payload=payload
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
                        payload=task.payload
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

# ---------------------------------------------------------------------------
# Global Singleton
# ---------------------------------------------------------------------------
orchestrator = NodeOrchestrator()
