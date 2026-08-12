"""
MTGroup VPN Ultimate — Auto-CDN & Smart SNI Engine
Continuously tests the primary SNI and Auto-CDN IP.
If a block is detected (GFW/DPI interference), switches to a clean IP / fallback SNI.

No Cloudflare account API token exists anywhere in this project's config
(only CDN_WORKER_URL/CDN_ENABLED) — "manages Cloudflare API updates" in
the original docstring was aspirational. What's actually implemented is a
real TLS-handshake reachability probe against every active node's Reality
SNI (the literal DPI-interference signature: a clean handshake vs. a
reset/timeout), plus fallback candidate selection from a small built-in
pool of Cloudflare edge addresses when a probe fails. It deliberately
stops short of rewriting any Node's SNI/routing automatically — see
_manage_auto_cdn's docstring for why.
"""

import asyncio
import logging
import ssl
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from backend.app.core.config import settings

logger = logging.getLogger("mtgroup.auto_cdn")

SNI_CHECK_TIMEOUT_SECONDS = 5.0

# A small, well-known pool of Cloudflare anycast edge addresses to test as
# fallback fronting targets when a node's primary SNI looks blocked.
# Cloudflare's edge is reachable at thousands of addresses across many
# ranges; censors typically block specific ranges rather than all of
# Cloudflare, so testing a handful spread across different /8s gives a
# real shot at finding one that still works. This is a lightweight
# fallback, not a substitute for real Cloudflare account integration —
# there is no API token configured to actually provision anything through
# Cloudflare's management API (see module docstring).
FALLBACK_CDN_CANDIDATES = [
    "104.16.0.0",
    "104.17.0.0",
    "104.18.0.0",
    "172.64.0.0",
    "1.1.1.1",
]


class SingularityAutoCDN:
    """
    Engine that probes node SNIs for DPI blocking and tracks a reachable
    Cloudflare fallback target when CDN fronting is enabled.
    """
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory
        self.is_running = False
        self._task = None
        # sni -> last probe result, consulted by _manage_auto_cdn and
        # available to anything else that wants current SNI health.
        self._sni_healthy: dict[str, bool] = {}
        # Currently-selected fallback CDN address, or None if either
        # nothing has needed one yet or every candidate is unreachable.
        self.current_cdn_target: Optional[str] = None

    async def start(self):
        if self.is_running:
            return
        self.is_running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("🟢 Auto-CDN & Smart SNI Engine started.")

    async def stop(self):
        self.is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("🛑 Auto-CDN & Smart SNI Engine stopped.")

    async def _run_loop(self):
        while self.is_running:
            try:
                await self._check_sni_health()
                await self._manage_auto_cdn()
            except Exception as e:
                logger.error(f"Auto-CDN Engine error: {e}")

            # Check every 60 seconds
            await asyncio.sleep(60)

    async def _probe_tls(self, host: str, port: int = 443, sni: Optional[str] = None) -> bool:
        """
        Real reachability probe: opens a TCP connection and completes a
        TLS handshake against `host:port`, sending `sni` (defaults to
        `host`) as the ClientHello SNI — the literal DPI-interference
        signature is a clean handshake vs. a connection reset or timeout.

        Certificate verification is deliberately off: this probes
        arbitrary CDN edge IPs (see FALLBACK_CDN_CANDIDATES) that have no
        single CA chain to validate against, and the probe never sends or
        receives anything sensitive — it only completes a handshake and
        closes.
        """
        server_hostname = sni or host
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # nosec B501 - reachability probe only, no sensitive data exchanged

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=server_hostname),
                timeout=SNI_CHECK_TIMEOUT_SECONDS,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception as e:
            logger.debug("TLS probe to %s:%s (SNI=%s) failed: %s", host, port, server_hostname, e)
            return False

    async def _check_sni_health(self):
        """
        Probes every active node's configured Reality SNI. Results are
        cached in `_sni_healthy`, keyed by SNI string, for
        `_manage_auto_cdn` to consult — a node with no `sni` set is
        skipped (nothing to probe).
        """
        if self.session_factory is None:
            return

        from backend.app.models import Node

        async with self.session_factory() as session:
            result = await session.execute(select(Node).where(Node.is_active.is_(True)))
            nodes = result.scalars().all()

        for node in nodes:
            if not node.sni:
                continue
            healthy = await self._probe_tls(node.address, node.port or 443, sni=node.sni)
            was_healthy = self._sni_healthy.get(node.sni, True)
            self._sni_healthy[node.sni] = healthy
            if was_healthy and not healthy:
                logger.warning(
                    "SNI %r on node %s (%s) failed its health probe — possible DPI interference.",
                    node.sni, node.name, node.address,
                )
            elif healthy and not was_healthy:
                logger.info("SNI %r on node %s (%s) recovered.", node.sni, node.name, node.address)

    async def _manage_auto_cdn(self):
        """
        If CDN fronting is enabled and any SNI just failed its health
        probe, looks for a reachable candidate among
        FALLBACK_CDN_CANDIDATES and records it as `current_cdn_target`.

        Deliberately does NOT rewrite any Node's SNI or routing config
        automatically, even with CDN_ENABLED on — actually rerouting live
        traffic based on an automated probe is a bigger behavioral change
        than "detect and expose a candidate," and there is no Cloudflare
        account API configured in this repo to provision a new fronting
        target through in the first place. Wiring `current_cdn_target`
        into an actual routing decision is separate follow-up work.
        """
        if not settings.CDN_ENABLED:
            return

        if not self._sni_healthy or all(self._sni_healthy.values()):
            return  # nothing unhealthy (or nothing probed yet) — no failover needed

        for candidate in FALLBACK_CDN_CANDIDATES:
            if await self._probe_tls(candidate, 443):
                if candidate != self.current_cdn_target:
                    logger.warning(
                        "Primary SNI(s) unhealthy — switching Auto-CDN fallback target to %s.",
                        candidate,
                    )
                self.current_cdn_target = candidate
                return

        logger.error("Auto-CDN: no fallback candidate was reachable — all probes failed.")
        self.current_cdn_target = None
