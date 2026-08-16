"""
MTGroup VPN Ultimate — User-Node Mesh Network (Agent Side)
═══════════════════════════════════════════════════════════════════
Establishes a VPN-within-VPN overlay network among peer nodes.
Multipath routing is triggered ONLY when the main server's CPU load
exceeds 85% or packet loss > 5%.
"""

import asyncio
import logging
from typing import Any

import psutil

logger = logging.getLogger("mtgroup.agent.mesh")

# Linux exposes cumulative TCP retransmit counters here; no root or raw
# sockets needed, just a world-readable proc file. See `man 5 proc` /
# net/ipv4/proc.c (Tcp: RetransSegs, OutSegs).
_PROC_NET_SNMP = "/proc/net/snmp"


class MeshRouter:
    """
    Monitors local node health and dynamically routes traffic
    through peer nodes (Multipath) if resources are exhausted.
    """

    def __init__(self):
        self.peers: list[dict[str, Any]] = []
        self._is_running = False
        self._worker_task: asyncio.Task | None = None
        self._active_tunnels: dict[int, asyncio.StreamWriter] = {}
        self._last_tcp_counters: tuple[int, int] | None = None
        self._packet_loss_unavailable_warned = False

    def update_peers(self, new_peers: list[dict[str, Any]]):
        """Called by the agent HTTP server when Orchestrator pushes peers."""
        self.peers = new_peers
        logger.info(f"MeshRouter updated with {len(self.peers)} peers.")

    async def start(self):
        if self._is_running:
            return
        self._is_running = True
        self._worker_task = asyncio.create_task(self._health_monitor_loop())
        logger.info("MeshRouter Background Service started.")

    async def stop(self):
        self._is_running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        
        # Close tunnels
        for writer in self._active_tunnels.values():
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        self._active_tunnels.clear()
        logger.info("MeshRouter Background Service stopped.")

    async def _health_monitor_loop(self):
        """Continuously monitors node health to trigger Multipath."""
        while self._is_running:
            try:
                cpu_load = psutil.cpu_percent(interval=1.0)
                packet_loss = self._get_packet_loss()
                
                if cpu_load > 85.0 or packet_loss > 0.05:
                    logger.warning(f"Mesh condition triggered! CPU: {cpu_load}%, Loss: {packet_loss*100}%")
                    await self._activate_multipath()
                else:
                    # If we recover, we might scale down tunnels (optional)
                    if self._active_tunnels and cpu_load < 50.0:
                        logger.info("Node recovered. Deactivating multipath overlay.")
                        await self._deactivate_multipath()

                await asyncio.sleep(5.0)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in MeshRouter monitor loop: {e}")
                await asyncio.sleep(5.0)

    @staticmethod
    def _read_tcp_retrans_counters() -> tuple[int, int] | None:
        """Reads cumulative (RetransSegs, OutSegs) from /proc/net/snmp.
        Returns None on any platform/format where this isn't available
        (e.g. non-Linux) rather than raising — callers must treat that
        as "no signal", not "zero loss"."""
        try:
            with open(_PROC_NET_SNMP, "r") as f:
                lines = f.readlines()
        except OSError:
            return None

        header = values = None
        for line in lines:
            if not line.startswith("Tcp:"):
                continue
            if header is None:
                header = line.split()
            else:
                values = line.split()
                break

        if not header or not values:
            return None
        try:
            idx = {name: i for i, name in enumerate(header)}
            retrans_segs = int(values[idx["RetransSegs"]])
            out_segs = int(values[idx["OutSegs"]])
            return retrans_segs, out_segs
        except (KeyError, ValueError, IndexError):
            return None

    def _get_packet_loss(self) -> float:
        """Real packet-loss estimate derived from TCP retransmit counters
        (retransmitted segments / segments sent, since the previous poll).

        This is an approximation — TCP retransmits also happen on RTO
        under normal jitter, not only real loss — but it's a genuine
        kernel-observed signal, not a hardcoded constant. Returns 0.0
        (never triggers the loss-based multipath condition on its own)
        when retransmit stats aren't available on this platform, or on
        the very first sample (no baseline to diff against yet).
        """
        counters = self._read_tcp_retrans_counters()
        if counters is None:
            if not self._packet_loss_unavailable_warned:
                logger.warning(
                    "TCP retransmit stats unavailable (%s not readable) — "
                    "packet-loss-based multipath trigger is disabled on "
                    "this platform; only the CPU-load trigger is active.",
                    _PROC_NET_SNMP,
                )
                self._packet_loss_unavailable_warned = True
            return 0.0

        retrans_segs, out_segs = counters
        prev = self._last_tcp_counters
        self._last_tcp_counters = counters
        if prev is None:
            return 0.0  # no baseline yet

        delta_retrans = retrans_segs - prev[0]
        delta_out = out_segs - prev[1]
        if delta_out <= 0 or delta_retrans <= 0:
            return 0.0
        return max(0.0, min(1.0, delta_retrans / delta_out))

    async def _activate_multipath(self):
        """Open async stream connections to all available peers for load balancing."""
        for peer in self.peers:
            peer_id = peer.get("id")
            address = peer.get("address")
            # We assume peers have a specific overlay port, e.g., port+10000
            overlay_port = peer.get("port", 443) + 10000 

            if peer_id not in self._active_tunnels:
                try:
                    # Establish encrypted overlay tunnel (using TLS in production)
                    _reader, writer = await asyncio.open_connection(address, overlay_port)
                    self._active_tunnels[peer_id] = writer
                    logger.info(f"Established Overlay Tunnel to Peer {peer_id} at {address}:{overlay_port}")
                except Exception as e:
                    logger.error(f"Failed to connect to Peer {peer_id} at {address}:{overlay_port} - {e}")

    async def _deactivate_multipath(self):
        """Close all overlay tunnels."""
        for peer_id, writer in list(self._active_tunnels.items()):
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        self._active_tunnels.clear()

mesh_router = MeshRouter()
