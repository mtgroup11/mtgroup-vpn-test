"""
MTGroup VPN Ultimate — User-Node Mesh Network (Agent Side)
═══════════════════════════════════════════════════════════════════
Establishes a VPN-within-VPN overlay network among peer nodes.
Multipath routing is triggered ONLY when the main server's CPU load 
exceeds 85% or packet loss > 5%.
"""

import asyncio
import logging
import psutil
from typing import Dict, List, Any

logger = logging.getLogger("mtgroup.agent.mesh")


class MeshRouter:
    """
    Monitors local node health and dynamically routes traffic
    through peer nodes (Multipath) if resources are exhausted.
    """

    def __init__(self):
        self.peers: List[Dict[str, Any]] = []
        self._is_running = False
        self._worker_task: asyncio.Task | None = None
        self._active_tunnels: Dict[int, asyncio.StreamWriter] = {}

    def update_peers(self, new_peers: List[Dict[str, Any]]):
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
                
                # Mock packet loss detection (usually from ping/mtr or XDP stats)
                # We assume we have a function get_packet_loss()
                packet_loss = self._get_mock_packet_loss()
                
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

    def _get_mock_packet_loss(self) -> float:
        """Mock function for packet loss. In real life, calculate via TCP retransmits."""
        return 0.01  # Normal condition

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
                    reader, writer = await asyncio.open_connection(address, overlay_port)
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
