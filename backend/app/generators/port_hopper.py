"""
MTGroup VPN Ultimate — Multi-Port Hopping Engine
Manages hybrid low/high port pools with per-second rotation
to neutralize port-targeted DPI throttling.
"""

from __future__ import annotations

import random
import time
import threading
import asyncio
from typing import Optional

try:
    from bcc import BPF  # type: ignore
    HAS_BCC = True
except ImportError:
    HAS_BCC = False



class PortHopper:
    """
    Manages a hybrid port pool combining standard privileged low ports
    (80, 443, 8080, 8888) with dynamic high ports (50000-65000).

    The hopping engine switches ports on a configurable schedule and
    can fragment transport layers across both pools seamlessly.
    """

    def __init__(
        self,
        low_ports: Optional[list[int]] = None,
        high_port_start: Optional[int] = None,
        high_port_end: Optional[int] = None,
        hop_interval_sec: Optional[int] = None,
        high_port_pool_size: int = 50,
    ):
        from backend.app.core.config import settings
        self.low_ports = low_ports or settings.low_port_list
        self.high_port_start = high_port_start if high_port_start is not None else settings.PORT_POOL_HIGH_START
        self.high_port_end = high_port_end if high_port_end is not None else settings.PORT_POOL_HIGH_END
        self.hop_interval_sec = hop_interval_sec if hop_interval_sec is not None else settings.PORT_HOP_INTERVAL_SEC
        self.high_port_pool_size = high_port_pool_size

        self._current_port: int = self.low_ports[0] if self.low_ports else 443
        self._current_index: int = 0
        self._last_hop_time: float = time.monotonic()
        self._lock = threading.Lock()

        # Pre-generate a randomized high port pool
        self._high_port_pool = self._generate_high_port_pool()
        self._combined_pool = self._build_combined_pool()

    def _generate_high_port_pool(self) -> list[int]:
        """Generate a randomized subset of high ports."""
        all_high = list(range(self.high_port_start, self.high_port_end + 1))
        random.shuffle(all_high)
        return all_high[: self.high_port_pool_size]

    def _build_combined_pool(self) -> list[int]:
        """Interleave low and high ports for maximum evasion."""
        combined = []
        high_iter = iter(self._high_port_pool)

        for low_port in self.low_ports:
            combined.append(low_port)
            # Interleave 3 high ports per low port
            for _ in range(3):
                try:
                    combined.append(next(high_iter))
                except StopIteration:
                    high_iter = iter(self._high_port_pool)
                    combined.append(next(high_iter))

        # Append remaining high ports
        for hp in high_iter:
            combined.append(hp)

        return combined

    def get_current_port(self) -> int:
        """Get the current active port, hopping if interval has elapsed."""
        with self._lock:
            now = time.monotonic()
            if now - self._last_hop_time >= self.hop_interval_sec:
                self._hop()
                self._last_hop_time = now
            return self._current_port

    def _hop(self) -> None:
        """Advance to the next port in the combined pool."""
        self._current_index = (self._current_index + 1) % len(self._combined_pool)
        self._current_port = self._combined_pool[self._current_index]

    def force_hop(self) -> int:
        """Force an immediate port hop. Returns the new port."""
        with self._lock:
            self._hop()
            self._last_hop_time = time.monotonic()
            return self._current_port

    def get_port_list_for_client(self, count: int = 10) -> list[int]:
        """
        Get a list of ports to embed in client configurations.
        Clients like Hysteria2 support multi-port (`mport`) for
        concurrent connection across multiple ports.
        """
        with self._lock:
            if count >= len(self._combined_pool):
                return list(self._combined_pool)

            start_idx = self._current_index
            result = []
            for i in range(count):
                idx = (start_idx + i) % len(self._combined_pool)
                result.append(self._combined_pool[idx])
            return result

    def get_port_range_string(self) -> str:
        """
        Get a port range string for Hysteria2/TUIC multi-port config.
        Format: "80,443,8080,8888,50000-65000"
        """
        low_str = ",".join(str(p) for p in self.low_ports)
        high_str = f"{self.high_port_start}-{self.high_port_end}"
        return f"{low_str},{high_str}"

    def get_nftables_port_set(self) -> str:
        """
        Generate an nftables port set expression for allowing all
        ports in the hopping pool.
        """
        ports = sorted(set(self.low_ports + self._high_port_pool))
        port_exprs = []
        i = 0
        while i < len(ports):
            start = ports[i]
            end = start
            while i + 1 < len(ports) and ports[i + 1] == end + 1:
                end = ports[i + 1]
                i += 1
            if start == end:
                port_exprs.append(str(start))
            else:
                port_exprs.append(f"{start}-{end}")
            i += 1
        return "{ " + ", ".join(port_exprs) + " }"

    def refresh_high_ports(self) -> None:
        """Regenerate the high port pool with new random ports."""
        with self._lock:
            self._high_port_pool = self._generate_high_port_pool()
            self._combined_pool = self._build_combined_pool()
            self._current_index = 0
            self._current_port = self._combined_pool[0]

    def get_stats(self) -> dict:
        """Get current hopping engine statistics."""
        with self._lock:
            return {
                "current_port": self._current_port,
                "current_index": self._current_index,
                "total_ports": len(self._combined_pool),
                "low_ports": self.low_ports,
                "high_port_range": f"{self.high_port_start}-{self.high_port_end}",
                "high_port_pool_size": len(self._high_port_pool),
                "hop_interval_sec": self.hop_interval_sec,
            }


class AsyncPortHoppingEngine:
    """
    Background worker that runs every X hours to dynamically shift the global port
    and push the new configuration to all connected nodes without dropping users.
    """
    def __init__(self, db_session_factory):
        self._db_session_factory = db_session_factory
        self._is_running = False
        self._worker_task: asyncio.Task | None = None
        self.hopper = PortHopper()
        self._bpf = None
        if HAS_BCC:
            try:
                # Attach to existing XDP maps if possible in a real deployment
                # This simulates pushing the new port into the kernel map
                self._bpf = BPF(text="BPF_ARRAY(active_port_map, u32, 1);")
            except Exception:
                pass
        
    async def start(self):
        if self._is_running:
            return
        self._is_running = True
        
        import logging
        logger = logging.getLogger("mtgroup.hopper")
        
        # Initialize eBPF maps with current ports
        if self._bpf:
            try:
                active_port_map = self._bpf.get_table("active_port_map")
                honeypot_port_map = self._bpf.get_table("honeypot_port_map")
                
                # Setup index 0 for both maps
                from backend.app.core.config import settings
                honeypot_port = getattr(settings, 'HONEYPOT_PORT', 8080)
                active_port_map[active_port_map.Key(0)] = active_port_map.Leaf(self.hopper.get_current_port())
                honeypot_port_map[honeypot_port_map.Key(0)] = honeypot_port_map.Leaf(honeypot_port)
                
                logger.info(f"Initialized XDP maps: active_port={self.hopper.get_current_port()}, honeypot_port={honeypot_port}")
            except Exception as e:
                logger.error(f"Failed to initialize XDP maps: {e}")

        self._worker_task = asyncio.create_task(self._hopping_loop())
        logger.info("Async Port Hopping Engine started.")

    async def stop(self):
        self._is_running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass

    async def _hopping_loop(self):
        from backend.app.orchestrator import orchestrator
        from backend.app.models import Node
        from sqlalchemy import select
        import logging
        
        logger = logging.getLogger("mtgroup.hopper")
        
        while self._is_running:
            try:
                # Hop every 6 hours (21600 seconds)
                await asyncio.sleep(21600)
                
                new_port = self.hopper.force_hop()
                logger.info(f"Dynamic Port Hopping triggered. New active port: {new_port}")
                
                # Fetch all active nodes
                async with self._db_session_factory() as session:
                    result = await session.execute(select(Node).where(Node.is_active.is_(True)))
                    nodes = result.scalars().all()
                    
                for node in nodes:
                    # Update the node port in DB
                    async with self._db_session_factory() as session:
                        node_db = await session.get(Node, node.id)
                        node_db.port = new_port
                        await session.commit()
                        
                    # Push to eBPF Map for Kernel-Level Port Routing
                    if self._bpf:
                        try:
                            active_port_map = self._bpf.get_table("active_port_map")
                            active_port_map[active_port_map.Key(0)] = active_port_map.Leaf(new_port)
                            logger.debug(f"Pushed new port {new_port} to XDP active_port_map")
                        except Exception as e:
                            logger.error(f"Failed to update XDP map: {e}")

                        
                    # Sync the new config payload to the Node Daemon
                    # We push a partial update telling it to rebind the port
                    # Using SO_REUSEPORT or graceful restart in the node daemon
                    # prevents dropping existing established connections.
                    payload = {
                        "action": "update_port",
                        "new_port": new_port
                    }
                    await orchestrator.sync_node_config(node, {
                        "config_type": node.protocol.value,
                        "payload": payload
                    })
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in async port hopping engine: {e}")
                await asyncio.sleep(60)

# The engine will be instantiated in main.py
