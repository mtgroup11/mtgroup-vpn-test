import logging
import threading
import time
from backend.app.core.config import settings
from backend.app.core.privileged_helper import (
    PrivilegedHelperError,
    helper_request,
    helper_request_sync,
)

logger = logging.getLogger("mtgroup.killswitch")

class EBPFKillSwitch:
    """
    Cerberus Multi-Layer Kill Switch.
    Monitors the system for Tunnel failures and immediately drops
    all unauthorized outgoing traffic using a Defense-in-Depth strategy:
    Layer 1: eBPF Map
    Layer 2: Iptables / Nftables (applied via the privileged helper daemon —
             this process never calls iptables/ip route itself)
    Layer 3: Blackhole Routing
    """
    def __init__(self):
        self.active = False
        self._bpf = None
        self._lock = threading.Lock()
        self._monitor_thread = None
        self._stop_monitor = threading.Event()

        # Ports that MUST remain open even during lockdown (e.g., SSH, Panel)
        self.whitelisted_tcp_ports = [22, settings.PORT, 80, 443]

    def initialize(self, bpf_module):
        """Injects the BPF module for map manipulation."""
        self._bpf = bpf_module
        logger.info("Cerberus Kill Switch initialized (Multi-Layer Engine Ready).")

    def _watchdog_loop(self):
        """Daemon thread to continuously enforce the kill switch state.
        Uses the blocking helper client — this runs on a plain thread,
        not the asyncio event loop."""
        logger.info("Cerberus Watchdog started.")
        while not self._stop_monitor.is_set():
            with self._lock:
                if self.active:
                    try:
                        resp = helper_request_sync("killswitch.status", timeout=5.0)
                        if resp.ok and resp.data and not resp.data.get("linked", True):
                            logger.critical("🚨 KERNEL WATCHDOG: Iptables rule bypassed! Re-applying Layer 2.")
                            helper_request_sync(
                                "killswitch.apply",
                                {"whitelist_ports": self.whitelisted_tcp_ports},
                                timeout=10.0,
                            )
                    except PrivilegedHelperError as e:
                        logger.error(f"Watchdog could not reach privileged helper: {e}")
            time.sleep(2)
        logger.info("Cerberus Watchdog stopped.")

    async def trigger_lockdown(self):
        """Triggers the ultimate multi-layer kill switch."""
        with self._lock:
            if self.active:
                return
            self.active = True

        logger.critical("🚨 CERBERUS LOCKDOWN INITIATED 🚨")

        # Layer 1: eBPF
        if self._bpf:
            try:
                killswitch_map = self._bpf.get_table("active_killswitch_map")
                killswitch_map[killswitch_map.Key(0)] = killswitch_map.Leaf(1)
                logger.critical("Layer 1 (eBPF): ACTIVE.")
            except Exception as e:
                logger.error(f"Layer 1 (eBPF) Failed: {e}")
        else:
            logger.warning("Layer 1 (eBPF): SKIPPED (Dry-Run / Not Loaded).")

        # Layer 2 + 3: iptables chain + blackhole route, via privileged helper
        try:
            resp = await helper_request(
                "killswitch.apply",
                {"whitelist_ports": self.whitelisted_tcp_ports},
                timeout=15.0,
            )
            if resp.ok:
                logger.critical("Layer 2/3 (Firewall + Routing): ACTIVE. All non-VPN traffic dropped.")
            else:
                logger.error(f"Layer 2/3 apply failed: {resp.message}")
        except PrivilegedHelperError as e:
            logger.error(f"Could not reach privileged helper to apply lockdown: {e}")

        # Start Watchdog
        self._stop_monitor.clear()
        if self._monitor_thread is None or not self._monitor_thread.is_alive():
            self._monitor_thread = threading.Thread(target=self._watchdog_loop, daemon=True)
            self._monitor_thread.start()

    async def release_lockdown(self):
        """Releases the kernel-level kill switch and restores normal routing."""
        with self._lock:
            if not self.active:
                return
            self.active = False

        logger.info("🟢 CERBERUS LOCKDOWN RELEASED 🟢")

        # Stop Watchdog — join outside self._lock since the watchdog thread
        # itself acquires self._lock inside its loop (avoids deadlock).
        self._stop_monitor.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)
            self._monitor_thread = None

        # Layer 1: eBPF
        if self._bpf:
            try:
                killswitch_map = self._bpf.get_table("active_killswitch_map")
                killswitch_map[killswitch_map.Key(0)] = killswitch_map.Leaf(0)
                logger.info("Layer 1 (eBPF): RESTORED.")
            except Exception as e:
                logger.error(f"Layer 1 (eBPF) Failed to release: {e}")

        # Layer 2 + 3: via privileged helper
        try:
            resp = await helper_request("killswitch.release", timeout=15.0)
            if resp.ok:
                logger.info("Layer 2/3 (Firewall + Routing): RESTORED. Traffic flowing normally.")
            else:
                logger.error(f"Layer 2/3 release failed: {resp.message}")
        except PrivilegedHelperError as e:
            logger.error(f"Could not reach privileged helper to release lockdown: {e}")

# Singleton instance
killswitch = EBPFKillSwitch()
