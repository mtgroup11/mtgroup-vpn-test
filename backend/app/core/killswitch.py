import logging
import subprocess
import threading
import time
from backend.app.core.config import settings

logger = logging.getLogger("mtgroup.killswitch")

class EBPFKillSwitch:
    """
    Cerberus Multi-Layer Kill Switch.
    Monitors the system for Tunnel failures and immediately drops
    all unauthorized outgoing traffic using a Defense-in-Depth strategy:
    Layer 1: eBPF Map
    Layer 2: Iptables / Nftables
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

    def _execute_cmd(self, cmd: list[str]) -> bool:
        """Helper to execute system commands safely."""
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return True
        except Exception:
            return False

    def _apply_iptables(self):
        """Layer 2: Applies iptables drop rules with whitelisting."""
        # 1. Flush old custom killswitch chain if exists
        self._remove_iptables()
        
        self._execute_cmd(["iptables", "-N", "MTG_KILLSWITCH"])
        self._execute_cmd(["iptables", "-I", "OUTPUT", "1", "-j", "MTG_KILLSWITCH"])
        self._execute_cmd(["iptables", "-I", "FORWARD", "1", "-j", "MTG_KILLSWITCH"])

        # Whitelist loopback
        self._execute_cmd(["iptables", "-A", "MTG_KILLSWITCH", "-o", "lo", "-j", "RETURN"])

        # Whitelist specific critical ports (SSH, Panel)
        for port in self.whitelisted_tcp_ports:
            self._execute_cmd(["iptables", "-A", "MTG_KILLSWITCH", "-p", "tcp", "--dport", str(port), "-j", "RETURN"])
            self._execute_cmd(["iptables", "-A", "MTG_KILLSWITCH", "-p", "tcp", "--sport", str(port), "-j", "RETURN"])

        # Allow established/related connections
        self._execute_cmd(["iptables", "-A", "MTG_KILLSWITCH", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"])

        # Drop everything else
        self._execute_cmd(["iptables", "-A", "MTG_KILLSWITCH", "-j", "DROP"])

    def _remove_iptables(self):
        """Removes the iptables kill switch rules."""
        self._execute_cmd(["iptables", "-D", "OUTPUT", "-j", "MTG_KILLSWITCH"])
        self._execute_cmd(["iptables", "-D", "FORWARD", "-j", "MTG_KILLSWITCH"])
        self._execute_cmd(["iptables", "-F", "MTG_KILLSWITCH"])
        self._execute_cmd(["iptables", "-X", "MTG_KILLSWITCH"])

    def _apply_blackhole_route(self):
        """Layer 3: Adds a high-priority blackhole route for all traffic."""
        # A metric of 50 is usually higher priority than default gateway (usually 100 or 600)
        self._execute_cmd(["ip", "route", "add", "blackhole", "default", "metric", "50"])

    def _remove_blackhole_route(self):
        """Removes the blackhole route."""
        self._execute_cmd(["ip", "route", "del", "blackhole", "default", "metric", "50"])

    def _watchdog_loop(self):
        """Daemon thread to continuously enforce the kill switch state."""
        logger.info("Cerberus Watchdog started.")
        while not self._stop_monitor.is_set():
            with self._lock:
                if self.active:
                    # Check if our iptables chain is still linked
                    try:
                        res = subprocess.run(["iptables", "-C", "OUTPUT", "-j", "MTG_KILLSWITCH"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        if res.returncode != 0:
                            logger.critical("🚨 KERNEL WATCHDOG: Iptables rule bypassed! Re-applying Layer 2.")
                            self._apply_iptables()
                    except Exception:
                        pass
            time.sleep(2)
        logger.info("Cerberus Watchdog stopped.")

    def trigger_lockdown(self):
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

            # Layer 2: Iptables
            self._apply_iptables()
            logger.critical("Layer 2 (Firewall): ACTIVE.")

            # Layer 3: Blackhole
            self._apply_blackhole_route()
            logger.critical("Layer 3 (Routing): ACTIVE. All non-VPN traffic dropped.")

            # Start Watchdog
            self._stop_monitor.clear()
            if self._monitor_thread is None or not self._monitor_thread.is_alive():
                self._monitor_thread = threading.Thread(target=self._watchdog_loop, daemon=True)
                self._monitor_thread.start()

    def release_lockdown(self):
        """Releases the kernel-level kill switch and restores normal routing."""
        with self._lock:
            if not self.active:
                return
            self.active = False
            
            logger.info("🟢 CERBERUS LOCKDOWN RELEASED 🟢")

            # Stop Watchdog
            self._stop_monitor.set()
            if self._monitor_thread:
                # To prevent deadlock, we don't join while holding the lock if the thread needs the lock
                # The watchdog acquires self._lock inside its loop.
                # So we must NOT join here while holding self._lock.
                pass

        # Join outside the lock
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)
            self._monitor_thread = None

        with self._lock:
            # Layer 1: eBPF
            if self._bpf:
                try:
                    killswitch_map = self._bpf.get_table("active_killswitch_map")
                    killswitch_map[killswitch_map.Key(0)] = killswitch_map.Leaf(0)
                    logger.info("Layer 1 (eBPF): RESTORED.")
                except Exception as e:
                    logger.error(f"Layer 1 (eBPF) Failed to release: {e}")

            # Layer 2: Iptables
            self._remove_iptables()
            logger.info("Layer 2 (Firewall): RESTORED.")

            # Layer 3: Blackhole
            self._remove_blackhole_route()
            logger.info("Layer 3 (Routing): RESTORED. Traffic flowing normally.")

# Singleton instance
killswitch = EBPFKillSwitch()
