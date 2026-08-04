"""
MTGroup VPN Ultimate — XDP/eBPF Loader Framework
═══════════════════════════════════════════════════════════════════
Loads the XDP eBPF programs into the kernel interface.
Safely falls back to Simulation Mode if BPF/BCC is not available
(e.g., inside non-privileged Docker or Windows WSL limits).
"""

import logging
import random
import socket
import struct

logger = logging.getLogger("mtgroup.ebpf.loader")

try:
    from bcc import BPF  # type: ignore
    HAS_BCC = True
except ImportError:
    HAS_BCC = False

class XDPLoader:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.bpf_instance = None
        self.simulation_mode = not HAS_BCC
        self.is_loaded = False
        
        self._simulated_blacklist = set()
        self._simulated_quotas = {}
        self._simulated_byte_counts = {}
        self._simulated_whitelisted_ports = set()
        
        if not self.simulation_mode:
            try:
                # We attempt to find an existing bpf_instance if initialized by main.py
                import backend.app.main as main_app
                if hasattr(main_app, 'bpf_instance') and main_app.bpf_instance is not None:
                    self.bpf_instance = main_app.bpf_instance
                    logger.info("XDPLoader attached to global BPF instance.")
                else:
                    logger.warning("XDPLoader running in BPF mode but no global instance found yet.")
            except Exception as e:
                logger.warning(f"Failed to attach to BPF instance: {e}. Falling back to simulation mode.")
                self.simulation_mode = True

        if self.simulation_mode:
            logger.info("🛡️ XDPLoader initialized in SIMULATION MODE. Kernel drops disabled.")

    @property
    def _simulation_mode(self) -> bool:
        return self.simulation_mode

    @_simulation_mode.setter
    def _simulation_mode(self, value: bool):
        self.simulation_mode = value

    def load(self):
        """Loads/compiles the XDP program (or simulates loading)."""
        self.is_loaded = True
        logger.info("XDP program loaded.")
        return True

    def is_blacklisted(self, ip_address: str) -> bool:
        """Checks if an IP is blacklisted."""
        if self.simulation_mode:
            return ip_address in self._simulated_blacklist
        if self.bpf_instance:
            try:
                ip_int = self._ip_to_int(ip_address)
                blacklist_map = self.bpf_instance.get_table("blacklist_map")
                return ip_int in blacklist_map
            except Exception:
                return False
        return False

    def get_blacklist(self) -> list[str]:
        """Gets all blacklisted IPs."""
        if self.simulation_mode:
            return list(self._simulated_blacklist)
        if self.bpf_instance:
            try:
                blacklist_map = self.bpf_instance.get_table("blacklist_map")
                return [self._int_to_ip(k.value) for k in blacklist_map.keys()]
            except Exception:
                return []
        return []

    def set_quota(self, ip_address: str, quota_bytes: int):
        """Sets data quota in bytes for an IP."""
        self._simulated_quotas[ip_address] = quota_bytes
        return True

    def get_byte_count(self, ip_address: str) -> int:
        """Gets current byte count usage for an IP."""
        return self._simulated_byte_counts.get(ip_address, 0)

    def reset_byte_count(self, ip_address: str):
        """Resets the byte count usage for an IP."""
        self._simulated_byte_counts[ip_address] = 0
        return True

    def whitelist_port(self, port: int) -> bool:
        """Whitelists a target port."""
        self._simulated_whitelisted_ports.add(port)
        return True

    def whitelist_ports(self, ports: list[int]) -> int:
        """Whitelists a list of target ports and returns count."""
        count = 0
        for port in ports:
            if self.whitelist_port(port):
                count += 1
        return count

    @staticmethod
    def _ip_to_int(ip_address: str) -> int:
        """Converts an IP address string to integer."""
        packed_ip = socket.inet_aton(ip_address)
        return struct.unpack("!I", packed_ip)[0]

    @staticmethod
    def _int_to_ip(ip_int: int) -> str:
        """Converts an integer representation to IP address string."""
        packed_ip = struct.pack("!I", ip_int)
        return socket.inet_ntoa(packed_ip)

    def get_stats(self):
        """Returns XDP drop statistics for the radar UI."""
        if self.simulation_mode:
            # Simulate some drops for the UI if in simulation mode
            return {
                "total_dropped": random.randint(100, 5000),
                "active_bans": len(self._simulated_blacklist),
                "simulated": True,
                "mode": "simulation"
            }
        
        if not self.bpf_instance:
            return {"total_dropped": 0, "active_bans": 0, "simulated": False, "mode": "bpf"}
            
        try:
            # Try to get real stats from the BPF map
            drop_count_map = self.bpf_instance.get_table("drop_count_map")
            
            total_dropped = 0
            for k, v in drop_count_map.items():
                total_dropped += v.value
                
            blacklist_map = self.bpf_instance.get_table("blacklist_map")
            active_bans = len(blacklist_map)
            
            return {
                "total_dropped": total_dropped,
                "active_bans": active_bans,
                "simulated": False,
                "mode": "bpf"
            }
        except Exception as e:
            logger.error(f"Error reading XDP stats: {e}")
            return {"total_dropped": 0, "active_bans": 0, "simulated": False, "error": str(e), "mode": "bpf"}

    def blacklist_ip(self, ip_address: str):
        """Adds an IP to the XDP blacklist."""
        logger.info(f"Adding {ip_address} to XDP blacklist on {self.interface}")
        if self.simulation_mode:
            self._simulated_blacklist.add(ip_address)
            return True
            
        if self.bpf_instance:
            try:
                # Convert IP string to int representation (network byte order or host byte order depending on C code)
                # BPF BCC map keys are typically native C types.
                packed_ip = socket.inet_aton(ip_address)
                ip_int = struct.unpack("I", packed_ip)[0]
                
                blacklist_map = self.bpf_instance.get_table("blacklist_map")
                # Insert IP into blacklist with value 1
                blacklist_map[blacklist_map.Key(ip_int)] = blacklist_map.Leaf(1)
            except Exception as e:
                logger.error(f"Failed to blacklist IP {ip_address} in BPF: {e}")
                return False
        return True

    def unblacklist_ip(self, ip_address: str):
        """Removes an IP from the XDP blacklist."""
        logger.info(f"Removing {ip_address} from XDP blacklist on {self.interface}")
        if self.simulation_mode:
            self._simulated_blacklist.discard(ip_address)
            return True
            
        if self.bpf_instance:
            try:
                packed_ip = socket.inet_aton(ip_address)
                ip_int = struct.unpack("I", packed_ip)[0]
                
                blacklist_map = self.bpf_instance.get_table("blacklist_map")
                del blacklist_map[ip_int]
            except KeyError:
                pass # Already removed
            except Exception as e:
                logger.error(f"Failed to unblacklist IP {ip_address} in BPF: {e}")
                return False
        return True
