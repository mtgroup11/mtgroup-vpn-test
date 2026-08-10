import ipaddress
import logging
import asyncio
import shlex
from typing import List

from backend.app.core.privileged_helper import PrivilegedHelperError, helper_request

logger = logging.getLogger("mtgroup.ebpf.nftables")

class NFTablesManager:
    """
    Manages nftables rules for firewalling, redirection, rate-limiting, and banning.

    NOTE: table/chain setup and port-redirect/rate-limit rules below are
    built from fixed, operator-controlled config (not request-derived
    strings), so they are executed in-process rather than via the
    privileged helper daemon. `ban_ip`/`unban_ip` are the exception — they
    embed a caller-supplied IP address, so they always go through the
    daemon's validated `firewall.ban_ip`/`firewall.unban_ip` operations
    (see below). This method still avoids a shell (`create_subprocess_exec`
    with `shlex.split`, not `create_subprocess_shell`) as defense in depth.
    """
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self._initialized = False

    async def _run_nft(self, command: str) -> bool:
        """Helper to execute nft commands or print them in dry-run mode."""
        if self.dry_run:
            logger.info(f"[DRY RUN] {command}")
            return True
        try:
            argv = shlex.split(command)
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.error(f"nft command failed: {stderr.decode()}")
                return False
            return True
        except Exception as e:
            logger.error(f"Failed to execute nft command: {e}")
            return False

    async def initialize(self) -> bool:
        """Initializes the mtgroup inet table and its chains."""
        success = True
        # 1. Create table
        success &= await self._run_nft("nft add table inet mtgroup")
        # 2. Create input filter chain for banning
        success &= await self._run_nft("nft add chain inet mtgroup banned_ips { type filter hook input priority -10 \\; policy accept \\; }")
        # 3. Create nat prerouting chain for port forwarding
        success &= await self._run_nft("nft add chain inet mtgroup port_forward { type nat hook prerouting priority -100 \\; }")
        # 4. Create filter input chain for rate limits
        success &= await self._run_nft("nft add chain inet mtgroup rate_limit { type filter hook input priority 0 \\; policy accept \\; }")
        
        if success:
            self._initialized = True
            logger.info("nftables table 'mtgroup' initialized")
        return success

    async def ban_ip(self, ip: str, duration_hours: int = 24) -> bool:
        """Bans an IP address by adding it to the privileged helper's
        nftables ban set.

        `ip` is validated with `ipaddress.ip_address()` *before* anything
        else happens — this used to be embedded directly into a shell
        command string (`create_subprocess_shell`), which was a shell
        injection vector. The actual `nft` invocation now happens in the
        root-owned privileged helper daemon, as a fixed argv list, never
        a shell string.
        """
        if not self._initialized:
            logger.warning("nftables manager not initialized.")
            return False
        try:
            ipaddress.ip_address(ip.strip())
        except ValueError:
            logger.error(f"Refusing to ban invalid IP address: {ip!r}")
            return False

        if self.dry_run:
            logger.info(f"[DRY RUN] ban_ip({ip})")
            return True

        try:
            resp = await helper_request("firewall.ban_ip", {"ip": ip.strip()})
        except PrivilegedHelperError as e:
            logger.error(f"Failed to reach privileged helper to ban {ip}: {e}")
            return False
        if resp.ok:
            logger.info(f"Banned IP {ip} for {duration_hours}h via nftables")
        else:
            logger.error(f"Privileged helper rejected ban for {ip}: {resp.message}")
        return resp.ok

    async def unban_ip(self, ip: str) -> bool:
        """Removes an IP from the privileged helper's nftables ban set."""
        try:
            ipaddress.ip_address(ip.strip())
        except ValueError:
            logger.error(f"Refusing to unban invalid IP address: {ip!r}")
            return False

        if self.dry_run:
            logger.info(f"[DRY RUN] unban_ip({ip})")
            return True

        try:
            resp = await helper_request("firewall.unban_ip", {"ip": ip.strip()})
        except PrivilegedHelperError as e:
            logger.error(f"Failed to reach privileged helper to unban {ip}: {e}")
            return False
        if not resp.ok:
            logger.error(f"Privileged helper rejected unban for {ip}: {resp.message}")
        return resp.ok

    async def setup_port_redirect(self, from_port: int, to_port: int) -> bool:
        """Sets up a single port redirection to a target port."""
        if not self._initialized:
            return False
        command = f"nft add rule inet mtgroup port_forward tcp dport {from_port} redirect to :{to_port}"
        return await self._run_nft(command)

    async def setup_port_pool_redirect(self, port_pool: List[int], target_port: int) -> int:
        """Redirects all ports in port_pool to target_port except the target_port itself."""
        if not self._initialized:
            return 0
        redirected_count = 0
        for port in port_pool:
            if port == target_port:
                continue
            success = await self.setup_port_redirect(port, target_port)
            if success:
                redirected_count += 1
        logger.info(f"Set up {len(port_pool)} port redirects to port {target_port}")
        return redirected_count

    async def add_rate_limit(self, port: int, rate: str = "25/second", burst: int = 50) -> bool:
        """Sets a rate limit rule for a specific port."""
        if not self._initialized:
            return False
        command = f"nft add rule inet mtgroup rate_limit tcp dport {port} limit rate {rate} burst {burst} packets accept"
        return await self._run_nft(command)

    async def add_syn_rate_limit(self) -> bool:
        """Sets a global rate limit rule for TCP SYN packets."""
        if not self._initialized:
            return False
        command = "nft add rule inet mtgroup rate_limit tcp flags syn limit rate 10/second burst 20 packets accept"
        return await self._run_nft(command)

    async def flush_all(self) -> bool:
        """Deletes the mtgroup table and resets state."""
        if not self._initialized:
            return False
        command = "nft delete table inet mtgroup"
        success = await self._run_nft(command)
        if success:
            self._initialized = False
            logger.info("Flushed entire nftables table 'mtgroup'")
        return success

    def generate_ruleset_script(self, banned_ips: List[str], port_pool: List[int], target_port: int) -> str:
        """Generates a standalone nft ruleset script."""
        script_lines = [
            "#!/usr/sbin/nft",
            "flush ruleset",
            "table inet mtgroup {",
            "    chain banned_ips {",
            "        type filter hook input priority -10; policy accept;",
        ]
        for ip in banned_ips:
            script_lines.append(f"        ip saddr {ip} counter drop comment \"auto-ban\"")
        script_lines.extend([
            "    }",
            "    chain port_forward {",
            "        type nat hook prerouting priority -100;",
        ])
        for port in port_pool:
            if port != target_port:
                script_lines.append(f"        tcp dport {port} redirect to :{target_port}")
        script_lines.extend([
            "    }",
            "    chain rate_limit {",
            "        type filter hook input priority 0; policy accept;",
            "    }",
            "}"
        ])
        return "\n".join(script_lines)

    async def get_ruleset(self) -> str:
        """Gets current ruleset. In dry-run mode, returns empty string."""
        if self.dry_run:
            return ""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nft", "list", "ruleset",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                return stdout.decode()
            return ""
        except Exception:
            return ""
