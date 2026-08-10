"""
MTGroup VPN Ultimate — eBPF & nftables Test Suite
Tests for the XDP loader (simulation mode) and nftables manager.
"""

from __future__ import annotations

import pytest

from backend.app.ebpf.loader import XDPLoader
from backend.app.ebpf.nftables_manager import NFTablesManager


class TestXDPLoader:
    """Tests for the XDP/eBPF loader in simulation mode."""

    def setup_method(self):
        self.loader = XDPLoader(interface="eth0")
        # Force simulation mode (no BCC required)
        self.loader._simulation_mode = True

    def test_load_simulation(self):
        self.loader.load()
        assert self.loader.is_loaded

    def test_blacklist_ip(self):
        self.loader.load()
        assert self.loader.blacklist_ip("192.168.1.100")
        assert self.loader.is_blacklisted("192.168.1.100")
        assert not self.loader.is_blacklisted("192.168.1.101")

    def test_unblacklist_ip(self):
        self.loader.load()
        self.loader.blacklist_ip("10.0.0.1")
        assert self.loader.is_blacklisted("10.0.0.1")

        self.loader.unblacklist_ip("10.0.0.1")
        assert not self.loader.is_blacklisted("10.0.0.1")

    def test_get_blacklist(self):
        self.loader.load()
        self.loader.blacklist_ip("1.1.1.1")
        self.loader.blacklist_ip("2.2.2.2")
        bl = self.loader.get_blacklist()
        assert "1.1.1.1" in bl
        assert "2.2.2.2" in bl

    def test_quota_management(self):
        self.loader.load()
        self.loader.set_quota("10.0.0.5", 1073741824)  # 1 GB
        assert self.loader.get_byte_count("10.0.0.5") == 0

        self.loader.reset_byte_count("10.0.0.5")
        assert self.loader.get_byte_count("10.0.0.5") == 0

    def test_port_whitelist(self):
        self.loader.load()
        assert self.loader.whitelist_port(443)
        assert self.loader.whitelist_port(80)
        count = self.loader.whitelist_ports([8080, 8888, 50000])
        assert count == 3

    def test_stats(self):
        self.loader.load()
        stats = self.loader.get_stats()
        assert "mode" in stats
        assert stats["mode"] == "simulation"

    def test_ip_conversion(self):
        ip_int = XDPLoader._ip_to_int("192.168.1.1")
        ip_str = XDPLoader._int_to_ip(ip_int)
        assert ip_str == "192.168.1.1"

    def test_ip_conversion_edge_cases(self):
        for ip in ["0.0.0.0", "255.255.255.255", "127.0.0.1", "10.0.0.1"]:
            ip_int = XDPLoader._ip_to_int(ip)
            result = XDPLoader._int_to_ip(ip_int)
            assert result == ip


class TestNFTablesManager:
    """Tests for the nftables manager in dry-run mode."""

    def setup_method(self):
        self.nft = NFTablesManager(dry_run=True)

    @pytest.mark.asyncio
    async def test_initialize(self):
        result = await self.nft.initialize()
        assert result is True
        assert self.nft._initialized is True

    @pytest.mark.asyncio
    async def test_ban_ip(self):
        await self.nft.initialize()
        result = await self.nft.ban_ip("192.168.1.100", duration_hours=24)
        assert result is True

    @pytest.mark.asyncio
    async def test_port_redirect(self):
        await self.nft.initialize()
        result = await self.nft.setup_port_redirect(8080, 443)
        assert result is True

    @pytest.mark.asyncio
    async def test_port_pool_redirect(self):
        await self.nft.initialize()
        count = await self.nft.setup_port_pool_redirect([80, 8080, 443], 443)
        assert count == 2  # 80 and 8080 redirected; 443 skipped (it is the target)

    @pytest.mark.asyncio
    async def test_rate_limit(self):
        await self.nft.initialize()
        result = await self.nft.add_rate_limit(443, rate="25/second", burst=50)
        assert result is True

    @pytest.mark.asyncio
    async def test_syn_rate_limit(self):
        await self.nft.initialize()
        result = await self.nft.add_syn_rate_limit()
        assert result is True

    @pytest.mark.asyncio
    async def test_flush_all(self):
        await self.nft.initialize()
        result = await self.nft.flush_all()
        assert result is True
        assert self.nft._initialized is False

    def test_generate_ruleset_script(self):
        script = self.nft.generate_ruleset_script(
            banned_ips=["1.2.3.4", "5.6.7.8"],
            port_pool=[80, 8080, 8888],
            target_port=443,
        )
        assert "#!/usr/sbin/nft" in script
        assert "1.2.3.4" in script
        assert "5.6.7.8" in script
        assert "redirect to :443" in script

    @pytest.mark.asyncio
    async def test_get_ruleset_dry_run(self):
        await self.nft.initialize()
        ruleset = await self.nft.get_ruleset()
        # In dry-run mode, output is empty
        assert ruleset == ""

    @pytest.mark.asyncio
    async def test_ban_ip_rejects_shell_injection_attempt(self):
        """Regression test: `ban_ip` used to embed `ip` directly into a
        shell command string. Any non-address input must now be rejected
        by ipaddress.ip_address() validation before a command is ever
        built — with or without a live privileged helper socket."""
        await self.nft.initialize()
        malicious = "1.2.3.4; touch /tmp/pwned"
        assert await self.nft.ban_ip(malicious) is False

    @pytest.mark.asyncio
    async def test_unban_ip_rejects_invalid_input(self):
        await self.nft.initialize()
        assert await self.nft.unban_ip("not-an-ip") is False
