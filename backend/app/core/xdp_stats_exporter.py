"""
MTGroup VPN Ultimate — XDP Stats Exporter
═══════════════════════════════════════════════════════════════════
Periodically writes /run/mtgroup/xdp_stats.json. Both `cli.py` and the
Telegram bot read this file for their eBPF firewall display
(`total_dropped`, `active_v4`, `active_v6`) — until this existed, nothing
anywhere ever wrote it, so both displays degraded gracefully to zero
forever, on every deployment, regardless of whether eBPF was actually
protecting anything.
"""

import asyncio
import json
import logging
import os

logger = logging.getLogger("mtgroup.xdp_stats_exporter")

STATS_PATH = "/run/mtgroup/xdp_stats.json"
EXPORT_INTERVAL_SECONDS = 5.0


class XDPStatsExporter:
    """Wraps an `XDPLoader` and periodically snapshots its stats to disk."""

    def __init__(self, xdp_loader, stats_path: str = STATS_PATH):
        self._xdp_loader = xdp_loader
        self._stats_path = stats_path
        self.is_running = False
        self._task = None

    async def start(self):
        if self.is_running:
            return
        self.is_running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("XDP stats exporter started (writing %s).", self._stats_path)

    async def stop(self):
        self.is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("XDP stats exporter stopped.")

    async def _run_loop(self):
        while self.is_running:
            try:
                self._write_stats()
            except Exception as e:
                logger.error("XDP stats export failed: %s", e)
            await asyncio.sleep(EXPORT_INTERVAL_SECONDS)

    def _write_stats(self):
        raw = self._xdp_loader.get_stats()

        if raw.get("simulated"):
            # XDPLoader falls back to random fabricated numbers whenever
            # BCC isn't importable, independent of whether the operator
            # actually enabled eBPF (a pre-existing quirk of that class,
            # not this exporter's to fix) — never persist those. An
            # operator reading this file has no way to tell fake numbers
            # from real ones; leaving the file unwritten is honest, and
            # both readers already degrade gracefully to zero when it's
            # absent.
            return

        payload = {
            "total_dropped": raw.get("total_dropped", 0),
            # This loader's blacklist map is IPv4-only (_int_to_ip uses
            # socket.inet_ntoa) — active_v6 is always 0 until v6 support
            # exists. Kept in the schema since both readers already
            # index it unconditionally.
            "active_v4": raw.get("active_bans", 0),
            "active_v6": 0,
        }

        directory = os.path.dirname(self._stats_path)
        os.makedirs(directory, exist_ok=True)
        tmp_path = self._stats_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp_path, self._stats_path)
