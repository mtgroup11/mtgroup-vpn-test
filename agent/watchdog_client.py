"""
MTGroup VPN Ultimate — Node-side Watchdog Client
═══════════════════════════════════════════════════════════════════
Speaks the same HMAC-signed ARM/HEARTBEAT protocol as
`backend/app/core/watchdog_client.py` over the local
`/var/run/mtgroup_watchdog.sock`, so `node_daemon.py` can arm the
Anti-Lockout Watchdog (`backend/app/core/watchdog.py`, installed by
`install.sh` on every host) before writing an AmneziaWG config change.

Reimplemented standalone rather than imported: `agent/` and `backend/`
are separate deployables that share no code (see `node_daemon.py`'s
module docstring) — this only needs to speak the same wire protocol,
not import anything from `backend.app`.

Best-effort throughout: a node without the watchdog installed (or with
its secret file missing) must not have peer add/remove start failing —
this is defence in depth, not a hard dependency.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import socket
import subprocess
import time

logger = logging.getLogger("node_daemon.watchdog_client")

SECRET_FILE = "/etc/mtgroup/watchdog.secret"
SOCK_FILE = "/var/run/mtgroup_watchdog.sock"
SNAPSHOT_DIR = "/var/lib/mtgroup/snapshots"
AWG_BAK_NAME = "awg0_config.conf.bak"


def _send(command: str) -> bool:
    try:
        with open(SECRET_FILE, "r", encoding="utf-8") as f:
            secret = f.read().strip().encode("utf-8")
    except OSError as exc:
        logger.warning("Could not read watchdog secret (%s) — %s not sent.", exc, command)
        return False

    timestamp = str(int(time.time()))
    signature = hmac.new(secret, timestamp.encode("utf-8"), hashlib.sha256).hexdigest()
    payload = f"{command}:{timestamp}:{signature}\n"

    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(SOCK_FILE)
        client.sendall(payload.encode("utf-8"))
        resp = client.recv(1024).decode("utf-8", errors="replace")
        client.close()
    except OSError as exc:
        logger.warning("Could not reach watchdog socket for %s: %s", command, exc)
        return False

    logger.info("Watchdog %s response: %s", command, resp.strip())
    return "SUCCESS" in resp


def arm_and_snapshot(config_path: str) -> bool:
    """
    Snapshot `config_path` (if it currently exists) and arm the watchdog.

    Call this immediately before writing an AmneziaWG config change.
    If the daemon crashes or hangs before `disarm()` runs, the watchdog's
    own timeout restores this snapshot — the same rollback that already
    protects `install.sh`'s local Xray/iptables changes.
    """
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    if os.path.exists(config_path):
        try:
            subprocess.run(
                ["cp", config_path, os.path.join(SNAPSHOT_DIR, AWG_BAK_NAME)],
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            logger.warning("Failed to snapshot %s before arming watchdog: %s", config_path, exc)
    return _send("ARM")


def disarm() -> bool:
    """
    Heartbeat the watchdog to cancel the rollback after a change applied
    without the process crashing.

    This only proves the *local* write/restart didn't blow up — unlike a
    human running `watchdog-client.sh` from a fresh SSH session, it can't
    confirm the change didn't break external reachability. That gap is
    accepted here because add_peer/remove_peer are unattended calls from
    the master with no human available to confirm; the timeout still
    catches the case where the daemon dies or hangs mid-change.
    """
    return _send("HEARTBEAT")
