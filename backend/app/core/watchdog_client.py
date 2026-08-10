import socket
import logging
import subprocess
import os
import time
import hmac
import hashlib

logger = logging.getLogger("mtgroup.watchdog_client")

SECRET_FILE = "/etc/mtgroup/watchdog.secret"

SOCK_FILE = "/var/run/mtgroup_watchdog.sock"
SNAPSHOT_DIR = "/var/lib/mtgroup/snapshots"

def snapshot_and_arm():
    """
    Snapshots current iptables and Xray configs, then arms the watchdog.
    """
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    
    # 1. Snapshot iptables (list-argv, no shell — output redirected in
    # Python rather than via a shell `>` operator)
    try:
        with open(os.path.join(SNAPSHOT_DIR, "iptables.bak"), "wb") as bak:
            subprocess.run(["iptables-save"], stdout=bak, check=True)
        logger.info("Saved iptables snapshot.")
    except (OSError, subprocess.CalledProcessError) as e:
        logger.warning(f"Failed to snapshot iptables: {e}")

    # 2. Snapshot Xray
    xray_conf = "/usr/local/etc/xray/config.json"
    if os.path.exists(xray_conf):
        try:
            subprocess.run(["cp", xray_conf, os.path.join(SNAPSHOT_DIR, "xray_config.json.bak")], check=True)
            logger.info("Saved Xray config snapshot.")
        except (OSError, subprocess.CalledProcessError) as e:
            logger.warning(f"Failed to snapshot Xray config: {e}")
            
    # 3. Arm watchdog with authentication
    try:
        # Read secret
        with open(SECRET_FILE, "r") as f:
            secret = f.read().strip().encode('utf-8')
            
        timestamp = str(int(time.time()))
        signature = hmac.new(secret, timestamp.encode('utf-8'), hashlib.sha256).hexdigest()
        payload = f"ARM:{timestamp}:{signature}\n"
        
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(SOCK_FILE)
        client.sendall(payload.encode('utf-8'))
        resp = client.recv(1024).decode('utf-8')
        logger.info(f"Watchdog arm response: {resp.strip()}")
        client.close()
    except Exception as e:
        logger.error(f"Failed to connect to watchdog socket or arm: {e}. Watchdog is NOT armed!")
