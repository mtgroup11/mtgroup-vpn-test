import os
import sys
import time
import hmac
import hashlib
import socket
import logging
import threading
import subprocess

# Constants
SOCK_FILE = "/var/run/mtgroup_watchdog.sock"
SECRET_FILE = "/etc/mtgroup/watchdog.secret"
LOG_FILE = "/var/log/mtgroup/watchdog.log"
SNAPSHOT_DIR = "/var/lib/mtgroup/snapshots"
IPTABLES_BAK = os.path.join(SNAPSHOT_DIR, "iptables.bak")
XRAY_BAK = os.path.join(SNAPSHOT_DIR, "xray_config.json.bak")
XRAY_TARGET = "/usr/local/etc/xray/config.json"
AWG_BAK = os.path.join(SNAPSHOT_DIR, "awg0_config.conf.bak")
AWG_TARGET = "/etc/amnezia/amneziawg/awg0.conf"
TIMEOUT_SECONDS = 60

# Setup logging
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_secret():
    try:
        with open(SECRET_FILE, "r") as f:
            return f.read().strip().encode('utf-8')
    except Exception as e:
        logging.critical(f"Could not read secret file {SECRET_FILE}: {e}")
        sys.exit(1)

class Watchdog:
    def __init__(self):
        self.secret = get_secret()
        self.timer = None
        self.armed = False
        self.lock = threading.Lock()

    def _execute_rollback(self):
        logging.warning("Watchdog timeout reached! Executing rollback...")
        
        success = True
        
        # 1. Restore iptables (list-argv, no shell — IPTABLES_BAK is a fixed
        # module constant, not attacker-influenced, but avoiding shell=True
        # is still the safer default for any subprocess call).
        if os.path.exists(IPTABLES_BAK):
            try:
                with open(IPTABLES_BAK, "rb") as bak:
                    subprocess.run(["iptables-restore"], stdin=bak, check=True)
                logging.info("iptables restored successfully.")
            except (subprocess.CalledProcessError, OSError) as e:
                logging.error(f"Failed to restore iptables: {e}")
                success = False
        else:
            logging.error(f"Iptables snapshot not found at {IPTABLES_BAK}")
            success = False

        # 2. Restore Xray config
        if os.path.exists(XRAY_BAK):
            try:
                subprocess.run(["cp", XRAY_BAK, XRAY_TARGET], check=True)
                logging.info("Xray config restored successfully.")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to restore Xray config: {e}")
                success = False
        else:
            logging.error(f"Xray snapshot not found at {XRAY_BAK}")
            success = False

        # 2b. Restore AmneziaWG config. Gated on the backup existing because
        # not every host runs AmneziaWG. Unlike iptables/Xray above, neither
        # step here affects `success`: SSH/network access — the thing the
        # last-resort fallback below exists to guarantee — has nothing to
        # do with whether a VPN tunnel protocol happens to be running,
        # exactly like the `mtgroup-backend` restart below. This matters in
        # practice: a *freshly provisioned* interface (install.sh's own use
        # case) is far more likely to fail its first start than a
        # previously-working Xray config is to fail restoring, and
        # escalating to a full iptables flush over that is real collateral
        # damage on a host running anything else.
        if os.path.exists(AWG_BAK):
            try:
                subprocess.run(["cp", AWG_BAK, AWG_TARGET], check=True)
                logging.info("AmneziaWG config restored successfully.")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to restore AmneziaWG config: {e}")

            try:
                subprocess.run(["systemctl", "restart", "awg-quick@awg0"], check=True)
                logging.info("AmneziaWG interface restarted.")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to restart AmneziaWG interface: {e}")

        # 3. Restart services
        try:
            subprocess.run(["systemctl", "restart", "xray"], check=True)
            logging.info("Xray service restarted.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to restart Xray service: {e}")
            success = False

        try:
            subprocess.run(["systemctl", "restart", "mtgroup-backend"], check=True)
            logging.info("Backend service restarted.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to restart Backend service: {e}")
            # Do not consider this a total failure if only backend fails but network is up
        
        # 4. Fallback if rollback failed
        if not success:
            logging.critical("Rollback encountered errors! Applying LAST RESORT iptables rules (ACCEPT all) to guarantee SSH access.")
            try:
                subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=True)
                subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=True)
                subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True)
                subprocess.run(["iptables", "-F"], check=True)
                logging.critical("Last resort iptables applied successfully. You must secure the server manually!")
            except subprocess.CalledProcessError as e:
                logging.critical(f"FAILED to apply last resort iptables: {e}. Server may be completely locked out.")
                
        with self.lock:
            self.armed = False

    def arm(self):
        with self.lock:
            if self.timer:
                self.timer.cancel()
            self.armed = True
            self.timer = threading.Timer(TIMEOUT_SECONDS, self._execute_rollback)
            self.timer.start()
            logging.info(f"Watchdog ARMED. Countdown started ({TIMEOUT_SECONDS}s).")

    def verify_auth(self, parts, action_name):
        if len(parts) != 3:
            return f"ERROR: Invalid {action_name} format\n", False
            
        timestamp_str = parts[1]
        signature = parts[2]
        
        try:
            client_time = float(timestamp_str)
        except ValueError:
            return "ERROR: Invalid timestamp\n", False
            
        current_time = time.time()
        
        # Check time window (allow +/- 60 seconds clock drift/delay)
        if abs(current_time - client_time) > 60:
            logging.warning(f"Rejected {action_name} due to timestamp window. Client: {client_time}, Server: {current_time}")
            return "ERROR: Timestamp out of bounds\n", False
            
        # Verify signature
        expected_sig = hmac.new(self.secret, timestamp_str.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, signature):
            logging.warning(f"Rejected {action_name} due to invalid signature. Potential replay attack or wrong secret.")
            return "ERROR: Invalid signature\n", False
            
        return "", True

    def handle_heartbeat(self, parts):
        err, valid = self.verify_auth(parts, "HEARTBEAT")
        if not valid:
            return err
            
        # Valid!
        with self.lock:
            if self.armed and self.timer:
                self.timer.cancel()
                self.armed = False
                logging.info("Valid heartbeat received. Watchdog DISARMED.")
                return "SUCCESS: Watchdog disarmed\n"
            else:
                return "INFO: Watchdog was not armed\n"

    def handle_arm(self, parts):
        err, valid = self.verify_auth(parts, "ARM")
        if not valid:
            return err
            
        self.arm()
        return "SUCCESS: Armed\n"
                
    def handle_connection(self, conn):
        try:
            data = conn.recv(1024).decode('utf-8').strip()
            parts = data.split(':')
            
            if parts[0] == "ARM":
                resp = self.handle_arm(parts)
                conn.sendall(resp.encode('utf-8'))
            elif parts[0] == "HEARTBEAT":
                resp = self.handle_heartbeat(parts)
                conn.sendall(resp.encode('utf-8'))
            else:
                conn.sendall(b"ERROR: Unknown command\n")
        except Exception as e:
            logging.error(f"Error handling connection: {e}")
        finally:
            conn.close()

    def run(self):
        if os.path.exists(SOCK_FILE):
            os.remove(SOCK_FILE)
            
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(SOCK_FILE)
        # Ensure only root or the specific user can write to the socket
        os.chmod(SOCK_FILE, 0o600)
        server.listen(5)
        logging.info(f"Watchdog listening on {SOCK_FILE}")
        
        try:
            while True:
                conn, addr = server.accept()
                threading.Thread(target=self.handle_connection, args=(conn,)).start()
        except KeyboardInterrupt:
            logging.info("Watchdog shutting down.")
        finally:
            server.close()
            if os.path.exists(SOCK_FILE):
                os.remove(SOCK_FILE)

if __name__ == "__main__":
    wd = Watchdog()
    wd.run()
