import json
import logging
import base64
from typing import Dict, Any, List
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from backend.app.core.watchdog_client import snapshot_and_arm
from backend.app.core.privileged_helper import PrivilegedHelperError, helper_request

logger = logging.getLogger("mtgroup.proxy_manager")

# Xray's own conventional default for its local StatsService API port. Bound
# to 127.0.0.1 only (see build_vless_reality_config) — never exposed
# externally, so this isn't new attack surface, just a loopback query point
# the node daemon reads per-user traffic from.
XRAY_API_PORT = 10085


class ProxyManager:
    """
    Manages Xray-core configurations dynamically for DPI Evasion.
    Generates JSON configurations for VLESS+XTLS-Reality and obfuscated WireGuard.
    """

    def __init__(self, bin_path: str = "/usr/local/bin/xray"):
        self.bin_path = bin_path

    def generate_reality_keypair(self) -> Dict[str, str]:
        """
        Generates an x25519 keypair for XTLS-Reality.
        In a production environment, this would call the xray binary.
        """
        try:
            priv = x25519.X25519PrivateKey.generate()
            pub = priv.public_key()
            priv_bytes = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            pub_bytes = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            
            return {
                "privateKey": base64.urlsafe_b64encode(priv_bytes).decode().rstrip('='),
                "publicKey": base64.urlsafe_b64encode(pub_bytes).decode().rstrip('=')
            }
        except Exception as e:
            logger.error(f"Failed to generate Reality keypair: {e}")
            raise

    def build_vless_reality_config(self, port: int, uuid: str, sni_dest: str = "www.microsoft.com:443", server_names: List[str] = None) -> Dict[str, Any]:
        """
        Builds a dynamic JSON configuration for Xray-core utilizing VLESS and XTLS-Reality.

        Enables Xray's StatsService on a loopback-only API inbound
        (127.0.0.1:XRAY_API_PORT) with per-user stats turned on, and tags
        each client with an `email` — Xray's own per-user stats key, in the
        form `user>>>{email}>>>traffic>>>{uplink,downlink}`. The node daemon
        queries this via `xray api statsquery` to report per-user traffic
        (see agent/node_daemon.py's get_xray_user_traffic()). `email` is set
        to the client's `uuid` here since that's the only identifier this
        function receives; callers that pass a different identifier as
        `uuid` get that identifier back out of the stats query too.
        """
        if server_names is None:
            server_names = ["www.microsoft.com"]

        keys = self.generate_reality_keypair()

        config = {
            "log": {
                "loglevel": "warning"
            },
            "api": {
                "tag": "api",
                "services": ["StatsService"]
            },
            "stats": {},
            "policy": {
                "levels": {
                    "0": {
                        "statsUserUplink": True,
                        "statsUserDownlink": True
                    }
                },
                "system": {
                    "statsInboundUplink": True,
                    "statsInboundDownlink": True
                }
            },
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": XRAY_API_PORT,
                    "protocol": "dokodemo-door",
                    "settings": {"address": "127.0.0.1"},
                    "tag": "api"
                },
                {
                    "port": port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [
                            {
                                "id": uuid,
                                "email": uuid,
                                "flow": "xtls-rprx-vision"
                            }
                        ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "show": False,
                            "dest": sni_dest,
                            "xver": 0,
                            "serverNames": server_names,
                            "privateKey": keys["privateKey"],
                            "shortIds": [""] # Can be generated dynamically
                        }
                    }
                }
            ],
            "outbounds": [
                {
                    "protocol": "freedom",
                    "tag": "direct"
                }
            ],
            "routing": {
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": ["api"],
                        "outboundTag": "api"
                    }
                ]
            }
        }
        return config

    async def deploy_config(self, node_id: str, config: Dict[str, Any], filepath: str = "/etc/xray/config.json"):
        """
        Writes the configuration to disk and restarts the Xray service.
        The restart goes through the privileged helper daemon — this
        process never calls `systemctl` itself.
        """
        try:
            # Snapshot and arm watchdog before applying config
            snapshot_and_arm()

            with open(filepath, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info(f"Deployed new Xray config for Node {node_id} to {filepath}")

            resp = await helper_request("service.restart", {"service": "xray"})
            if not resp.ok:
                raise RuntimeError(f"privileged helper refused xray restart: {resp.message}")
            logger.info(f"Xray service restarted for Node {node_id}")

        except PrivilegedHelperError as e:
            logger.error(f"Could not reach privileged helper to restart Xray for Node {node_id}: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to deploy Xray config for Node {node_id}: {e}")
            raise
