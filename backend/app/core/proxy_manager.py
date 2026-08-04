import json
import logging
import subprocess
import base64
from typing import Dict, Any, List
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from backend.app.core.watchdog_client import snapshot_and_arm

logger = logging.getLogger("mtgroup.proxy_manager")

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
        """
        if server_names is None:
            server_names = ["www.microsoft.com"]
            
        keys = self.generate_reality_keypair()
        
        config = {
            "log": {
                "loglevel": "warning"
            },
            "inbounds": [
                {
                    "port": port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [
                            {
                                "id": uuid,
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
            ]
        }
        return config

    def deploy_config(self, node_id: str, config: Dict[str, Any], filepath: str = "/etc/xray/config.json"):
        """
        Writes the configuration to disk and restarts/reloads the Xray service.
        """
        try:
            # Snapshot and arm watchdog before applying config
            snapshot_and_arm()
            
            with open(filepath, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info(f"Deployed new Xray config for Node {node_id} to {filepath}")
            
            # Restart Xray service (systemd or direct depending on setup)
            subprocess.run(["systemctl", "restart", "xray"], check=True)
            logger.info(f"Xray service restarted for Node {node_id}")
            
        except Exception as e:
            logger.error(f"Failed to deploy Xray config for Node {node_id}: {e}")
            raise
