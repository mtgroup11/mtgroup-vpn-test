"""
MTGroup VPN Ultimate — Dynamic Honeypot Engine
Acts as an asynchronous Nginx simulator to deceive Active Probes.
"""

import asyncio
import logging
import ssl
from datetime import datetime, timedelta, timezone
import tempfile
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from backend.app.core.config import settings
from backend.app.orchestrator import orchestrator

logger = logging.getLogger("mtgroup.honeypot")

NGINX_404_RESPONSE = b"""HTTP/1.1 404 Not Found
Server: nginx/1.18.0 (Ubuntu)
Date: {date}
Content-Type: text/html
Content-Length: 162
Connection: keep-alive

<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
"""

NGINX_200_RESPONSE = b"""HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: {date}
Content-Type: text/html
Content-Length: 612
Last-Modified: Tue, 21 Apr 2020 14:09:01 GMT
Connection: keep-alive
ETag: "5e9efe7d-264"
Accept-Ranges: bytes

<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>
</body>
</html>
"""

class HoneypotEngine:
    def __init__(self, host: str = "0.0.0.0", port: int | None = None):  # nosec B104 - decoy server must be reachable from the public internet to bait probes
        self.host = host
        # Default fallback to 8080 if not defined in config
        # Expecting HONEYPOT_PORT in config, but using PORT or a default for now.
        self.port = port if port is not None else getattr(settings, 'HONEYPOT_PORT', 8080)
        self._server = None
        self._is_running = False
        self._cert_path = None
        self._key_path = None

    async def _generate_self_signed_cert(self):
        """Generates a temporary self-signed certificate for the Honeypot SSL/TLS handshake."""
        logger.info("Generating temporary self-signed SSL certificate for Honeypot using cryptography...")
        # Generate our key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Generate our certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Nginx Server"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Web"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=3650)
        ).sign(key, hashes.SHA256())
        
        cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
        key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
        
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        
        cert_file.close()
        key_file.close()
        
        self._cert_path = cert_file.name
        self._key_path = key_file.name
        logger.debug(f"Self-signed cert created at: {self._cert_path}")

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        logger.info(f"[HONEYPOT] Connection received from Active Probe: {addr}")
        try:
            # Read the HTTP request (Active Probes usually send a GET /)
            data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            request = data.decode('utf-8', errors='ignore')
            
            # Format Date header for realism
            current_date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT").encode()
            
            if request.startswith("GET / HTTP"):
                response = NGINX_200_RESPONSE.replace(b"{date}", current_date)
            else:
                # LETHAL DECOY CHECK: If probe asks for sensitive files, ban permanently.
                if "/admin/backup.sql.zip" in request or "/.env" in request:
                    logger.critical(f"[LETHAL HONEYPOT] Active Probe requested sensitive file: {addr[0]}")
                    reason = "LETHAL_PROBE: Attempted to access decoy sensitive files"
                    # handle_security_alert() already branches internally on
                    # EBPF_ENABLED (XDP blacklist vs. the app-level ban set
                    # enforced by stealth_middleware) — gating the call
                    # itself on EBPF_ENABLED meant probes were never banned
                    # at all when eBPF was disabled, silently defeating the
                    # "lethal" honeypot with no error or warning.
                    await orchestrator.handle_security_alert(addr[0], reason)

                response = NGINX_404_RESPONSE.replace(b"{date}", current_date)
                
            writer.write(response)
            await writer.drain()
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug(f"[HONEYPOT] Error handling probe {addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self):
        if self._is_running:
            return
        self._is_running = True
        
        await self._generate_self_signed_cert()
        
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=self._cert_path, keyfile=self._key_path)
        
        self._server = await asyncio.start_server(
            self.handle_client, 
            self.host, 
            self.port,
            ssl=ssl_context
        )
        logger.info(f"🛡️ Dynamic Honeypot Engine (TLS/SSL) started on {self.host}:{self.port} (Simulating Nginx)")

    async def stop(self):
        self._is_running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            
        # Clean up temp certs
        if self._cert_path and os.path.exists(self._cert_path):
            os.remove(self._cert_path)
        if self._key_path and os.path.exists(self._key_path):
            os.remove(self._key_path)
            
        logger.info("Dynamic Honeypot Engine stopped and temp certs cleaned.")

# Singleton
honeypot = HoneypotEngine()
