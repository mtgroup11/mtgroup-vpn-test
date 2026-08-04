"""
MTGroup VPN Ultimate — Asynchronous SSL/TLS Certificate Manager
═══════════════════════════════════════════════════════════════════
Automates Let's Encrypt SSL certificate provisioning and renewals
using certbot via non-blocking async subprocesses.
"""

import asyncio
import logging


logger = logging.getLogger("mtgroup.ssl_manager")


class AsyncSSLManager:
    """
    Manages SSL/TLS certificates asynchronously.
    """
    
    def __init__(self):
        self._is_running = False
        self._cron_task: asyncio.Task | None = None
        
    async def start_auto_renew_cron(self):
        """Starts the daily background check for certificate expiry."""
        if self._is_running:
            return
        self._is_running = True
        self._cron_task = asyncio.create_task(self._cron_loop())
        logger.info("AsyncSSLManager auto-renew cron started.")
        
    async def stop(self):
        """Stops the cron gracefully."""
        self._is_running = False
        if self._cron_task:
            self._cron_task.cancel()
            try:
                await self._cron_task
            except asyncio.CancelledError:
                pass
        logger.info("AsyncSSLManager auto-renew cron stopped.")
        
    async def issue_certificate(self, domain: str, email: str) -> bool:
        """
        Issues a new SSL certificate for a given domain using certbot standalone.
        Note: Port 80 must be free for standalone mode.
        """
        logger.info(f"Issuing new SSL certificate for {domain}")
        try:
            # We use --standalone, assuming this is run on the node or panel where port 80 is available
            cmd = [
                "certbot", "certonly", "--standalone",
                "--non-interactive", "--agree-tos",
                "-m", email, "-d", domain
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.info(f"Successfully issued certificate for {domain}:\n{stdout.decode()}")
                return True
            else:
                logger.error(f"Failed to issue certificate for {domain}. Error:\n{stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error executing certbot for {domain}: {e}")
            return False

    async def _check_and_renew(self):
        """Checks expiry of current domains managed by certbot and renews if necessary."""
        logger.info("Checking SSL certificate renewals...")
        try:
            # `certbot renew` automatically skips certificates that are not near expiry (< 30 days)
            # It also runs hooks if configured, but here we just call the raw command
            cmd = ["certbot", "renew", "--non-interactive"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            out_str = stdout.decode()
            if process.returncode == 0:
                if "No renewals were attempted" in out_str:
                    logger.debug("No certificates needed renewal.")
                else:
                    logger.info(f"Certificate renewal check completed:\n{out_str}")
                    # If certificates were renewed, we might want to reload FastAPI or the VPN process
                    # Usually certbot deploy-hook handles this, but we can do it manually if needed.
            else:
                logger.error(f"Error during certificate renewal check:\n{stderr.decode()}")
                
        except FileNotFoundError:
            logger.warning("Certbot is not installed. Skipping SSL renewal check.")
        except Exception as e:
            logger.error(f"Unexpected error during SSL renewal: {e}")

    async def _cron_loop(self):
        """Runs the renewal check once every 24 hours."""
        while self._is_running:
            try:
                await self._check_and_renew()
                
                # Sleep for 24 hours (86400 seconds)
                # We break it into smaller chunks so it can be interrupted cleanly
                for _ in range(8640):
                    if not self._is_running:
                        break
                    await asyncio.sleep(10.0)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Unexpected error in SSL cron loop: {e}")
                await asyncio.sleep(60.0)

# Singleton instance for the application lifespan
ssl_manager = AsyncSSLManager()
