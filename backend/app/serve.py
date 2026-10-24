"""
MTGroup VPN Ultimate — production entry point

    python -m backend.app.serve

Binds to settings.HOST:settings.PORT and serves HTTPS when TLS_CERT_PATH and
TLS_KEY_PATH are set. Without TLS the stealth token and admin JWTs cross the
network in clear text, so terminate TLS here or in front of the panel.

Always a single worker process. The app keeps state in memory — app-level IP
bans, the rate limiter, and the orchestrator / node-user-sync / health-poll
loops — so N workers would mean N copies of every background loop pushing
to nodes, and bans that only apply on whichever worker recorded them.
"""

from __future__ import annotations

import logging

import uvicorn

from backend.app.core.config import settings


def main() -> None:
    tls: dict[str, str] = {}
    if settings.TLS_CERT_PATH and settings.TLS_KEY_PATH:
        tls = {"ssl_certfile": settings.TLS_CERT_PATH, "ssl_keyfile": settings.TLS_KEY_PATH}
    elif not settings.DEBUG:
        logging.getLogger("mtgroup.serve").warning(
            "Serving the panel over plain HTTP on :%s. Set TLS_CERT_PATH/TLS_KEY_PATH "
            "or put a TLS terminator in front — the stealth token and admin tokens "
            "are otherwise readable on the wire.", settings.PORT,
        )
    if settings.WORKERS != 1:
        logging.getLogger("mtgroup.serve").warning(
            "WORKERS=%s ignored: the panel must run as one process (see serve.py).", settings.WORKERS,
        )
    uvicorn.run(
        "backend.app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        workers=1,
        server_header=False,  # no "server: uvicorn" fingerprint
        **tls,
    )


if __name__ == "__main__":
    main()
