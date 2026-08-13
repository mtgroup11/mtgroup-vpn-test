"""
MTGroup VPN Ultimate — Application Configuration
Loads settings from environment variables / .env file.
Includes Zero-Knowledge DB encryption, active probe deflection,
and post-quantum shield toggles.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Central configuration loaded from environment variables."""

    # ── Application ──────────────────────────────────────────────────────
    APP_NAME: str = "MTGroup VPN Ultimate"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"  # nosec B104 - VPN panel must accept external client connections
    PORT: int = 8443
    BASE_URL: str = "https://panel.example.com"
    WORKERS: int = 4

    # ── Database ─────────────────────────────────────────────────────────
    DATABASE_URL: str = f"sqlite+aiosqlite:///{Path(__file__).resolve().parent.parent.parent.parent.as_posix()}/mtgroup.db"

    # ── JWT / Auth ───────────────────────────────────────────────────────
    JWT_SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(64))
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── Default Admin ────────────────────────────────────────────────────
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "MTGroup@2024!Secure"

    # ── TLS / Security ───────────────────────────────────────────────────
    TLS_CERT_PATH: Optional[str] = None
    TLS_KEY_PATH: Optional[str] = None
    CORS_ORIGINS: str = "*"

    # ── Rate Limiting ────────────────────────────────────────────────────
    RATE_LIMIT_REQUESTS: int = 60  # per window
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    MAX_FAILED_LOGINS: int = 5
    MAX_ANOMALOUS_HANDSHAKES: int = 3
    BAN_DURATION_HOURS: int = 24

    # ── Telegram ─────────────────────────────────────────────────────────
    TELEGRAM_BOT_TOKEN: str = ""
    TELEGRAM_ADMIN_ID: int = 0
    TELEGRAM_ENABLED: bool = False

    # ── Cloud Providers ──────────────────────────────────────────────────
    HETZNER_API_TOKEN: str = ""
    OVH_APP_KEY: str = ""
    OVH_APP_SECRET: str = ""
    OVH_CONSUMER_KEY: str = ""

    # ── CDN / Fronting ───────────────────────────────────────────────────
    CDN_WORKER_URL: str = ""
    CDN_ENABLED: bool = False

    # ── SNI Multiplexer / Active-Probe Deflection ─────────────────────────
    # Fronts :443 with a real TLS ClientHello-SNI router (core/routing_engine.py).
    # No backend routes are pre-registered here — everything that reaches it
    # falls through to DECOY_REVERSE_PROXY_TARGET, i.e. it behaves as a
    # probe-deflection façade on :443, not a live traffic router. The panel
    # API itself listens on SNI_MULTIPLEXER_API_PORT (loopback-friendly),
    # never on :443 directly. Off by default: operators must opt in.
    SNI_MULTIPLEXER_ENABLED: bool = False
    SNI_MULTIPLEXER_PORT: int = 443
    SNI_MULTIPLEXER_API_PORT: int = 8443
    # How often (seconds) the mux's backend routes are re-synced against
    # active nodes in the DB, so added/removed/renamed nodes get picked up
    # without a restart.
    SNI_MUX_SYNC_INTERVAL_SEC: int = 60

    # ── Traffic Accounting / Quota Enforcement ────────────────────────────
    # Suspends users/agents over data_limit_bytes and pushes drop commands
    # to nodes (core/accounting.py). Off by default: operators must opt in
    # after auditing existing data_used_bytes/data_limit_bytes values (see
    # CLAUDE.md). Once enabled it runs live (dry_run=False) — no separate
    # flag for that, since a flag left permanently in observe-only mode
    # enforces nothing.
    ACCOUNTING_ENABLED: bool = False

    # ── Subscription Defaults ────────────────────────────────────────────
    DEFAULT_PROTOCOLS: str = "vless_reality,hysteria2"
    DEFAULT_SNI: str = "www.google.com"
    DEFAULT_FINGERPRINT: str = "chrome"
    SUBSCRIPTION_PATH_PREFIX: str = "/sub"

    # ── Port Hopping ─────────────────────────────────────────────────────
    PORT_POOL_LOW: str = "80,443,8080,8888"
    PORT_POOL_HIGH_START: int = 50000
    PORT_POOL_HIGH_END: int = 65000
    PORT_HOP_INTERVAL_SEC: int = 1

    # ── Traffic Shaping ──────────────────────────────────────────────────
    TRAFFIC_SHAPE_MODE: str = "video_stream"
    JITTER_MIN_MS: int = 5
    JITTER_MAX_MS: int = 50
    CHAFF_INTERVAL_SEC: float = 0.5

    # ── TLS Fragmentation ────────────────────────────────────────────────
    TLS_FRAGMENT_ENABLED: bool = True
    TLS_FRAGMENT_SIZE_MIN: int = 50
    TLS_FRAGMENT_SIZE_MAX: int = 200
    TLS_FRAGMENT_INTERVAL_MIN_MS: int = 10
    TLS_FRAGMENT_INTERVAL_MAX_MS: int = 50
    TLS_PADDING_MIN: int = 64
    TLS_PADDING_MAX: int = 512

    # ── Zero-Knowledge Database Encryption ────────────────────────────
    # 64-char hex string for AES-GCM-256 field encryption.
    # Generate with:  python -c "import secrets; print(secrets.token_hex(32))"
    DB_ENCRYPTION_KEY: str = ""

    # ── Active Probe Deflection ──────────────────────────────────────
    # Unrecognised SNI/handshakes are reverse-proxied to this site
    # so that active probes see a legitimate web page, not a VPN.
    DECOY_REVERSE_PROXY_TARGET: str = "https://www.microsoft.com"

    # ── Post-Quantum Shield ──────────────────────────────────────────
    # Enable Kyber-768 KEM key exchange for tunnel negotiation.
    QUANTUM_SHIELD_ENABLED: bool = False

    # ── eBPF / Kernel ────────────────────────────────────────────────────
    EBPF_ENABLED: bool = False
    EBPF_INTERFACE: str = "eth0"
    NFTABLES_ENABLED: bool = False

    # ── Stealth Middleware ─────────────────────────────────────────────
    # Header value clients must send (X-Stealth-Token) to see the real API
    # instead of a 404. No default in production — must be set via env.
    STEALTH_TOKEN: str = ""

    # ── Privileged Helper Daemon ─────────────────────────────────────────
    # Unix socket the root-owned helper listens on. The backend process
    # talks to it instead of calling iptables/nft/systemctl/eBPF directly,
    # so the API process itself never needs NET_ADMIN/SYS_ADMIN.
    PRIVILEGED_HELPER_SOCKET: str = "/run/mtgroup/helper.sock"

    # ── Logging ──────────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "mtgroup.log"
    LOG_MAX_BYTES: int = 10_485_760  # 10 MB
    LOG_BACKUP_COUNT: int = 5

    # ── Paths ────────────────────────────────────────────────────────────
    FRONTEND_DIR: str = str(Path(__file__).resolve().parent.parent.parent.parent / "frontend")

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }

    @property
    def default_protocol_list(self) -> list[str]:
        return [p.strip() for p in self.DEFAULT_PROTOCOLS.split(",") if p.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def low_port_list(self) -> list[int]:
        return [int(p.strip()) for p in self.PORT_POOL_LOW.split(",") if p.strip()]


# Singleton instance
settings = Settings()
