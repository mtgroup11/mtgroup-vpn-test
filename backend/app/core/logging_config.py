"""
MTGroup VPN Ultimate — Structured Logging Configuration
JSON-formatted logs with rotation and security audit trail.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.app.core.config import settings


# ---------------------------------------------------------------------------
# Custom JSON Formatter
# ---------------------------------------------------------------------------

class JSONFormatter(logging.Formatter):
    """Emit structured JSON log lines for machine consumption."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
            }

        # Attach extra fields if present
        for attr in ("ip", "user_id", "username", "action", "detail", "request_id"):
            val = getattr(record, attr, None)
            if val is not None:
                log_entry[attr] = val

        return json.dumps(log_entry, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Security Audit Logger
# ---------------------------------------------------------------------------

class SecurityAuditLogger:
    """
    Dedicated audit logger for security-relevant events.
    Writes to a separate audit log file.
    """

    def __init__(self, log_file: str = "audit.log"):
        self.logger = logging.getLogger("mtgroup.audit")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        log_path = Path(log_file)
        handler = logging.handlers.RotatingFileHandler(
            str(log_path),
            maxBytes=settings.LOG_MAX_BYTES,
            backupCount=settings.LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(JSONFormatter())
        if not self.logger.handlers:
            self.logger.addHandler(handler)

    def log_login_attempt(
        self,
        ip: str,
        username: str,
        success: bool,
        detail: str = "",
    ) -> None:
        self.logger.info(
            "Login attempt",
            extra={
                "ip": ip,
                "username": username,
                "action": "login_success" if success else "login_failure",
                "detail": detail,
            },
        )

    def log_rate_limit(self, ip: str, endpoint: str) -> None:
        self.logger.warning(
            "Rate limit exceeded",
            extra={
                "ip": ip,
                "action": "rate_limit_exceeded",
                "detail": endpoint,
            },
        )

    def log_ban(self, ip: str, reason: str, duration_hours: int) -> None:
        self.logger.warning(
            "IP banned",
            extra={
                "ip": ip,
                "action": "ip_banned",
                "detail": f"reason={reason}, duration={duration_hours}h",
            },
        )

    def log_anomalous_handshake(self, ip: str, detail: str = "") -> None:
        self.logger.warning(
            "Anomalous handshake detected",
            extra={
                "ip": ip,
                "action": "anomalous_handshake",
                "detail": detail,
            },
        )

    def log_admin_action(
        self,
        admin_username: str,
        action: str,
        target: str,
        detail: str = "",
    ) -> None:
        self.logger.info(
            "Admin action",
            extra={
                "username": admin_username,
                "action": action,
                "detail": f"target={target} {detail}".strip(),
            },
        )

    def log_node_event(self, node_name: str, event: str, detail: str = "") -> None:
        self.logger.info(
            "Node event",
            extra={
                "action": f"node_{event}",
                "detail": f"node={node_name} {detail}".strip(),
            },
        )

    def log_user_event(
        self,
        username: str,
        action: str,
        detail: str = "",
    ) -> None:
        self.logger.info(
            "User event",
            extra={
                "username": username,
                "action": action,
                "detail": detail,
            },
        )

    def log_ip_redeploy(
        self, node_name: str, old_ip: str, new_ip: str
    ) -> None:
        self.logger.critical(
            "IP redeployed",
            extra={
                "action": "ip_redeploy",
                "detail": f"node={node_name} old={old_ip} new={new_ip}",
            },
        )


# ---------------------------------------------------------------------------
# Setup Function
# ---------------------------------------------------------------------------

def setup_logging() -> logging.Logger:
    """
    Configure the root application logger with JSON formatting,
    console output, and rotating file handler.
    """
    logger = logging.getLogger("mtgroup")
    logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))

    # Prevent duplicate handlers on reload
    if logger.handlers:
        return logger

    # Console handler (human-readable for development)
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    console_fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(console_fmt)
    logger.addHandler(console_handler)

    # File handler (JSON structured)
    log_path = Path(settings.LOG_FILE)
    file_handler = logging.handlers.RotatingFileHandler(
        str(log_path),
        maxBytes=settings.LOG_MAX_BYTES,
        backupCount=settings.LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(JSONFormatter())
    logger.addHandler(file_handler)

    return logger


# ---------------------------------------------------------------------------
# Global Instances
# ---------------------------------------------------------------------------

audit_logger = SecurityAuditLogger()
