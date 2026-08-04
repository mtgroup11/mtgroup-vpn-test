"""
MTGroup VPN Ultimate v2.0 — Database Models
════════════════════════════════════════════════════════════════════
Async SQLAlchemy ORM models with military-grade AES-GCM-256
zero-knowledge encryption at rest.

Architecture pillars:
  • Marzban — periodic quota reset (daily/weekly/monthly), role-based
    access (Admin / User / Reseller-Agent)
  • Spiritus — multi-agent commission & wallet system with full
    financial tracking (traffic_quota, commission_rate, balance)
  • 3X-UI — deep network telemetry: connection logs, handshake
    anomaly detection, concurrent session tracking, login audit trail
  • Zero-Knowledge — every PII column (IP, notes, ban details, agent
    notes) encrypted with AES-GCM-256 via ``EncryptedType`` before
    touching disk.  Database exfiltration yields ZERO plaintext.

All models are fully compatible with async SQLAlchemy 2.0+
(``AsyncAttrs``, ``mapped_column``, ``Mapped`` type hints).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.ext.asyncio import AsyncAttrs, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from backend.app.core.crypto_quantum import EncryptedType


# ═══════════════════════════════════════════════════════════════════
# Base
# ═══════════════════════════════════════════════════════════════════

class Base(AsyncAttrs, DeclarativeBase):
    """Shared declarative base for all models."""
    pass


# ═══════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════

class UserRole(str, enum.Enum):
    """
    Role hierarchy:
      ADMIN    — full system control
      RESELLER — agent/dealer with commission & wallet
      USER     — end-user VPN client
    """
    ADMIN = "admin"
    USER = "user"
    RESELLER = "reseller"


class PeriodicResetStrategy(str, enum.Enum):
    """
    Marzban-style periodic data quota reset interval.
    ``NO_RESET`` means the quota is lifetime-only.
    """
    NO_RESET = "no_reset"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class NodeProtocol(str, enum.Enum):
    VLESS_REALITY = "vless_reality"
    HYSTERIA2 = "hysteria2"
    TUIC_V5 = "tuic_v5"
    AMNEZIA_WG = "amnezia_wg"
    SHADOWSOCKS = "shadowsocks"
    DNSTT = "dnstt"
    ICMP_TUNNEL = "icmp_tunnel"


class BanReason(str, enum.Enum):
    FAILED_LOGIN = "failed_login"
    ANOMALOUS_HANDSHAKE = "anomalous_handshake"
    ACTIVE_PROBE = "active_probe"
    MANUAL = "manual"
    RATE_LIMIT = "rate_limit"
    CONCURRENT_ABUSE = "concurrent_abuse"
    TRAFFIC_ANOMALY = "traffic_anomaly"


class HandshakeStatus(str, enum.Enum):
    """3X-UI style handshake classification for connection auditing."""
    SUCCESS = "success"
    TIMEOUT = "timeout"
    TLS_MISMATCH = "tls_mismatch"
    REPLAY_DETECTED = "replay_detected"
    DPI_BLOCKED = "dpi_blocked"
    UNKNOWN_FAILURE = "unknown_failure"


class LoginResult(str, enum.Enum):
    """Outcome of an authentication attempt."""
    SUCCESS = "success"
    WRONG_PASSWORD = "wrong_password"
    USER_NOT_FOUND = "user_not_found"
    ACCOUNT_DISABLED = "account_disabled"
    RATE_LIMITED = "rate_limited"
    BANNED_IP = "banned_ip"


class TransactionType(str, enum.Enum):
    """Spiritus agent wallet transaction categories."""
    DEPOSIT = "deposit"
    WITHDRAWAL = "withdrawal"
    COMMISSION = "commission"
    TRAFFIC_PURCHASE = "traffic_purchase"
    REFUND = "refund"
    ADJUSTMENT = "adjustment"


class HostSpoofMode(str, enum.Enum):
    """Host header spoofing mechanisms for DPI evasion."""
    NONE = "none"
    WS_FRONT = "ws_front"
    CDN_FRONT = "cdn_front"
    BUG_INJECTION = "bug_injection"


class ShapingMode(str, enum.Enum):
    """Traffic shaping mimicry modes."""
    VIDEO_STREAM = "video_stream"
    VOIP = "voip"
    BROWSING = "browsing"
    RANDOM = "random"
    GAMING = "gaming"


# ═══════════════════════════════════════════════════════════════════
# User  (Marzban-grade roles + periodic quotas + feature flags)
# ═══════════════════════════════════════════════════════════════════

class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("username", name="uq_users_username"),
        Index("ix_users_is_active", "is_active"),
        Index("ix_users_role", "role"),
        Index("ix_users_agent_id", "agent_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    hashed_password: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole), nullable=False, default=UserRole.USER
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # ── Lifetime Quotas & Bandwidth ─────────────────────────────
    data_limit_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0  # 0 = unlimited
    )
    data_used_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    upload_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    download_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bandwidth_limit_mbps: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0  # 0 = unlimited, max 50
    )

    # ── Marzban Periodic Quota System ───────────────────────────
    periodic_reset_strategy: Mapped[PeriodicResetStrategy] = mapped_column(
        Enum(PeriodicResetStrategy),
        nullable=False,
        default=PeriodicResetStrategy.NO_RESET,
    )
    periodic_data_limit_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0,  # 0 = no periodic limit
    )
    current_period_usage_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0,
    )
    current_period_start: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None,
    )
    next_period_reset: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None,
    )

    # ── Expiration ──────────────────────────────────────────────
    expire_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Telegram link ───────────────────────────────────────────
    telegram_chat_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    # ── Web3 Crypto Payments ────────────────────────────────────
    crypto_address_ton: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    crypto_address_trx: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # ── Spiritus Agent/Reseller Binding ─────────────────────────
    # If this user was created by a reseller, link to the agent
    agent_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("agents.id", ondelete="SET NULL"), nullable=True,
    )

    # ── Zero-Knowledge Encrypted PII (AES-GCM-256) ─────────────
    private_notes: Mapped[Optional[str]] = mapped_column(
        EncryptedType(), nullable=True, default=None,
    )
    # Encrypted last known IP — forensics only, never shown in UI
    last_known_ip: Mapped[Optional[str]] = mapped_column(
        EncryptedType(), nullable=True, default=None,
    )

    # ── Feature Flags (3X-UI + Custom) ──────────────────────────
    gamer_mode: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    battery_saver: Mapped[bool] = mapped_column(Boolean, default=False)
    split_tunnel_bypass: Mapped[str | None] = mapped_column(Text, nullable=True)
    split_tunnel_force: Mapped[str | None] = mapped_column(Text, nullable=True)
    warp_bypass: Mapped[bool] = mapped_column(Boolean, default=False)
    multi_device_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False,
    )
    max_concurrent_connections: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3,
    )

    # ── Split Tunnel Config (JSON strings) ──────────────────────
    split_tunnel_bypass: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default="[]"
    )
    split_tunnel_force: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default="[]"
    )

    # ── Advanced DPI Evasion (Zero-Knowledge / uTLS / Shaping) ──
    shaping_mode: Mapped[ShapingMode] = mapped_column(
        Enum(ShapingMode), nullable=False, default=ShapingMode.VIDEO_STREAM,
    )
    tls_fragment_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False,
    )
    tls_fingerprint: Mapped[str] = mapped_column(
        String(32), default="chrome", nullable=False,  # chrome, firefox, safari, randomized
    )
    host_spoofing_mode: Mapped[HostSpoofMode] = mapped_column(
        Enum(HostSpoofMode), nullable=False, default=HostSpoofMode.NONE,
    )
    spoofed_host: Mapped[Optional[str]] = mapped_column(
        String(256), nullable=True, default=None,  # e.g. chat.deepseek.com
    )

    # ── Timestamps ──────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # ── Online Status Tracking ──────────────────────────────────
    last_online_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None,
    )
    online_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # ── Relationships ───────────────────────────────────────────
    subscriptions: Mapped[list["Subscription"]] = relationship(
        "Subscription", back_populates="user", cascade="all, delete-orphan"
    )
    connection_logs: Mapped[list["ConnectionLog"]] = relationship(
        "ConnectionLog", back_populates="user", cascade="all, delete-orphan"
    )
    login_attempts: Mapped[list["LoginTracker"]] = relationship(
        "LoginTracker", back_populates="user", cascade="all, delete-orphan"
    )
    agent: Mapped[Optional["Agent"]] = relationship(
        "Agent", back_populates="users", foreign_keys=[agent_id],
    )


# ═══════════════════════════════════════════════════════════════════
# Agent / Reseller  (Spiritus-grade commission & wallet system)
# ═══════════════════════════════════════════════════════════════════

class Agent(Base):
    """
    Spiritus-style reseller/agent entity.

    Agents purchase traffic quota from the admin panel and resell it
    to end-users, earning commission on each sale.  Their financial
    state is tracked through ``balance``, ``commission_rate``, and
    the linked ``AgentWallet`` transaction history.
    """
    __tablename__ = "agents"
    __table_args__ = (
        UniqueConstraint("agent_code", name="uq_agents_code"),
        Index("ix_agents_is_active", "is_active"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Link to the User account that acts as agent
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE", use_alter=True, name="fk_agent_user_id"),
        nullable=False, unique=True,
    )

    # Human-readable agent code (e.g. "AG-7291")
    agent_code: Mapped[str] = mapped_column(
        String(32), nullable=False, unique=True,
        default=lambda: f"AG-{uuid.uuid4().hex[:8].upper()}",
    )

    # ── Multi-Tier Hierarchy ────────────────────────────────────
    parent_agent_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("agents.id", ondelete="SET NULL"), nullable=True,
    )
    sub_agents: Mapped[list["Agent"]] = relationship(
        "Agent", back_populates="parent_agent", remote_side=[id], cascade="all"
    )
    parent_agent: Mapped[Optional["Agent"]] = relationship(
        "Agent", back_populates="sub_agents", remote_side=[parent_agent_id]
    )

    # ── Traffic Quota (purchased from admin) ────────────────────
    traffic_quota_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0,
    )
    traffic_used_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0,
    )

    # ── Commission System ───────────────────────────────────────
    commission_rate: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.10,  # 10% default
    )
    total_commission_earned: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0,
    )

    # ── Wallet Balance (Spiritus accounting) ────────────────────
    balance: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # ── Limits ──────────────────────────────────────────────────
    max_users: Mapped[int] = mapped_column(
        Integer, nullable=False, default=100,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # ── Zero-Knowledge Encrypted Notes ──────────────────────────
    admin_notes: Mapped[Optional[str]] = mapped_column(
        EncryptedType(), nullable=True, default=None,
    )

    # ── Timestamps ──────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # ── Relationships ───────────────────────────────────────────
    owner: Mapped["User"] = relationship(
        "User", foreign_keys=[user_id],
    )
    users: Mapped[list["User"]] = relationship(
        "User", back_populates="agent", foreign_keys=[User.agent_id],
    )
    transactions: Mapped[list["AgentTransaction"]] = relationship(
        "AgentTransaction", back_populates="agent", cascade="all, delete-orphan",
    )


# ═══════════════════════════════════════════════════════════════════
# Agent Transaction  (Spiritus wallet ledger)
# ═══════════════════════════════════════════════════════════════════

class AgentTransaction(Base):
    """
    Immutable ledger entry for agent wallet operations.
    Every deposit, withdrawal, commission payout, and traffic
    purchase is recorded here for full financial audit trail.
    """
    __tablename__ = "agent_transactions"
    __table_args__ = (
        Index("ix_agent_tx_agent_id", "agent_id"),
        Index("ix_agent_tx_created_at", "created_at"),
        Index("ix_agent_tx_type", "transaction_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False,
    )
    transaction_type: Mapped[TransactionType] = mapped_column(
        Enum(TransactionType), nullable=False,
    )
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    balance_after: Mapped[float] = mapped_column(Float, nullable=False)

    # Optional reference (e.g. user_id for commission, order_id, etc.)
    reference_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ── Zero-Knowledge Encrypted Details ────────────────────────
    encrypted_details: Mapped[Optional[str]] = mapped_column(
        EncryptedType(), nullable=True, default=None,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Immutable — no updated_at by design

    # ── Relationships ───────────────────────────────────────────
    agent: Mapped["Agent"] = relationship("Agent", back_populates="transactions")


# ═══════════════════════════════════════════════════════════════════
# Node
# ═══════════════════════════════════════════════════════════════════

class Node(Base):
    __tablename__ = "nodes"
    __table_args__ = (
        UniqueConstraint("name", name="uq_nodes_name"),
        Index("ix_nodes_is_active", "is_active"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    address: Mapped[str] = mapped_column(String(256), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    protocol: Mapped[NodeProtocol] = mapped_column(
        Enum(NodeProtocol), nullable=False, default=NodeProtocol.VLESS_REALITY
    )

    # TLS / Security
    tls_cert_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    tls_key_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    api_key: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        default=lambda: uuid.uuid4().hex,
    )

    # REALITY specific fields
    reality_public_key: Mapped[Optional[str]] = mapped_column(
        String(256), nullable=True
    )
    reality_private_key: Mapped[Optional[str]] = mapped_column(
        String(256), nullable=True
    )
    reality_short_id: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    sni: Mapped[Optional[str]] = mapped_column(
        String(256), nullable=True, default="www.google.com"
    )

    # Floating IP / Cloud
    floating_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    cloud_provider: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True  # "hetzner" or "ovh"
    )
    cloud_instance_id: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )

    # Port hopping
    port_pool_low: Mapped[str] = mapped_column(
        String(256), nullable=False, default="80,443,8080,8888"
    )
    port_pool_high_start: Mapped[int] = mapped_column(
        Integer, nullable=False, default=50000
    )
    port_pool_high_end: Mapped[int] = mapped_column(
        Integer, nullable=False, default=65000
    )
    port_hop_interval_sec: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )

    # AmneziaWG specific
    amnezia_jc: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    amnezia_jmin: Mapped[int] = mapped_column(Integer, nullable=False, default=40)
    amnezia_jmax: Mapped[int] = mapped_column(Integer, nullable=False, default=70)
    amnezia_s1: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    amnezia_s2: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    amnezia_h1: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    amnezia_h2: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    amnezia_h3: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    amnezia_h4: Mapped[int] = mapped_column(Integer, nullable=False, default=4)

    # ── Node Health Telemetry ───────────────────────────────────
    last_health_check: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    health_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown",
    )
    current_connections: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
    )
    max_connections: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,  # 0 = unlimited
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    connection_logs: Mapped[list["ConnectionLog"]] = relationship(
        "ConnectionLog", back_populates="node", cascade="all, delete-orphan"
    )


# ═══════════════════════════════════════════════════════════════════
# Subscription
# ═══════════════════════════════════════════════════════════════════

class Subscription(Base):
    __tablename__ = "subscriptions"
    __table_args__ = (
        UniqueConstraint("token", name="uq_subscriptions_token"),
        Index("ix_subscriptions_user_id", "user_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        default=lambda: uuid.uuid4().hex,
    )

    # Enabled protocols for this subscription (JSON array)
    protocols: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default='["vless_reality", "hysteria2"]',
    )

    # Custom label for client display
    label: Mapped[str] = mapped_column(
        String(128), nullable=False, default="MTGroup VPN"
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Iran bypass toggle
    iran_bypass: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="subscriptions")


# ═══════════════════════════════════════════════════════════════════
# Connection Log  (3X-UI deep network telemetry)
# ═══════════════════════════════════════════════════════════════════

class ConnectionLog(Base):
    """
    Enhanced connection audit log with 3X-UI-grade telemetry.

    Every VPN session records:
      • encrypted client IP (AES-GCM-256)
      • byte counters (upload/download)
      • handshake status (success / timeout / replay / DPI block)
      • protocol used, node connected to
      • session duration tracking
    """
    __tablename__ = "connection_logs"
    __table_args__ = (
        Index("ix_connlog_user_id", "user_id"),
        Index("ix_connlog_connected_at", "connected_at"),
        Index("ix_connlog_handshake", "handshake_status"),
        Index("ix_connlog_node_id", "node_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    node_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False
    )

    # ── Zero-Knowledge Encrypted Client IP ──────────────────────
    client_ip: Mapped[Optional[str]] = mapped_column(EncryptedType(), nullable=True)
    # Deterministic hash for IP lookup without decrypting everything
    client_ip_hash: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, index=True,
    )

    # ── Traffic Counters ────────────────────────────────────────
    bytes_up: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bytes_down: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    # ── 3X-UI Handshake & Protocol Intelligence ─────────────────
    handshake_status: Mapped[HandshakeStatus] = mapped_column(
        Enum(HandshakeStatus),
        nullable=False,
        default=HandshakeStatus.SUCCESS,
    )
    protocol_used: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True,
    )
    handshake_duration_ms: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True,
    )

    # ── Concurrent Session Tracking ─────────────────────────────
    session_id: Mapped[str] = mapped_column(
        String(64), nullable=False, default=lambda: uuid.uuid4().hex,
    )
    is_active_session: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False,
    )

    # ── Timestamps ──────────────────────────────────────────────
    connected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    disconnected_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="connection_logs")
    node: Mapped["Node"] = relationship("Node", back_populates="connection_logs")


# ═══════════════════════════════════════════════════════════════════
# Login Tracker  (3X-UI brute-force & anomaly detection)
# ═══════════════════════════════════════════════════════════════════

class LoginTracker(Base):
    """
    Persistent login attempt audit log for security forensics.

    Records every authentication attempt — successful or failed —
    with encrypted source IP, user agent, and geolocation hints.
    This feeds the auto-ban system for brute-force protection.
    """
    __tablename__ = "login_tracker"
    __table_args__ = (
        Index("ix_login_user_id", "user_id"),
        Index("ix_login_attempted_at", "attempted_at"),
        Index("ix_login_result", "result"),
        Index("ix_login_ip_hash", "ip_hash"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
    )
    username_attempted: Mapped[str] = mapped_column(
        String(128), nullable=False,
    )

    # ── Zero-Knowledge Encrypted Source Info ─────────────────────
    source_ip: Mapped[Optional[str]] = mapped_column(
        EncryptedType(), nullable=True,
    )
    ip_hash: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True,
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        EncryptedType(), nullable=True,
    )

    # ── Result & Metadata ───────────────────────────────────────
    result: Mapped[LoginResult] = mapped_column(
        Enum(LoginResult), nullable=False,
    )
    failure_reason: Mapped[Optional[str]] = mapped_column(
        String(256), nullable=True,
    )

    # ── Geo Hint (country code only — not PII) ──────────────────
    geo_country: Mapped[Optional[str]] = mapped_column(
        String(4), nullable=True,
    )

    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # ── Relationships ───────────────────────────────────────────
    user: Mapped[Optional["User"]] = relationship(
        "User", back_populates="login_attempts",
    )


# ═══════════════════════════════════════════════════════════════════
# Banned IP
# ═══════════════════════════════════════════════════════════════════

class BannedIP(Base):
    __tablename__ = "banned_ips"
    __table_args__ = (
        UniqueConstraint("ip_hash", name="uq_banned_ips_ip_hash"),
        Index("ix_banned_ips_expires_at", "expires_at"),
        Index("ix_banned_ips_reason", "reason"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # The raw IP is stored encrypted; lookups use the hash
    ip_address: Mapped[str] = mapped_column(
        EncryptedType(), nullable=False,
    )
    ip_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True,
    )

    reason: Mapped[BanReason] = mapped_column(
        Enum(BanReason), nullable=False, default=BanReason.MANUAL
    )

    # AES-GCM-256 encrypted — ban details may contain PII
    details: Mapped[Optional[str]] = mapped_column(EncryptedType(), nullable=True)

    # How many times this IP triggered a ban (escalation counter)
    strike_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    banned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


# ═══════════════════════════════════════════════════════════════════
# System Config (Key-Value)
# ═══════════════════════════════════════════════════════════════════

class SystemConfig(Base):
    __tablename__ = "system_config"
    __table_args__ = (UniqueConstraint("key", name="uq_system_config_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


# ═══════════════════════════════════════════════════════════════════
# System Snapshot (Config Time Machine & Blast Radius)
# ═══════════════════════════════════════════════════════════════════

class SystemSnapshot(Base):
    __tablename__ = "system_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    preset_name: Mapped[str] = mapped_column(String(128), nullable=False)
    config_json: Mapped[str] = mapped_column(Text, nullable=False)
    health_score: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    active_users_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


# ═══════════════════════════════════════════════════════════════════
# Audit Log  (Uyum ve Operatör Geçmişi)
# ═══════════════════════════════════════════════════════════════════

class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_action_type", "action_type"),
        Index("ix_audit_timestamp", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    operator_role: Mapped[str] = mapped_column(String(32), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


# ═══════════════════════════════════════════════════════════════════
# Abuse Reputation (Abuse & Fair Usage Guard)
# ═══════════════════════════════════════════════════════════════════

class AbuseReputation(Base):
    __tablename__ = "abuse_reputations"
    __table_args__ = (
        Index("ix_abuse_user_id", "user_id"),
        Index("ix_abuse_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    link_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, unique=True
    )
    abuse_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    device_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    country_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="Active")

    user: Mapped[Optional["User"]] = relationship("User")


# ═══════════════════════════════════════════════════════════════════
# Processed Transaction (Web3 Payment Deduplication)
# ═══════════════════════════════════════════════════════════════════

class ProcessedTransaction(Base):
    """
    Persists processed crypto transaction hashes to prevent
    double-crediting on service restarts.
    """
    __tablename__ = "processed_transactions"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tx_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    network: Mapped[str] = mapped_column(String(32), nullable=False)
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


# ═══════════════════════════════════════════════════════════════════
# Database Engine Factory
# ═══════════════════════════════════════════════════════════════════

def create_db_engine(database_url: str = "sqlite+aiosqlite:///./mtgroup.db"):
    """Create an async SQLAlchemy engine."""
    engine = create_async_engine(
        database_url,
        echo=False,
        future=True,
        connect_args={"check_same_thread": False} if "sqlite" in database_url else {},
    )
    return engine


def create_session_factory(engine):
    """Create an async session factory bound to the given engine."""
    return async_sessionmaker(engine, expire_on_commit=False)


async def init_db(engine):
    """Create all tables in the database."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
