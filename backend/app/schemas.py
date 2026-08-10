"""
MTGroup VPN Ultimate — Pydantic Schemas
Request/Response models for the FastAPI backend.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class TokenRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=128)
    password: str = Field(..., min_length=6, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 3600


class RefreshRequest(BaseModel):
    refresh_token: str


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"
    RESELLER = "reseller"


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=128)
    password: str = Field(..., min_length=6, max_length=256)
    role: UserRole = UserRole.USER
    data_limit_bytes: int = Field(default=0, ge=0)
    bandwidth_limit_mbps: int = Field(default=0, ge=0, le=50)
    expire_days: Optional[int] = Field(default=None, ge=1)
    telegram_chat_id: Optional[int] = None
    gamer_mode: bool = False
    battery_saver: bool = False
    protocols: list[str] = Field(
        default=["vless_reality", "hysteria2"],
        description="Protocols to enable in subscription",
    )
    iran_bypass: bool = True
    warp_bypass: bool = False
    split_tunnel_bypass: list[str] = Field(
        default_factory=list,
        description="Domains/IPs to bypass tunnel (e.g., local banking)",
    )
    split_tunnel_force: list[str] = Field(
        default_factory=list,
        description="Domains/IPs to force through tunnel",
    )


class UserUpdate(BaseModel):
    password: Optional[str] = Field(default=None, min_length=6, max_length=256)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    data_limit_bytes: Optional[int] = Field(default=None, ge=0)
    bandwidth_limit_mbps: Optional[int] = Field(default=None, ge=0, le=50)
    expire_days: Optional[int] = Field(default=None, ge=1)
    telegram_chat_id: Optional[int] = None
    gamer_mode: Optional[bool] = None
    battery_saver: Optional[bool] = None
    warp_bypass: Optional[bool] = None
    protocols: Optional[list[str]] = None
    iran_bypass: Optional[bool] = None
    split_tunnel_bypass: Optional[list[str]] = None
    split_tunnel_force: Optional[list[str]] = None


class UserResponse(BaseModel):
    id: int
    username: str
    role: UserRole
    is_active: bool
    data_limit_bytes: int
    data_used_bytes: int
    upload_bytes: int
    download_bytes: int
    bandwidth_limit_mbps: int
    expire_date: Optional[datetime]
    telegram_chat_id: Optional[int]
    gamer_mode: bool
    battery_saver: bool
    warp_bypass: bool
    split_tunnel_bypass: list[str]
    split_tunnel_force: list[str]
    subscription_token: Optional[str] = None
    subscription_url: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    @field_validator("split_tunnel_bypass", "split_tunnel_force", mode="before")
    @classmethod
    def parse_json_list(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, list) else []
            except (json.JSONDecodeError, TypeError):
                return []
        if isinstance(v, list):
            return v
        return []

    model_config = {"from_attributes": True}


class UserListResponse(BaseModel):
    total: int
    page: int
    per_page: int
    users: list[UserResponse]


class UserTrafficReset(BaseModel):
    user_id: int


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

class NodeProtocol(str, Enum):
    VLESS_REALITY = "vless_reality"
    HYSTERIA2 = "hysteria2"
    TUIC_V5 = "tuic_v5"
    AMNEZIA_WG = "amnezia_wg"
    SHADOWSOCKS = "shadowsocks"
    DNSTT = "dnstt"
    ICMP_TUNNEL = "icmp_tunnel"


class NodeCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    address: str = Field(..., min_length=1, max_length=256)
    port: int = Field(default=443, ge=1, le=65535)
    protocol: NodeProtocol = NodeProtocol.VLESS_REALITY
    sni: str = Field(default="www.google.com", max_length=256)
    reality_public_key: Optional[str] = None
    reality_private_key: Optional[str] = None
    reality_short_id: Optional[str] = None
    tls_cert_path: Optional[str] = None
    tls_key_path: Optional[str] = None
    cloud_provider: Optional[str] = None
    cloud_instance_id: Optional[str] = None
    port_pool_low: str = "80,443,8080,8888"
    port_pool_high_start: int = Field(default=50000, ge=1024, le=65535)
    port_pool_high_end: int = Field(default=65000, ge=1024, le=65535)
    port_hop_interval_sec: int = Field(default=1, ge=1, le=60)

    # AmneziaWG parameters
    amnezia_jc: int = Field(default=4, ge=0, le=128)
    amnezia_jmin: int = Field(default=40, ge=0, le=1280)
    amnezia_jmax: int = Field(default=70, ge=0, le=1280)
    amnezia_s1: int = Field(default=0, ge=0, le=1280)
    amnezia_s2: int = Field(default=0, ge=0, le=1280)
    amnezia_h1: int = Field(default=1, ge=0, le=4294967295)
    amnezia_h2: int = Field(default=2, ge=0, le=4294967295)
    amnezia_h3: int = Field(default=3, ge=0, le=4294967295)
    amnezia_h4: int = Field(default=4, ge=0, le=4294967295)

    @model_validator(mode="after")
    def validate_port_range(self) -> "NodeCreate":
        if self.port_pool_high_end <= self.port_pool_high_start:
            raise ValueError("port_pool_high_end must be > port_pool_high_start")
        return self


class NodeUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=128)
    address: Optional[str] = Field(default=None, max_length=256)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    is_active: Optional[bool] = None
    protocol: Optional[NodeProtocol] = None
    sni: Optional[str] = None
    reality_public_key: Optional[str] = None
    reality_private_key: Optional[str] = None
    reality_short_id: Optional[str] = None
    floating_ip: Optional[str] = None
    cloud_provider: Optional[str] = None
    cloud_instance_id: Optional[str] = None
    port_pool_low: Optional[str] = None
    port_pool_high_start: Optional[int] = None
    port_pool_high_end: Optional[int] = None
    port_hop_interval_sec: Optional[int] = None
    amnezia_jc: Optional[int] = None
    amnezia_jmin: Optional[int] = None
    amnezia_jmax: Optional[int] = None
    amnezia_s1: Optional[int] = None
    amnezia_s2: Optional[int] = None
    amnezia_h1: Optional[int] = None
    amnezia_h2: Optional[int] = None
    amnezia_h3: Optional[int] = None
    amnezia_h4: Optional[int] = None


class NodeResponse(BaseModel):
    id: int
    name: str
    address: str
    port: int
    is_active: bool
    protocol: NodeProtocol
    sni: Optional[str]
    reality_public_key: Optional[str]
    reality_short_id: Optional[str]
    floating_ip: Optional[str]
    cloud_provider: Optional[str]
    port_pool_low: str
    port_pool_high_start: int
    port_pool_high_end: int
    port_hop_interval_sec: int
    amnezia_jc: int
    amnezia_jmin: int
    amnezia_jmax: int
    amnezia_s1: int
    amnezia_s2: int
    amnezia_h1: int
    amnezia_h2: int
    amnezia_h3: int
    amnezia_h4: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class NodeListResponse(BaseModel):
    total: int
    nodes: list[NodeResponse]


# ---------------------------------------------------------------------------
# Subscription & Config Outputs
# ---------------------------------------------------------------------------

class SubscriptionOutput(BaseModel):
    """Response containing all generated subscription formats."""
    token: str
    base64_links: str  # Base64-encoded multi-line V2Ray links
    singbox_json: dict[str, Any]  # Sing-box JSON config
    clash_yaml: str  # Clash Meta YAML
    amnezia_conf: Optional[str] = None  # AmneziaWG .conf (if applicable)
    v2ray_links: list[str]  # Raw protocol URIs
    subscription_url: str
    qr_code_url: str


class AmneziaWGConfig(BaseModel):
    """AmneziaWG configuration parameters mapped from web UI sliders."""
    jc: int = Field(default=4, ge=0, le=128, description="Junk packet count")
    jmin: int = Field(default=40, ge=0, le=1280, description="Min junk size")
    jmax: int = Field(default=70, ge=0, le=1280, description="Max junk size")
    s1: int = Field(default=0, ge=0, le=1280, description="Init packet junk size")
    s2: int = Field(default=0, ge=0, le=1280, description="Response packet junk size")
    h1: int = Field(default=1, ge=0, le=4294967295, description="Init header value")
    h2: int = Field(default=2, ge=0, le=4294967295, description="Response header value")
    h3: int = Field(default=3, ge=0, le=4294967295, description="Cookie header value")
    h4: int = Field(default=4, ge=0, le=4294967295, description="Transport header value")

    # WireGuard core
    private_key: Optional[str] = None
    public_key: Optional[str] = None
    endpoint: Optional[str] = None
    address: str = "10.0.0.2/32"
    dns: str = "1.1.1.1, 1.0.0.1"
    mtu: int = Field(default=1280, ge=1000, le=1500)
    allowed_ips: str = "0.0.0.0/0, ::/0"
    persistent_keepalive: int = Field(default=25, ge=0, le=300)

    @model_validator(mode="after")
    def validate_junk_range(self) -> "AmneziaWGConfig":
        if self.jmax < self.jmin:
            raise ValueError("jmax must be >= jmin")
        return self


class GamerModeProfile(BaseModel):
    """Optimized routing rules for low-latency gaming."""
    enabled: bool = True
    game_endpoints: list[str] = Field(
        default=[
            # Riot Games
            "104.160.128.0/17",
            # Valve / Steam
            "208.64.200.0/22",
            "205.196.6.0/24",
            # Activision / Blizzard
            "24.105.0.0/18",
            "137.221.0.0/16",
            # Epic Games
            "52.38.0.0/15",
        ],
        description="CIDR blocks for game server direct routing",
    )
    direct_domains: list[str] = Field(
        default=[
            "riotgames.com",
            "leagueoflegends.com",
            "steampowered.com",
            "valvesoftware.com",
            "blizzard.com",
            "epicgames.com",
            "ea.com",
        ]
    )
    optimize_udp: bool = True
    zero_packet_loss: bool = True


class SplitTunnelProfile(BaseModel):
    """Custom app-level split tunneling configuration."""
    bypass_domains: list[str] = Field(
        default_factory=list,
        description="Domains routed directly (outside tunnel)",
    )
    bypass_ips: list[str] = Field(
        default_factory=list,
        description="IP CIDRs routed directly",
    )
    force_domains: list[str] = Field(
        default_factory=list,
        description="Domains forced through tunnel",
    )
    force_ips: list[str] = Field(
        default_factory=list,
        description="IP CIDRs forced through tunnel",
    )


class IranBypassProfile(BaseModel):
    """Iran-specific bypass rules for domestic traffic."""
    enabled: bool = True
    bypass_domains: list[str] = Field(
        default=[
            "geosite:category-ir",
            "geosite:category-bank-ir",
            "domain:.ir",
        ]
    )
    bypass_ips: list[str] = Field(
        default=[
            "geoip:ir",
            "geoip:private",
        ]
    )
    bypass_process: list[str] = Field(
        default=[],
        description="Process names to bypass (e.g., banking apps)",
    )


class BatterySaverProfile(BaseModel):
    """Eco-stealth battery optimization settings."""
    enabled: bool = True
    idle_timeout_sec: int = Field(
        default=300, ge=60, le=3600,
        description="Seconds of inactivity before entering low-power mode",
    )
    connection_check_interval_sec: int = Field(
        default=600, ge=60, le=3600,
        description="Interval between keep-alive pings in idle mode",
    )
    sniff_enabled: bool = False
    dns_strategy: str = "ipv4_only"


# ---------------------------------------------------------------------------
# Traffic Shaping
# ---------------------------------------------------------------------------

class TrafficShapingProfile(BaseModel):
    """AI-driven traffic shaping configuration."""
    mode: str = Field(
        default="video_stream",
        description="Mimicry mode: video_stream, voip, browsing, random",
    )
    jitter_min_ms: int = Field(default=5, ge=0, le=200)
    jitter_max_ms: int = Field(default=50, ge=0, le=500)
    chaff_interval_sec: float = Field(default=0.5, ge=0.1, le=10.0)
    chaff_size_min: int = Field(default=64, ge=16, le=1400)
    chaff_size_max: int = Field(default=512, ge=16, le=1400)
    bandwidth_noise_percent: float = Field(
        default=15.0, ge=0, le=50,
        description="Random bandwidth variation percentage",
    )


# ---------------------------------------------------------------------------
# Port Hopping
# ---------------------------------------------------------------------------

class PortHopConfig(BaseModel):
    """Multi-port hopping configuration."""
    low_ports: list[int] = Field(default=[80, 443, 8080, 8888])
    high_port_start: int = Field(default=50000, ge=1024, le=65535)
    high_port_end: int = Field(default=65000, ge=1024, le=65535)
    hop_interval_sec: int = Field(default=1, ge=1, le=60)
    fragment_across_pools: bool = True


# ---------------------------------------------------------------------------
# System & Stats
# ---------------------------------------------------------------------------

class SystemStatsResponse(BaseModel):
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_total_mb: float
    disk_percent: float
    bandwidth_up_mbps: float
    bandwidth_down_mbps: float
    total_users: int
    active_users: int
    total_nodes: int
    active_nodes: int
    uptime_seconds: float


class SystemConfigUpdate(BaseModel):
    key: str = Field(..., max_length=128)
    value: Any
    description: Optional[str] = None


class SystemConfigResponse(BaseModel):
    key: str
    value: Any
    description: Optional[str]
    updated_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Banned IP
# ---------------------------------------------------------------------------

class BanReason(str, Enum):
    """Mirrors backend.app.models.BanReason. Kept as a separate schema-layer
    enum (same convention as UserRole/NodeProtocol above) rather than
    importing the ORM enum directly.

    Typing `BannedIPCreate.reason` as a plain `str` let any arbitrary
    value reach the DB unvalidated — SQLAlchemy's Enum column then
    raised an unhandled LookupError (500) for anything that wasn't an
    exact match, instead of FastAPI/Pydantic rejecting it with a clean
    422 at the request boundary."""
    FAILED_LOGIN = "failed_login"
    ANOMALOUS_HANDSHAKE = "anomalous_handshake"
    ACTIVE_PROBE = "active_probe"
    MANUAL = "manual"
    RATE_LIMIT = "rate_limit"
    CONCURRENT_ABUSE = "concurrent_abuse"
    TRAFFIC_ANOMALY = "traffic_anomaly"


class BannedIPCreate(BaseModel):
    ip_address: str
    reason: BanReason = BanReason.MANUAL
    details: Optional[str] = None
    duration_hours: int = Field(default=24, ge=1, le=8760)


class BannedIPResponse(BaseModel):
    id: int
    ip_address: str
    reason: str
    details: Optional[str]
    banned_at: datetime
    expires_at: Optional[datetime]

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Generic
# ---------------------------------------------------------------------------

class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None


class PaginationParams(BaseModel):
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=20, ge=1, le=100)
