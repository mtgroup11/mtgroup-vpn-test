"""
MTGroup VPN Ultimate — AI Traffic Shaper
Injects randomized micro-delays and synthetic dummy packets to
manipulate bandwidth graphs, mimicking authentic video streaming
or VoIP cadence to confuse ML-based censorship classifiers.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from backend.app.models import ShapingMode


@dataclass
class TrafficProfile:
    """Defines the statistical profile of a traffic pattern to mimic."""
    name: str
    # Packet size distribution (bytes)
    min_packet_size: int
    max_packet_size: int
    mean_packet_size: float
    stddev_packet_size: float
    # Inter-packet delay distribution (milliseconds)
    min_delay_ms: float
    max_delay_ms: float
    mean_delay_ms: float
    stddev_delay_ms: float
    # Burst characteristics
    burst_probability: float  # 0-1, chance of a burst per interval
    burst_min_packets: int
    burst_max_packets: int
    burst_inter_delay_ms: float
    # Bandwidth noise
    bandwidth_noise_percent: float  # Random variation in throughput


# Pre-defined traffic profiles based on real-world traffic analysis
TRAFFIC_PROFILES: dict[ShapingMode, TrafficProfile] = {
    ShapingMode.VIDEO_STREAM: TrafficProfile(
        name="YouTube/Netflix 1080p Stream",
        min_packet_size=200,
        max_packet_size=1400,
        mean_packet_size=1100,
        stddev_packet_size=300,
        min_delay_ms=2,
        max_delay_ms=30,
        mean_delay_ms=8,
        stddev_delay_ms=5,
        burst_probability=0.3,
        burst_min_packets=5,
        burst_max_packets=20,
        burst_inter_delay_ms=0.5,
        bandwidth_noise_percent=15,
    ),
    ShapingMode.VOIP: TrafficProfile(
        name="WhatsApp/Signal VoIP Call",
        min_packet_size=60,
        max_packet_size=250,
        mean_packet_size=160,
        stddev_packet_size=40,
        min_delay_ms=18,
        max_delay_ms=22,
        mean_delay_ms=20,
        stddev_delay_ms=2,
        burst_probability=0.05,
        burst_min_packets=2,
        burst_max_packets=4,
        burst_inter_delay_ms=1,
        bandwidth_noise_percent=5,
    ),
    ShapingMode.BROWSING: TrafficProfile(
        name="Casual Web Browsing",
        min_packet_size=40,
        max_packet_size=1400,
        mean_packet_size=600,
        stddev_packet_size=400,
        min_delay_ms=5,
        max_delay_ms=2000,
        mean_delay_ms=200,
        stddev_delay_ms=300,
        burst_probability=0.6,
        burst_min_packets=10,
        burst_max_packets=50,
        burst_inter_delay_ms=0.2,
        bandwidth_noise_percent=40,
    ),
    ShapingMode.RANDOM: TrafficProfile(
        name="Randomized Noise",
        min_packet_size=64,
        max_packet_size=1400,
        mean_packet_size=700,
        stddev_packet_size=350,
        min_delay_ms=1,
        max_delay_ms=100,
        mean_delay_ms=25,
        stddev_delay_ms=20,
        burst_probability=0.2,
        burst_min_packets=3,
        burst_max_packets=15,
        burst_inter_delay_ms=1,
        bandwidth_noise_percent=25,
    ),
    ShapingMode.GAMING: TrafficProfile(
        name="Online Gaming (FPS/MOBA)",
        min_packet_size=40,
        max_packet_size=200,
        mean_packet_size=80,
        stddev_packet_size=30,
        min_delay_ms=14,
        max_delay_ms=18,
        mean_delay_ms=16,
        stddev_delay_ms=1.5,
        burst_probability=0.1,
        burst_min_packets=2,
        burst_max_packets=5,
        burst_inter_delay_ms=0.5,
        bandwidth_noise_percent=3,
    ),
}


class TrafficShaper:
    """
    AI-driven traffic shaper that generates synthetic traffic parameters
    to inject into server-side proxy configurations.

    This shaper works by:
    1. Selecting a traffic profile that mimics real application traffic
    2. Generating randomized chaff (dummy) packet schedules
    3. Computing jitter injection parameters
    4. Outputting server-side configuration for Xray/Sing-box
    """

    def __init__(self, mode: ShapingMode = ShapingMode.VIDEO_STREAM):
        self.mode = mode
        self.profile = TRAFFIC_PROFILES[mode]
        self._rng = random.Random()

    def set_mode(self, mode: ShapingMode) -> None:
        """Switch to a different traffic shaping mode."""
        self.mode = mode
        self.profile = TRAFFIC_PROFILES[mode]

    def generate_chaff_schedule(
        self,
        duration_sec: float = 60.0,
    ) -> list[dict]:
        """
        Generate a schedule of chaff (dummy) packets to inject.

        Returns a list of dicts with 'delay_ms', 'size_bytes', and 'is_burst'.
        """
        schedule: list[dict] = []
        elapsed = 0.0

        while elapsed < duration_sec * 1000:
            # Determine if this is a burst
            if self._rng.random() < self.profile.burst_probability:
                burst_count = self._rng.randint(
                    self.profile.burst_min_packets,
                    self.profile.burst_max_packets,
                )
                for _ in range(burst_count):
                    size = self._sample_packet_size()
                    schedule.append({
                        "delay_ms": self.profile.burst_inter_delay_ms,
                        "size_bytes": size,
                        "is_burst": True,
                    })
                    elapsed += self.profile.burst_inter_delay_ms
            else:
                delay = self._sample_delay()
                size = self._sample_packet_size()
                schedule.append({
                    "delay_ms": delay,
                    "size_bytes": size,
                    "is_burst": False,
                })
                elapsed += delay

        return schedule

    def _sample_packet_size(self) -> int:
        """Sample a packet size from the profile's distribution."""
        size = int(self._rng.gauss(
            self.profile.mean_packet_size,
            self.profile.stddev_packet_size,
        ))
        return max(
            self.profile.min_packet_size,
            min(self.profile.max_packet_size, size),
        )

    def _sample_delay(self) -> float:
        """Sample an inter-packet delay from the profile's distribution."""
        delay = self._rng.gauss(
            self.profile.mean_delay_ms,
            self.profile.stddev_delay_ms,
        )
        return max(
            self.profile.min_delay_ms,
            min(self.profile.max_delay_ms, delay),
        )

    def get_jitter_params(self) -> dict:
        """
        Get jitter injection parameters for server-side configuration.
        These parameters tell the proxy to add randomized delays.
        """
        return {
            "jitter_enabled": True,
            "jitter_min_ms": int(self.profile.min_delay_ms),
            "jitter_max_ms": int(self.profile.max_delay_ms),
            "jitter_distribution": "gaussian",
            "jitter_mean_ms": int(self.profile.mean_delay_ms),
            "jitter_stddev_ms": int(self.profile.stddev_delay_ms),
        }

    def get_padding_params(self) -> dict:
        """
        Get padding/chaff parameters for proxy configuration.
        """
        return {
            "padding_enabled": True,
            "padding_min_bytes": self.profile.min_packet_size,
            "padding_max_bytes": self.profile.max_packet_size,
            "chaff_enabled": True,
            "chaff_interval_ms": int(self.profile.mean_delay_ms * 2),
            "chaff_size_min": max(64, self.profile.min_packet_size),
            "chaff_size_max": min(512, self.profile.max_packet_size),
        }

    def get_bandwidth_noise_percent(self) -> float:
        """Get bandwidth noise percentage for throughput variation."""
        return self.profile.bandwidth_noise_percent

    def generate_xray_noise_config(self) -> dict:
        """
        Generate Xray-compatible noise/padding configuration.
        This injects into the transport layer settings.
        """
        return {
            "header": {
                "type": "http",
                "request": {
                    "version": "1.1",
                    "method": "GET",
                    "path": ["/", "/video", "/stream", "/api/v1"],
                    "headers": {
                        "Host": ["www.google.com", "www.youtube.com"],
                        "User-Agent": [
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
                            "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36",
                        ],
                        "Accept-Encoding": ["gzip, deflate, br"],
                        "Connection": ["keep-alive"],
                        "Pragma": "no-cache",
                    },
                },
            },
        }

    def generate_singbox_multiplex_config(self) -> dict:
        """
        Generate Sing-box multiplex configuration for traffic shaping.
        Uses multiplex to fragment and mix traffic patterns.
        """
        return {
            "enabled": True,
            "protocol": "h2mux",
            "max_connections": 4,
            "min_streams": 4,
            "max_streams": 0,
            "padding": True,
            "brutal": {
                "enabled": True,
                "up_mbps": 50,
                "down_mbps": 100,
            },
        }

    def get_profile_summary(self) -> dict:
        """Get a human-readable summary of the current traffic profile."""
        p = self.profile
        return {
            "mode": self.mode.value,
            "name": p.name,
            "packet_size_range": f"{p.min_packet_size}-{p.max_packet_size} bytes",
            "mean_packet_size": f"{p.mean_packet_size:.0f} bytes",
            "delay_range": f"{p.min_delay_ms:.1f}-{p.max_delay_ms:.1f} ms",
            "mean_delay": f"{p.mean_delay_ms:.1f} ms",
            "burst_probability": f"{p.burst_probability * 100:.0f}%",
            "bandwidth_noise": f"±{p.bandwidth_noise_percent:.0f}%",
        }

    @staticmethod
    def get_available_modes() -> list[dict]:
        """List all available traffic shaping modes with descriptions."""
        return [
            {
                "mode": mode.value,
                "name": profile.name,
                "description": f"Mimics {profile.name} traffic patterns",
            }
            for mode, profile in TRAFFIC_PROFILES.items()
        ]
