"""
MTGroup VPN Ultimate — helpers shared by the share-link / config generators.
"""

from __future__ import annotations

import ipaddress

# uTLS fingerprints both Xray and sing-box accept. "random" picks one per
# process start, "randomized" builds a fully randomized ClientHello — both
# are resolved by the *client* core, so the panel passes them through as-is
# instead of picking one itself (which also made every refetch of the same
# subscription return a different link).
UTLS_FINGERPRINTS = frozenset({
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
    "random", "randomized",
})


def normalize_fingerprint(fp: str | None) -> str:
    """Return a uTLS fingerprint every supported core understands."""
    fp = (fp or "").strip().lower()
    return fp if fp in UTLS_FINGERPRINTS else "chrome"


def uri_host(address: str) -> str:
    """Host part for a `scheme://user@host:port` share link.

    IPv6 literals must be bracketed (RFC 3986): `vless://id@2001:db8::1:443`
    is unparseable — every client splits it at the wrong colon.
    """
    try:
        if ipaddress.ip_address(address.strip("[]")).version == 6:
            return f"[{address.strip('[]')}]"
    except ValueError:
        pass  # hostname
    return address
