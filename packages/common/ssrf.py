"""SSRF protection utilities validating outbound URLs against metadata and private IP ranges."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

_BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",  # noqa: S104  # nosec B104 - blocklist entry, not a bind address
        "::1",
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.azure.com",
    }
)


def validate_outbound_https_url(url: str) -> str:
    """Ensure an outbound endpoint uses HTTPS and does not target private/link-local hosts."""
    parsed = urlparse(url.strip())
    if parsed.scheme != "https":
        raise ValueError("Outbound URL must use https:// scheme.")
    hostname = (parsed.hostname or "").lower().strip()
    if not hostname or hostname in _BLOCKED_HOSTS:
        raise ValueError("Outbound URL targets a prohibited host.")
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
        ):
            raise ValueError("Outbound URL targets a non-public IP range.")
    except ValueError as exc:
        if "non-public IP range" in str(exc):
            raise
        # Domain name (not raw IP literal) — verify no obvious local suffix
        if hostname.endswith((".local", ".internal", ".localhost")):
            raise ValueError("Outbound URL targets an internal domain suffix.") from None
    return url.strip()
