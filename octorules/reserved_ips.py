"""Reserved and bogon IP ranges (RFC 1918, loopback, link-local, ...).

Single source of truth for every provider's reserved-IP lint check. The
list was duplicated across cloudflare, aws, google, azure, and bunny
providers under four different names (`_RESERVED_NETWORKS`,
`_PRIVATE_SUPERNETS`, `_PRIVATE_NETWORKS`, `_PRIVATE_RANGES`) with
byte-identical content — consolidated here in v0.26.0.

Public API::

    from octorules.reserved_ips import is_reserved, RESERVED_NETWORKS

    desc = is_reserved("10.1.2.3")      # -> "RFC 1918 private"
    desc = is_reserved("8.8.8.8")       # -> None
    desc = is_reserved("10.0.0.0/24")   # -> "RFC 1918 private"
"""

from __future__ import annotations

import ipaddress

RESERVED_NETWORKS: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = [
    # IPv4
    (ipaddress.ip_network("10.0.0.0/8"), "RFC 1918 private"),
    (ipaddress.ip_network("172.16.0.0/12"), "RFC 1918 private"),
    (ipaddress.ip_network("192.168.0.0/16"), "RFC 1918 private"),
    (ipaddress.ip_network("127.0.0.0/8"), "loopback"),
    (ipaddress.ip_network("169.254.0.0/16"), "link-local"),
    (ipaddress.ip_network("100.64.0.0/10"), "CGNAT (RFC 6598)"),
    (ipaddress.ip_network("0.0.0.0/8"), "this network"),
    (ipaddress.ip_network("192.0.2.0/24"), "documentation (RFC 5737)"),
    (ipaddress.ip_network("198.51.100.0/24"), "documentation (RFC 5737)"),
    (ipaddress.ip_network("203.0.113.0/24"), "documentation (RFC 5737)"),
    (ipaddress.ip_network("192.0.0.0/24"), "IANA special purpose"),
    (ipaddress.ip_network("192.88.99.0/24"), "6to4 relay anycast"),
    (ipaddress.ip_network("198.18.0.0/15"), "benchmark testing (RFC 2544)"),
    (ipaddress.ip_network("224.0.0.0/4"), "multicast"),
    (ipaddress.ip_network("240.0.0.0/4"), "reserved for future use"),
    # IPv6
    (ipaddress.ip_network("::/128"), "unspecified"),
    (ipaddress.ip_network("::1/128"), "loopback"),
    (ipaddress.ip_network("::ffff:0:0/96"), "IPv4-mapped"),
    (ipaddress.ip_network("64:ff9b::/96"), "NAT64 (RFC 6052)"),
    (ipaddress.ip_network("100::/64"), "discard (RFC 6666)"),
    (ipaddress.ip_network("2001:db8::/32"), "documentation (RFC 3849)"),
    (ipaddress.ip_network("2001::/23"), "IANA special purpose"),
    (ipaddress.ip_network("2001::/32"), "Teredo"),
    (ipaddress.ip_network("2002::/16"), "6to4"),
    (ipaddress.ip_network("fc00::/7"), "unique local"),
    (ipaddress.ip_network("fe80::/10"), "link-local"),
    (ipaddress.ip_network("ff00::/8"), "multicast"),
    (ipaddress.ip_network("::ffff:0:0:0/96"), "IPv4-translated"),
]

# Partitioned by version to avoid a per-candidate version comparison.
_RESERVED_V4: list[tuple[ipaddress.IPv4Network, str]] = [
    (n, d)  # type: ignore[misc]
    for n, d in RESERVED_NETWORKS
    if n.version == 4
]
_RESERVED_V6: list[tuple[ipaddress.IPv6Network, str]] = [
    (n, d)  # type: ignore[misc]
    for n, d in RESERVED_NETWORKS
    if n.version == 6
]


def is_reserved(ip_str: str) -> str | None:
    """Return a description if *ip_str* falls within a reserved or bogon
    range, else None.

    Accepts both plain addresses (``"10.1.2.3"``) and CIDR notation
    (``"10.0.0.0/24"``).  Returns ``None`` on parse failure rather than
    raising — lint callers treat unparseable input as a separate concern
    (e.g. CF540 / GA301 / AZ318 / BN302).
    """
    try:
        net = ipaddress.ip_network(ip_str, strict=False)
    except (ValueError, TypeError):
        return None
    candidates = _RESERVED_V4 if net.version == 4 else _RESERVED_V6
    for reserved, desc in candidates:
        if net.subnet_of(reserved):  # type: ignore[arg-type]
            return desc
    return None
