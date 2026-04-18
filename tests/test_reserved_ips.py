"""Tests for octorules.reserved_ips."""

from __future__ import annotations

import ipaddress

import pytest

from octorules.reserved_ips import (
    _RESERVED_V4,
    _RESERVED_V6,
    RESERVED_NETWORKS,
    is_reserved,
)


class TestReservedNetworksTable:
    def test_shape(self):
        assert len(RESERVED_NETWORKS) == 28
        assert len(_RESERVED_V4) == 15
        assert len(_RESERVED_V6) == 13

    def test_v4_is_all_ipv4(self):
        for net, _ in _RESERVED_V4:
            assert isinstance(net, ipaddress.IPv4Network)

    def test_v6_is_all_ipv6(self):
        for net, _ in _RESERVED_V6:
            assert isinstance(net, ipaddress.IPv6Network)

    def test_no_duplicate_networks(self):
        seen = set()
        for net, _ in RESERVED_NETWORKS:
            key = (net.version, str(net))
            assert key not in seen, f"duplicate: {net}"
            seen.add(key)


class TestIsReservedPositive:
    @pytest.mark.parametrize(
        "ip,expected",
        [
            ("10.0.0.0", "RFC 1918 private"),
            ("10.1.2.3", "RFC 1918 private"),
            ("172.16.0.1", "RFC 1918 private"),
            ("172.31.255.255", "RFC 1918 private"),
            ("192.168.0.1", "RFC 1918 private"),
            ("127.0.0.1", "loopback"),
            ("169.254.1.1", "link-local"),
            ("100.64.0.1", "CGNAT (RFC 6598)"),
            ("0.0.0.0", "this network"),
            ("192.0.2.1", "documentation (RFC 5737)"),
            ("198.51.100.1", "documentation (RFC 5737)"),
            ("203.0.113.1", "documentation (RFC 5737)"),
            ("224.0.0.1", "multicast"),
            ("240.0.0.1", "reserved for future use"),
        ],
    )
    def test_v4_hits(self, ip, expected):
        assert is_reserved(ip) == expected

    @pytest.mark.parametrize(
        "ip,expected",
        [
            ("::", "unspecified"),
            ("::1", "loopback"),
            ("::ffff:0.0.0.0", "IPv4-mapped"),
            ("64:ff9b::1.2.3.4", "NAT64 (RFC 6052)"),
            ("2001:db8::1", "documentation (RFC 3849)"),
            ("fc00::1", "unique local"),
            ("fe80::1", "link-local"),
            ("ff02::1", "multicast"),
        ],
    )
    def test_v6_hits(self, ip, expected):
        assert is_reserved(ip) == expected


class TestIsReservedNegative:
    @pytest.mark.parametrize(
        "ip",
        [
            "8.8.8.8",  # public DNS
            "1.1.1.1",  # public DNS
            "142.250.0.1",  # Google public
            "2606:4700::1",  # Cloudflare public
            "2a00:1450::1",  # Google public IPv6
        ],
    )
    def test_public_ips_not_reserved(self, ip):
        assert is_reserved(ip) is None


class TestIsReservedCIDR:
    def test_cidr_entirely_inside_reserved_hits(self):
        assert is_reserved("10.0.0.0/24") == "RFC 1918 private"

    def test_cidr_outside_reserved_misses(self):
        assert is_reserved("8.8.8.0/24") is None

    def test_cidr_exactly_matching_reserved_hits(self):
        assert is_reserved("10.0.0.0/8") == "RFC 1918 private"

    def test_cidr_straddling_boundary_misses(self):
        # 9.255.0.0/15 overlaps 10.0.0.0/8 but is not fully inside it,
        # so subnet_of() returns False — correct for a lint check that
        # only flags addresses guaranteed to be reserved.
        assert is_reserved("9.255.0.0/15") is None

    def test_host_cidr_v6(self):
        assert is_reserved("fc00::/7") == "unique local"


class TestIsReservedEdges:
    @pytest.mark.parametrize(
        "inp",
        [
            "",
            "not-an-ip",
            "999.999.999.999",
            "10.0.0.0/33",
            None,
            "::/200",
        ],
    )
    def test_garbage_returns_none(self, inp):
        # Does not raise.
        assert is_reserved(inp) is None  # type: ignore[arg-type]

    def test_ipv4_mapped_ipv6_hit(self):
        assert is_reserved("::ffff:10.0.0.1") == "IPv4-mapped"
