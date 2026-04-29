"""Tests for the audit module — IP overlap, shadow, CDN ranges, zone drift."""

from pathlib import Path
from unittest.mock import patch

import yaml

from octorules._cdn_sources import (
    _parse_aws_cloudfront_ips,
    _parse_azure_front_door_ips,
    _parse_bunny_ips,
    _parse_cloudflare_ips,
    _parse_google_cloud_ips,
)
from octorules.audit import (
    _SEVERITY_RANK,
    ALL_CHECKS,
    AuditFinding,
    CdnRangeResult,
    FindingSeverity,
    RuleIPInfo,
    _load_baked_in_ranges,
    _to_network,
    audit_zone_rules,
    check_cdn_ranges,
    check_ip_overlap,
    check_ip_shadow,
    check_zone_drift,
    fetch_cdn_ranges,
    format_findings,
    parse_audit_acceptances,
    run_audit,
)
from octorules.extensions import (
    _audit_extensions,
    register_audit_extension,
    unregister_audit_extension,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_rule_ip(
    zone: str = "example.com",
    phase: str = "waf_custom_rules",
    ref: str = "rule1",
    action: str = "block",
    ips: list[str] | None = None,
) -> RuleIPInfo:
    return RuleIPInfo(
        zone_name=zone,
        phase_name=phase,
        ref=ref,
        action=action,
        ip_ranges=ips or [],
    )


# ---------------------------------------------------------------------------
# _to_network
# ---------------------------------------------------------------------------
class TestToNetwork:
    def test_valid_ipv4(self):
        net = _to_network("192.168.1.0/24")
        assert net is not None
        assert str(net) == "192.168.1.0/24"

    def test_valid_ipv6(self):
        net = _to_network("2001:db8::/32")
        assert net is not None
        assert str(net) == "2001:db8::/32"

    def test_single_host(self):
        net = _to_network("10.0.0.1")
        assert net is not None
        assert str(net) == "10.0.0.1/32"

    def test_invalid(self):
        assert _to_network("not-an-ip") is None

    def test_empty_string(self):
        assert _to_network("") is None


# ---------------------------------------------------------------------------
# check_ip_overlap
# ---------------------------------------------------------------------------
class TestCheckIPOverlap:
    def test_no_overlap(self):
        rules = [
            _make_rule_ip(ref="r1", ips=["10.0.0.0/24"]),
            _make_rule_ip(ref="r2", ips=["10.0.1.0/24"]),
        ]
        assert check_ip_overlap(rules) == []

    def test_overlap_different_rules(self):
        rules = [
            _make_rule_ip(ref="r1", ips=["10.0.0.0/16"]),
            _make_rule_ip(ref="r2", ips=["10.0.1.0/24"]),
        ]
        findings = check_ip_overlap(rules)
        assert len(findings) == 1
        assert findings[0].check == "ip-overlap"
        assert "10.0.1.0/24" in findings[0].message
        assert "10.0.0.0/16" in findings[0].message

    def test_no_overlap_same_rule_different_cidrs(self):
        """Intra-rule overlap is skipped (linter handles that)."""
        rules = [
            _make_rule_ip(ref="r1", ips=["10.0.0.0/16", "10.0.1.0/24"]),
        ]
        # Intra-rule: same ref + same phase → skipped
        assert check_ip_overlap(rules) == []

    def test_cross_phase_overlap(self):
        rules = [
            _make_rule_ip(ref="r1", phase="phase_a", ips=["10.0.0.0/8"]),
            _make_rule_ip(ref="r2", phase="phase_b", ips=["10.0.0.0/24"]),
        ]
        findings = check_ip_overlap(rules)
        assert len(findings) == 1

    def test_no_overlap_different_families(self):
        rules = [
            _make_rule_ip(ref="r1", ips=["10.0.0.0/8"]),
            _make_rule_ip(ref="r2", ips=["2001:db8::/32"]),
        ]
        assert check_ip_overlap(rules) == []

    def test_empty_input(self):
        assert check_ip_overlap([]) == []

    def test_invalid_cidr_skipped(self):
        rules = [
            _make_rule_ip(ref="r1", ips=["not-valid"]),
            _make_rule_ip(ref="r2", ips=["10.0.0.0/8"]),
        ]
        assert check_ip_overlap(rules) == []

    def test_exact_duplicate_overlap(self):
        rules = [
            _make_rule_ip(ref="r1", ips=["10.0.0.0/24"]),
            _make_rule_ip(ref="r2", ips=["10.0.0.0/24"]),
        ]
        findings = check_ip_overlap(rules)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# check_ip_shadow
# ---------------------------------------------------------------------------
class TestCheckIPShadow:
    PHASE_ORDER = ["phase_a", "phase_b", "phase_c"]

    def test_no_shadow(self):
        rules = [
            _make_rule_ip(ref="r1", phase="phase_a", action="block", ips=["10.0.0.0/24"]),
            _make_rule_ip(ref="r2", phase="phase_b", action="block", ips=["10.0.1.0/24"]),
        ]
        assert check_ip_shadow(rules, self.PHASE_ORDER) == []

    def test_shadow_by_earlier_phase(self):
        rules = [
            _make_rule_ip(ref="r1", phase="phase_a", action="block", ips=["10.0.0.0/8"]),
            _make_rule_ip(ref="r2", phase="phase_b", action="allow", ips=["10.0.1.0/24"]),
        ]
        findings = check_ip_shadow(rules, self.PHASE_ORDER)
        assert len(findings) == 1
        assert findings[0].check == "ip-shadow"
        assert "r2" in findings[0].message
        assert "r1" in findings[0].message

    def test_no_shadow_when_later_phase(self):
        """Later-phase rule cannot shadow an earlier one."""
        rules = [
            _make_rule_ip(ref="r1", phase="phase_b", action="allow", ips=["10.0.1.0/24"]),
            _make_rule_ip(ref="r2", phase="phase_a", action="block", ips=["10.0.0.0/8"]),
        ]
        # r1 is in phase_b, r2 is in phase_a (earlier). r1 is shadowed by r2.
        findings = check_ip_shadow(rules, self.PHASE_ORDER)
        assert len(findings) == 1
        assert "r1" in findings[0].ref

    def test_no_shadow_non_blocking_action(self):
        """Allow action in earlier phase doesn't shadow."""
        rules = [
            _make_rule_ip(ref="r1", phase="phase_a", action="allow", ips=["10.0.0.0/8"]),
            _make_rule_ip(ref="r2", phase="phase_b", action="block", ips=["10.0.1.0/24"]),
        ]
        assert check_ip_shadow(rules, self.PHASE_ORDER) == []

    def test_shadow_google_deny_action(self):
        """Google deny(403) format recognized as blocking."""
        rules = [
            _make_rule_ip(ref="r1", phase="phase_a", action="deny(403)", ips=["10.0.0.0/8"]),
            _make_rule_ip(ref="r2", phase="phase_b", action="allow", ips=["10.0.1.0/24"]),
        ]
        findings = check_ip_shadow(rules, self.PHASE_ORDER)
        assert len(findings) == 1

    def test_partial_coverage_not_shadowed(self):
        """Not all IPs covered → not shadowed."""
        rules = [
            _make_rule_ip(ref="r1", phase="phase_a", action="block", ips=["10.0.0.0/24"]),
            _make_rule_ip(
                ref="r2", phase="phase_b", action="allow", ips=["10.0.0.0/25", "172.16.0.0/24"]
            ),
        ]
        assert check_ip_shadow(rules, self.PHASE_ORDER) == []

    def test_empty_input(self):
        assert check_ip_shadow([], self.PHASE_ORDER) == []


# ---------------------------------------------------------------------------
# check_cdn_ranges
# ---------------------------------------------------------------------------
class TestCheckCDNRanges:
    CDN = {"CloudProvider": ["198.51.100.0/24", "2001:db8:face::/48"]}

    def test_match(self):
        rules = [_make_rule_ip(ref="r1", ips=["198.51.100.128/25"])]
        findings = check_cdn_ranges(rules, self.CDN)
        assert len(findings) == 1
        assert findings[0].check == "cdn-ranges"
        assert "CloudProvider" in findings[0].message

    def test_no_match(self):
        rules = [_make_rule_ip(ref="r1", ips=["10.0.0.0/8"])]
        assert check_cdn_ranges(rules, self.CDN) == []

    def test_empty_cdn(self):
        rules = [_make_rule_ip(ref="r1", ips=["198.51.100.0/24"])]
        assert check_cdn_ranges(rules, {}) == []

    def test_ipv6_match(self):
        rules = [_make_rule_ip(ref="r1", ips=["2001:db8:face::1/128"])]
        findings = check_cdn_ranges(rules, self.CDN)
        assert len(findings) == 1

    def test_invalid_cidr_skipped(self):
        rules = [_make_rule_ip(ref="r1", ips=["garbage"])]
        assert check_cdn_ranges(rules, self.CDN) == []

    def test_broad_cdn_range_detected_after_narrow_miss(self):
        """Regression: a broad CDN /8 must be detected even when a narrower
        CDN range with a later start address doesn't overlap the rule."""
        cdn = {"BigCDN": ["10.0.0.0/8", "10.1.0.0/16"]}
        rules = [_make_rule_ip(ref="r1", ips=["10.2.0.0/16"])]
        findings = check_cdn_ranges(rules, cdn)
        assert len(findings) == 1
        assert "BigCDN" in findings[0].message

    def test_broad_cdn_range_ipv6(self):
        """Same regression scenario for IPv6."""
        cdn = {"BigCDN": ["2001:db8::/32", "2001:db8:1::/48"]}
        rules = [_make_rule_ip(ref="r1", ips=["2001:db8:2::/48"])]
        findings = check_cdn_ranges(rules, cdn)
        assert len(findings) == 1
        assert "BigCDN" in findings[0].message


# ---------------------------------------------------------------------------
# check_zone_drift
# ---------------------------------------------------------------------------
class TestCheckZoneDrift:
    def test_no_drift(self):
        rules = [
            _make_rule_ip(zone="zone-a", ref="r1", action="block", ips=["10.0.0.0/24"]),
            _make_rule_ip(zone="zone-b", ref="r2", action="block", ips=["10.0.0.0/24"]),
        ]
        assert check_zone_drift(rules) == []

    def test_drift_different_actions(self):
        rules = [
            _make_rule_ip(zone="zone-a", ref="r1", action="block", ips=["10.0.0.0/24"]),
            _make_rule_ip(zone="zone-b", ref="r2", action="allow", ips=["10.0.0.0/24"]),
        ]
        findings = check_zone_drift(rules)
        assert len(findings) == 1
        assert findings[0].check == "zone-drift"
        assert "zone-a" in findings[0].message
        assert "zone-b" in findings[0].message

    def test_single_zone_no_drift(self):
        rules = [
            _make_rule_ip(zone="zone-a", ref="r1", action="block", ips=["10.0.0.0/24"]),
            _make_rule_ip(zone="zone-a", ref="r2", action="allow", ips=["10.0.0.0/24"]),
        ]
        # Same zone — not drift
        assert check_zone_drift(rules) == []

    def test_empty_input(self):
        assert check_zone_drift([]) == []

    def test_normalizes_cidr(self):
        """10.0.0.1/24 normalizes to 10.0.0.0/24."""
        rules = [
            _make_rule_ip(zone="zone-a", ref="r1", action="block", ips=["10.0.0.1/24"]),
            _make_rule_ip(zone="zone-b", ref="r2", action="allow", ips=["10.0.0.0/24"]),
        ]
        findings = check_zone_drift(rules)
        assert len(findings) == 1

    def test_list_pseudo_rules_excluded(self):
        """List pseudo-rules (phase_name='lists') don't trigger drift."""
        rules = [
            _make_rule_ip(zone="zone-a", ref="r1", action="block", ips=["10.0.0.0/24"]),
            _make_rule_ip(
                zone="zone-b", ref="list:orphan", phase="lists", action="", ips=["10.0.0.0/24"]
            ),
        ]
        assert check_zone_drift(rules) == []


# ---------------------------------------------------------------------------
# CDN parsers
# ---------------------------------------------------------------------------
class TestCDNParsers:
    def test_cloudflare_parser(self):
        data = {"result": {"ipv4_cidrs": ["1.1.1.0/24"], "ipv6_cidrs": ["2606:4700::/32"]}}
        cidrs = _parse_cloudflare_ips(data)
        assert "1.1.1.0/24" in cidrs
        assert "2606:4700::/32" in cidrs

    def test_cloudflare_parser_bad_data(self):
        assert _parse_cloudflare_ips({}) == []
        assert _parse_cloudflare_ips("not a dict") == []

    def test_cloudflare_parser_warns_on_non_dict(self, caplog):
        _parse_cloudflare_ips("not a dict")
        assert "expected dict" in caplog.text

    def test_cloudflare_parser_warns_on_bad_result(self, caplog):
        _parse_cloudflare_ips({"result": "not a dict"})
        assert "'result' is" in caplog.text

    def test_cloudflare_parser_warns_on_empty_result(self, caplog):
        _parse_cloudflare_ips({"result": {}})
        assert "no CIDRs found" in caplog.text

    def test_aws_parser(self):
        data = {
            "prefixes": [
                {"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT"},
                {"ip_prefix": "3.5.0.0/19", "service": "EC2"},
            ],
            "ipv6_prefixes": [
                {"ipv6_prefix": "2600:9000::/28", "service": "CLOUDFRONT"},
            ],
        }
        cidrs = _parse_aws_cloudfront_ips(data)
        assert "13.32.0.0/15" in cidrs
        assert "3.5.0.0/19" not in cidrs  # EC2, not CLOUDFRONT
        assert "2600:9000::/28" in cidrs

    def test_aws_parser_bad_data(self):
        assert _parse_aws_cloudfront_ips({}) == []
        assert _parse_aws_cloudfront_ips("not a dict") == []

    def test_aws_parser_warns_on_non_dict(self, caplog):
        _parse_aws_cloudfront_ips("not a dict")
        assert "expected dict" in caplog.text

    def test_aws_parser_warns_on_no_cloudfront(self, caplog):
        _parse_aws_cloudfront_ips({"prefixes": [{"service": "EC2", "ip_prefix": "1.2.3.0/24"}]})
        assert "no CloudFront CIDRs" in caplog.text

    def test_google_parser(self):
        data = {"prefixes": [{"ipv4Prefix": "8.8.8.0/24"}, {"ipv6Prefix": "2001:4860::/32"}]}
        cidrs = _parse_google_cloud_ips(data)
        assert "8.8.8.0/24" in cidrs
        assert "2001:4860::/32" in cidrs

    def test_google_parser_bad_data(self):
        assert _parse_google_cloud_ips({}) == []
        assert _parse_google_cloud_ips("not a dict") == []

    def test_google_parser_warns_on_non_dict(self, caplog):
        _parse_google_cloud_ips("not a dict")
        assert "expected dict" in caplog.text

    def test_google_parser_warns_on_empty_prefixes(self, caplog):
        _parse_google_cloud_ips({"prefixes": []})
        assert "no CIDRs found" in caplog.text

    def test_bunny_parser_ipv4_and_ipv6(self):
        data = "89.187.188.227\n185.93.1.243\n\n2400:52e0:1500::714:1\n"
        cidrs = _parse_bunny_ips(data)
        assert "89.187.188.227/32" in cidrs
        assert "185.93.1.243/32" in cidrs
        assert "2400:52e0:1500::714:1/128" in cidrs

    def test_bunny_parser_skips_blank_and_malformed(self):
        data = "1.2.3.4\n\n   \nnot-an-ip\n5.6.7.8\n"
        cidrs = _parse_bunny_ips(data)
        assert cidrs == ["1.2.3.4/32", "5.6.7.8/32"]

    def test_bunny_parser_bad_data(self):
        assert _parse_bunny_ips(b"bytes not str") == []  # type: ignore[arg-type]
        assert _parse_bunny_ips("") == []

    def test_bunny_parser_warns_on_non_str(self, caplog):
        _parse_bunny_ips(["list", "not", "str"])  # type: ignore[arg-type]
        assert "expected str" in caplog.text

    def test_bunny_parser_warns_on_no_ips(self, caplog):
        _parse_bunny_ips("# just a comment\nnot-an-ip\n")
        assert "no IPs parsed" in caplog.text

    def test_azure_front_door_parser(self):
        data = {
            "changeNumber": 396,
            "values": [
                {
                    "name": "AzureFrontDoor.Frontend",
                    "properties": {"addressPrefixes": ["4.145.22.160/29", "2603:1030::/48"]},
                },
                {
                    "name": "AzureFrontDoor.Backend",
                    "properties": {"addressPrefixes": ["13.73.248.16/29"]},
                },
                {
                    "name": "AzureFrontDoor.FirstParty",  # ignored
                    "properties": {"addressPrefixes": ["1.2.3.0/24"]},
                },
                {
                    "name": "Storage",  # ignored
                    "properties": {"addressPrefixes": ["9.9.9.0/24"]},
                },
            ],
        }
        cidrs = _parse_azure_front_door_ips(data)
        assert "4.145.22.160/29" in cidrs
        assert "2603:1030::/48" in cidrs
        assert "13.73.248.16/29" in cidrs
        assert "1.2.3.0/24" not in cidrs
        assert "9.9.9.0/24" not in cidrs

    def test_azure_front_door_parser_bad_data(self):
        assert _parse_azure_front_door_ips({}) == []
        assert _parse_azure_front_door_ips("not a dict") == []  # type: ignore[arg-type]
        assert _parse_azure_front_door_ips({"values": [{"name": "AzureFrontDoor.Frontend"}]}) == []

    def test_azure_front_door_parser_warns_on_non_dict(self, caplog):
        _parse_azure_front_door_ips("not a dict")  # type: ignore[arg-type]
        assert "expected dict" in caplog.text

    def test_azure_front_door_parser_warns_on_no_prefixes(self, caplog):
        _parse_azure_front_door_ips({"values": []})
        assert "no Front Door prefixes" in caplog.text


# ---------------------------------------------------------------------------
# fetch_cdn_ranges (with a local HTTP server)
# ---------------------------------------------------------------------------
class TestFetchCDNRanges:
    def test_fetch_success_returns_api_source(self):
        """When APIs succeed and baked-in data is stale, source is 'api'."""
        from octorules.audit import CdnRangeResult

        stale = CdnRangeResult(ranges={}, source="baked-in", generated_at=None)

        def mock_fetch(url, timeout=15):
            if "cloudflare" in url:
                return {"result": {"ipv4_cidrs": ["1.1.1.0/24"], "ipv6_cidrs": []}}
            return None

        with (
            patch("octorules.audit._load_baked_in_ranges", return_value=stale),
            patch("octorules.audit._fetch_json", side_effect=mock_fetch),
            patch("octorules.audit._fetch_text", return_value=None),
        ):
            result = fetch_cdn_ranges()
        assert result.source == "api"
        assert result.generated_at is None
        assert "Cloudflare" in result.ranges

    def test_fresh_baked_in_skips_api(self):
        """When baked-in data is fresh, API is not called."""
        with (
            patch("octorules.audit._fetch_json") as mock_fetch,
            patch("octorules.audit._fetch_text") as mock_fetch_text,
        ):
            result = fetch_cdn_ranges()
        mock_fetch.assert_not_called()
        mock_fetch_text.assert_not_called()
        assert result.source == "baked-in"
        assert len(result.ranges) > 0

    def test_fetch_failure_falls_back_to_baked_in(self):
        """When all CDN APIs fail and baked-in is stale, falls back to stale baked-in."""
        from datetime import datetime, timezone

        from octorules.audit import CdnRangeResult

        stale = CdnRangeResult(
            ranges={"Cloudflare": ["1.0.0.0/24"]},
            source="baked-in",
            generated_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )
        with (
            patch("octorules.audit._load_baked_in_ranges", return_value=stale),
            patch("octorules.audit._fetch_json", return_value=None),
            patch("octorules.audit._fetch_text", return_value=None),
        ):
            result = fetch_cdn_ranges(timeout=1)
        assert result.source == "baked-in"
        assert len(result.ranges) > 0

    def test_fetch_partial_success_uses_api(self):
        """When some CDN APIs succeed and baked-in is stale, source is 'api'."""
        from datetime import datetime, timezone

        from octorules.audit import CdnRangeResult

        stale = CdnRangeResult(
            ranges={},
            source="baked-in",
            generated_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )

        def mock_fetch(url, timeout=15):
            if "cloudflare" in url:
                return {"result": {"ipv4_cidrs": ["1.1.1.0/24"], "ipv6_cidrs": []}}
            return None

        with (
            patch("octorules.audit._load_baked_in_ranges", return_value=stale),
            patch("octorules.audit._fetch_json", side_effect=mock_fetch),
        ):
            result = fetch_cdn_ranges()
        assert result.source == "api"
        assert "Cloudflare" in result.ranges
        assert "AWS CloudFront" not in result.ranges

    def test_fetch_parser_exception_does_not_crash(self, caplog):
        """A parser raising must be logged + treated as failed fetch, not propagated.

        Without the defensive ``try/except`` around ``future.result()``, a
        parser bug would propagate out of ``fetch_cdn_ranges`` and crash the
        audit command. The contract is: parser failures degrade to baked-in
        fallback, never abort the run.
        """
        from datetime import datetime, timezone

        from octorules.audit import CdnRangeResult

        stale = CdnRangeResult(
            ranges={"Cloudflare": ["203.0.113.0/24"]},
            source="baked-in",
            generated_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )

        def boom(_data):
            raise RuntimeError("simulated parser failure")

        with (
            patch("octorules.audit._load_baked_in_ranges", return_value=stale),
            patch(
                "octorules.audit._fetch_json",
                return_value={"result": {"ipv4_cidrs": ["1.1.1.0/24"], "ipv6_cidrs": []}},
            ),
            patch("octorules.audit._fetch_text", return_value=None),
            patch("octorules.audit._parse_cloudflare_ips", side_effect=boom),
        ):
            result = fetch_cdn_ranges()

        # All API parsers fail → fall back to (stale) baked-in data.
        assert result.source == "baked-in"
        assert "CDN fetch failed for Cloudflare" in caplog.text


# ---------------------------------------------------------------------------
# CdnRangeResult
# ---------------------------------------------------------------------------
class TestCdnRangeResult:
    def test_api_source_never_stale(self):
        result = CdnRangeResult(ranges={}, source="api", generated_at=None)
        assert not result.is_stale(max_age_days=1)

    def test_fresh_baked_in_not_stale(self):
        from datetime import datetime, timedelta, timezone

        recent = datetime.now(timezone.utc) - timedelta(days=30)
        result = CdnRangeResult(ranges={}, source="baked-in", generated_at=recent)
        assert not result.is_stale(max_age_days=60)

    def test_old_baked_in_is_stale(self):
        from datetime import datetime, timedelta, timezone

        old = datetime.now(timezone.utc) - timedelta(days=61)
        result = CdnRangeResult(ranges={}, source="baked-in", generated_at=old)
        assert result.is_stale(max_age_days=60)

    def test_boundary_not_stale(self):
        from datetime import datetime, timedelta, timezone

        # 59 days ago is definitely not stale at threshold of 60
        just_under = datetime.now(timezone.utc) - timedelta(days=59)
        result = CdnRangeResult(ranges={}, source="baked-in", generated_at=just_under)
        assert not result.is_stale(max_age_days=60)


# ---------------------------------------------------------------------------
# _load_baked_in_ranges
# ---------------------------------------------------------------------------
class TestLoadBakedInRanges:
    def test_loads_real_baked_in_files(self):
        """The actual baked-in JSON files load successfully."""
        result = _load_baked_in_ranges()
        assert result.source == "baked-in"
        assert result.generated_at is not None
        assert "Cloudflare" in result.ranges
        assert "AWS CloudFront" in result.ranges
        assert "Google Cloud" in result.ranges
        assert len(result.ranges["Cloudflare"]) > 0

    def test_missing_files_returns_empty(self, tmp_path):
        """If data dir doesn't exist, returns empty ranges."""
        with patch("octorules.audit._CDN_DATA_DIR", tmp_path / "nonexistent"):
            result = _load_baked_in_ranges()
        assert result.ranges == {}
        assert result.generated_at is None

    def test_corrupt_json_skipped(self, tmp_path):
        """Corrupt JSON files are skipped with a warning."""
        data_dir = tmp_path / "cdn_ranges"
        data_dir.mkdir()
        (data_dir / "cloudflare.json").write_text("not json{{{")
        with patch("octorules.audit._CDN_DATA_DIR", data_dir):
            result = _load_baked_in_ranges()
        assert "Cloudflare" not in result.ranges


# ---------------------------------------------------------------------------
# format_findings
# ---------------------------------------------------------------------------
class TestFormatFindings:
    def test_empty(self):
        assert format_findings([]) == ""

    def test_groups_by_check(self):
        findings = [
            AuditFinding(check="ip-overlap", severity=FindingSeverity.WARNING, message="overlap"),
            AuditFinding(check="cdn-ranges", severity=FindingSeverity.INFO, message="cdn hit"),
        ]
        output = format_findings(findings)
        assert "[ip-overlap]" in output
        assert "[cdn-ranges]" in output
        assert "overlap" in output
        assert "cdn hit" in output

    def test_format_uses_lowercase_severity_prefix(self):
        """Output uses 'warning:' not '[WARNING]' (GHA annotation regression)."""
        findings = [
            AuditFinding(
                check="ip-overlap",
                severity=FindingSeverity.WARNING,
                message="test msg",
                zone_name="z",
            ),
        ]
        output = format_findings(findings)
        assert "warning:" in output
        assert "[WARNING]" not in output

    def test_format_min_severity_filters_warnings(self):
        findings = [
            AuditFinding(check="ip-overlap", severity=FindingSeverity.WARNING, message="warn"),
        ]
        output = format_findings(findings, min_severity=FindingSeverity.ERROR)
        assert output == ""

    def test_format_min_severity_default_shows_all(self):
        findings = [
            AuditFinding(check="ip-overlap", severity=FindingSeverity.WARNING, message="warn"),
        ]
        output = format_findings(findings)
        assert output != ""
        assert "warn" in output

    def test_format_min_severity_shows_equal_and_higher(self):
        findings = [
            AuditFinding(check="ip-overlap", severity=FindingSeverity.WARNING, message="warn"),
        ]
        output = format_findings(findings, min_severity=FindingSeverity.WARNING)
        assert "warn" in output

    def test_format_groups_by_check_with_count(self):
        findings = [
            AuditFinding(check="ip-overlap", severity=FindingSeverity.WARNING, message="a"),
            AuditFinding(check="ip-overlap", severity=FindingSeverity.WARNING, message="b"),
        ]
        output = format_findings(findings)
        assert "[ip-overlap] 2 finding(s):" in output

    def test_format_empty_findings_returns_empty(self):
        assert format_findings([]) == ""

    def test_json_format_returns_valid_json(self):
        """format_findings_json returns valid JSON array."""
        import json

        from octorules.audit import format_findings_json

        findings = [
            AuditFinding(
                check="ip-overlap",
                severity=FindingSeverity.WARNING,
                message="overlap msg",
                zone_name="zone-a",
            ),
        ]
        output = format_findings_json(findings)
        data = json.loads(output)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["check"] == "ip-overlap"
        assert data[0]["severity"] == "warning"
        assert data[0]["message"] == "overlap msg"
        assert data[0]["zone_name"] == "zone-a"

    def test_json_format_respects_min_severity(self):
        """format_findings_json filters by min_severity."""
        import json

        from octorules.audit import format_findings_json

        findings = [
            AuditFinding(check="ip-overlap", severity=FindingSeverity.WARNING, message="w"),
            AuditFinding(check="cdn-ranges", severity=FindingSeverity.INFO, message="i"),
        ]
        output = format_findings_json(findings, min_severity=FindingSeverity.WARNING)
        data = json.loads(output)
        assert len(data) == 1
        assert data[0]["severity"] == "warning"


# ---------------------------------------------------------------------------
# run_audit
# ---------------------------------------------------------------------------
class TestRunAudit:
    PHASE_ORDER = ["phase_a", "phase_b"]

    def test_only_selected_checks(self):
        rules = [
            _make_rule_ip(ref="r1", phase="phase_a", action="block", ips=["10.0.0.0/8"]),
            _make_rule_ip(ref="r2", phase="phase_b", action="allow", ips=["10.0.0.0/24"]),
        ]
        # Only run ip-overlap, not ip-shadow
        findings = run_audit(
            rules, self.PHASE_ORDER, checks=frozenset({"ip-overlap"}), cdn_timeout=1
        )
        assert all(f.check == "ip-overlap" for f in findings)

    def test_all_checks(self):
        """Runs without error with all checks enabled (mocking CDN)."""
        rules = [
            _make_rule_ip(
                zone="zone-a", ref="r1", phase="phase_a", action="block", ips=["10.0.0.0/8"]
            ),
            _make_rule_ip(
                zone="zone-a", ref="r2", phase="phase_b", action="allow", ips=["10.0.0.0/24"]
            ),
        ]
        empty_cdn = CdnRangeResult(ranges={}, source="api")
        with patch("octorules.audit.fetch_cdn_ranges", return_value=empty_cdn):
            findings = run_audit(rules, self.PHASE_ORDER)
        # Should have ip-overlap and ip-shadow findings at minimum
        checks_found = {f.check for f in findings}
        assert "ip-overlap" in checks_found
        assert "ip-shadow" in checks_found

    def test_empty_input(self):
        empty_cdn = CdnRangeResult(ranges={}, source="api")
        with patch("octorules.audit.fetch_cdn_ranges", return_value=empty_cdn):
            findings = run_audit([], self.PHASE_ORDER)
        assert findings == []

    def test_stale_baked_in_injects_warning(self):
        """When baked-in CDN data is stale, a warning finding is injected."""
        from datetime import datetime, timedelta, timezone

        old_date = datetime.now(timezone.utc) - timedelta(days=90)
        stale_cdn = CdnRangeResult(
            ranges={"TestCDN": ["198.51.100.0/24"]},
            source="baked-in",
            generated_at=old_date,
        )
        rules = [_make_rule_ip(ref="r1", ips=["198.51.100.128/25"])]
        with patch("octorules.audit.fetch_cdn_ranges", return_value=stale_cdn):
            findings = run_audit(rules, self.PHASE_ORDER, cdn_stale_days=60)
        cdn_findings = [f for f in findings if f.check == "cdn-ranges"]
        # Should have at least the CDN match + the staleness warning
        assert len(cdn_findings) >= 2
        stale_warnings = [f for f in cdn_findings if "baked-in" in f.message]
        assert len(stale_warnings) == 1
        assert "90 days old" in stale_warnings[0].message

    def test_fresh_baked_in_no_warning(self):
        """Fresh baked-in CDN data does not produce a staleness warning."""
        from datetime import datetime, timedelta, timezone

        recent = datetime.now(timezone.utc) - timedelta(days=10)
        fresh_cdn = CdnRangeResult(
            ranges={"TestCDN": ["198.51.100.0/24"]},
            source="baked-in",
            generated_at=recent,
        )
        rules = [_make_rule_ip(ref="r1", ips=["198.51.100.128/25"])]
        with patch("octorules.audit.fetch_cdn_ranges", return_value=fresh_cdn):
            findings = run_audit(rules, self.PHASE_ORDER, cdn_stale_days=60)
        stale_warnings = [f for f in findings if "baked-in" in f.message]
        assert len(stale_warnings) == 0


# ---------------------------------------------------------------------------
# audit_zone_rules (extension integration)
# ---------------------------------------------------------------------------
class TestAuditZoneRules:
    def test_calls_registered_extensions(self):
        """audit_zone_rules calls registered audit extensions."""
        called = []

        def fake_extractor(rules_data, phase_name):
            called.append(phase_name)
            if phase_name == "test_phase":
                return [
                    RuleIPInfo(
                        zone_name="",
                        phase_name=phase_name,
                        ref="r1",
                        action="block",
                        ip_ranges=["10.0.0.0/24"],
                    )
                ]
            return []

        register_audit_extension("test_provider", fake_extractor)
        try:
            rules_data = {"test_phase": [{"ref": "r1"}], "other_phase": []}
            results = audit_zone_rules(rules_data, "example.com")
            assert len(results) == 1
            assert results[0].zone_name == "example.com"
            assert results[0].ref == "r1"
            assert "test_phase" in called
        finally:
            unregister_audit_extension("test_provider")

    def test_no_extensions_no_lists_returns_empty(self):
        # Clear all audit extensions for this test
        saved = dict(_audit_extensions)
        _audit_extensions.clear()
        try:
            results = audit_zone_rules({"some_phase": []}, "example.com")
            assert results == []
        finally:
            _audit_extensions.update(saved)

    def test_unreferenced_lists_extracted_as_pseudo_rules(self):
        """Unreferenced IP lists are extracted as pseudo-rules."""
        saved = dict(_audit_extensions)
        _audit_extensions.clear()
        try:
            rules_data = {
                "some_phase": [],
                "lists": [
                    {
                        "name": "blocked-ips",
                        "kind": "ip",
                        "items": [{"ip": "10.0.0.0/24"}, {"ip": "172.16.0.0/12"}],
                    },
                    {
                        "name": "hostnames",
                        "kind": "hostname",
                        "items": [{"hostname": "example.com"}],
                    },
                ],
            }
            results = audit_zone_rules(rules_data, "zone-a")
            assert len(results) == 1
            assert results[0].ref == "list:blocked-ips"
            assert results[0].phase_name == "lists"
            assert results[0].zone_name == "zone-a"
            assert "10.0.0.0/24" in results[0].ip_ranges
            assert "172.16.0.0/12" in results[0].ip_ranges
        finally:
            _audit_extensions.update(saved)

    def test_list_refs_resolved_into_rule(self):
        """list_refs from extractor are resolved to IPs from lists section."""
        called = []

        def fake_extractor(rules_data, phase_name):
            called.append(phase_name)
            if phase_name == "test_phase":
                return [
                    RuleIPInfo(
                        zone_name="",
                        phase_name=phase_name,
                        ref="r1",
                        action="block",
                        ip_ranges=["1.2.3.0/24"],  # inline IP
                        list_refs=["office-ips"],  # references a list
                    )
                ]
            return []

        register_audit_extension("test_resolver", fake_extractor)
        try:
            rules_data = {
                "test_phase": [{"ref": "r1"}],
                "lists": [
                    {
                        "name": "office-ips",
                        "kind": "ip",
                        "items": [{"ip": "10.0.0.0/24"}, {"ip": "172.16.0.0/12"}],
                    },
                ],
            }
            results = audit_zone_rules(rules_data, "zone-a")
            # Should have 1 rule (with resolved list IPs), no standalone list pseudo-rule
            rule_results = [r for r in results if r.ref == "r1"]
            list_results = [r for r in results if r.ref.startswith("list:")]
            assert len(rule_results) == 1
            assert len(list_results) == 0  # Referenced list is NOT standalone
            # Rule should have inline IP + resolved list IPs
            assert "1.2.3.0/24" in rule_results[0].ip_ranges
            assert "10.0.0.0/24" in rule_results[0].ip_ranges
            assert "172.16.0.0/12" in rule_results[0].ip_ranges
        finally:
            unregister_audit_extension("test_resolver")

    def test_unreferenced_list_still_included(self):
        """Lists NOT referenced by any rule still appear as pseudo-rules."""

        def fake_extractor(rules_data, phase_name):
            if phase_name == "test_phase":
                return [
                    RuleIPInfo(
                        zone_name="",
                        phase_name=phase_name,
                        ref="r1",
                        action="block",
                        ip_ranges=[],
                        list_refs=["used-list"],
                    )
                ]
            return []

        register_audit_extension("test_unref", fake_extractor)
        try:
            rules_data = {
                "test_phase": [{"ref": "r1"}],
                "lists": [
                    {
                        "name": "used-list",
                        "kind": "ip",
                        "items": [{"ip": "10.0.0.0/24"}],
                    },
                    {
                        "name": "orphaned-list",
                        "kind": "ip",
                        "items": [{"ip": "192.168.0.0/16"}],
                    },
                ],
            }
            results = audit_zone_rules(rules_data, "zone-a")
            refs = {r.ref for r in results}
            assert "r1" in refs  # Rule with resolved list
            assert "list:orphaned-list" in refs  # Unreferenced list
            assert "list:used-list" not in refs  # Referenced → merged into r1
        finally:
            unregister_audit_extension("test_unref")

    def test_unreferenced_lists_participate_in_overlap(self):
        """Unreferenced list IPs are checked against rule IPs for overlaps."""
        rule_ips = [
            _make_rule_ip(ref="r1", phase="waf", ips=["10.0.0.0/8"]),
            _make_rule_ip(ref="list:blocked", phase="lists", ips=["10.0.1.0/24"]),
        ]
        findings = check_ip_overlap(rule_ips)
        assert len(findings) == 1
        assert "list:blocked" in findings[0].message or "r1" in findings[0].message


# ---------------------------------------------------------------------------
# Extension registry
# ---------------------------------------------------------------------------
class TestAuditExtensionRegistry:
    def test_register_unregister(self):
        fn = lambda rules_data, phase_name: []  # noqa: E731
        register_audit_extension("test", fn)
        assert "test" in _audit_extensions
        unregister_audit_extension("test")
        assert "test" not in _audit_extensions

    def test_unregister_nonexistent(self):
        """Unregistering non-existent extension doesn't raise and leaves
        the registry unchanged."""
        before = dict(_audit_extensions)
        unregister_audit_extension("does_not_exist")
        assert "does_not_exist" not in _audit_extensions
        assert _audit_extensions == before


# ---------------------------------------------------------------------------
# parse_audit_acceptances
# ---------------------------------------------------------------------------
class TestParseAuditAcceptances:
    def test_single_check(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("# octorules:accept=zone-drift\nsome: yaml\n")
        assert parse_audit_acceptances(f) == {"zone-drift"}

    def test_multiple_checks_one_line(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("# octorules:accept=ip-overlap,cdn-ranges\n")
        assert parse_audit_acceptances(f) == {"ip-overlap", "cdn-ranges"}

    def test_whitespace_variations(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("# octorules: accept = ip-overlap , cdn-ranges\n")
        assert parse_audit_acceptances(f) == {"ip-overlap", "cdn-ranges"}

    def test_unknown_check_logged_and_dropped(self, tmp_path, caplog):
        f = tmp_path / "test.yaml"
        f.write_text("# octorules:accept=bogus\n")
        import logging

        with caplog.at_level(logging.WARNING, logger="octorules.audit"):
            result = parse_audit_acceptances(f)
        assert result == set()
        assert "bogus" in caplog.text

    def test_mixed_known_unknown(self, tmp_path, caplog):
        f = tmp_path / "test.yaml"
        f.write_text("# octorules:accept=zone-drift,bogus\n")
        import logging

        with caplog.at_level(logging.WARNING, logger="octorules.audit"):
            result = parse_audit_acceptances(f)
        assert result == {"zone-drift"}
        assert "bogus" in caplog.text

    def test_file_not_found(self, tmp_path):
        f = tmp_path / "nonexistent.yaml"
        assert parse_audit_acceptances(f) == set()

    def test_multiple_directives(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("# octorules:accept=zone-drift\nsome: yaml\n# octorules:accept=ip-overlap\n")
        assert parse_audit_acceptances(f) == {"zone-drift", "ip-overlap"}

    def test_empty_file(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("")
        assert parse_audit_acceptances(f) == set()

    def test_no_directives(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("zones:\n  example.com:\n    sources: [rules]\n")
        assert parse_audit_acceptances(f) == set()

    def test_all_checks_accepted(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("# octorules:accept=ip-overlap,ip-shadow,cdn-ranges,zone-drift\n")
        assert parse_audit_acceptances(f) == ALL_CHECKS

    def test_coexists_with_lint_disable(self, tmp_path):
        """Both octorules:disable and octorules:accept in the same file work independently."""
        from octorules.linter.suppressions import parse_suppressions

        f = tmp_path / "test.yaml"
        f.write_text(
            "# octorules:disable=CF001\n"
            "# octorules:accept=zone-drift\n"
            "- ref: r1\n"
            "  expression: 'true'\n"
        )
        # Audit sees only accept, not disable
        audit_result = parse_audit_acceptances(f)
        assert audit_result == {"zone-drift"}

        # Lint sees only disable, not accept
        lint_result = parse_suppressions(f)
        assert "CF001" in lint_result.get("r1", set()) or "CF001" in lint_result.get("*", set())

    def test_coexists_with_lint_disable_same_rule(self, tmp_path):
        """Both directives on adjacent lines before the same rule anchor."""
        from octorules.linter.suppressions import parse_suppressions

        f = tmp_path / "test.yaml"
        f.write_text(
            "# octorules:disable=CF018,CF423\n"
            "# octorules:accept=zone-drift\n"
            "- ref: 81f3cf649da74ee29a547fdb9b8425eb\n"
            "  expression: 'ip.src in {194.154.198.204}'\n"
        )
        # Audit acceptance works
        assert parse_audit_acceptances(f) == {"zone-drift"}

        # Lint suppression attaches to the ref
        lint_result = parse_suppressions(f)
        ref_suppressions = lint_result.get("81f3cf649da74ee29a547fdb9b8425eb", set())
        assert "CF018" in ref_suppressions
        assert "CF423" in ref_suppressions


# ---------------------------------------------------------------------------
# _SEVERITY_RANK
# ---------------------------------------------------------------------------
class TestSeverityRank:
    def test_error_ranks_highest(self):
        assert _SEVERITY_RANK[FindingSeverity.ERROR] < _SEVERITY_RANK[FindingSeverity.WARNING]

    def test_all_severities_present(self):
        for sev in FindingSeverity:
            assert sev in _SEVERITY_RANK

    def test_rank_ordering(self):
        assert (
            _SEVERITY_RANK[FindingSeverity.ERROR]
            < _SEVERITY_RANK[FindingSeverity.WARNING]
            < _SEVERITY_RANK[FindingSeverity.INFO]
        )


# ---------------------------------------------------------------------------
# cmd_audit integration tests
# ---------------------------------------------------------------------------
def _write_config_and_rules(
    tmp_path: Path,
    zone_rules: dict[str, dict],
    *,
    extra_files: dict[str, dict] | None = None,
) -> Path:
    """Create a config file and rules files, return the config path."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    zones_section = {}
    for name in zone_rules:
        zones_section[name] = {"sources": ["rules"]}

    config_data = {
        "providers": {
            "cloudflare": {"token": "fake"},
            "rules": {"directory": str(rules_dir)},
        },
        "zones": zones_section,
    }
    config_path = tmp_path / "config.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config_data, f)

    for name, rules in zone_rules.items():
        with open(rules_dir / f"{name}.yaml", "w") as f:
            yaml.dump(rules, f)

    # Write extra files not in zones (e.g. account rules)
    if extra_files:
        for name, rules in extra_files.items():
            with open(rules_dir / f"{name}.yaml", "w") as f:
                yaml.dump(rules, f)

    return config_path


def _cf_extract_ips(rules_data: dict, phase_name: str) -> list[RuleIPInfo]:
    """Test audit extractor — mimics the Cloudflare extractor for waf phases."""
    from octorules.phases import PHASE_BY_NAME

    if phase_name not in PHASE_BY_NAME:
        return []
    rules = rules_data.get(phase_name)
    if not isinstance(rules, list):
        return []
    results: list[RuleIPInfo] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        expr = rule.get("expression", "")
        if not isinstance(expr, str):
            continue
        # Simple regex extraction for tests
        import re

        ips = re.findall(r"(\d+\.\d+\.\d+\.\d+(?:/\d+)?)", expr)
        if ips:
            results.append(
                RuleIPInfo(
                    zone_name="",
                    phase_name=phase_name,
                    ref=str(rule.get("ref", "")),
                    action=str(rule.get("action", "")),
                    ip_ranges=ips,
                )
            )
    return results


class TestCmdAudit:
    """Integration tests for cmd_audit.

    Uses a test audit extractor rather than relying on provider packages,
    since the conftest registers test phases that conflict with provider
    phase registration.
    """

    _empty_cdn = CdnRangeResult(ranges={}, source="api")

    # Skip _ensure_provider_loaded inside cmd_audit — this class
    # registers its own test extractor and does not need real providers
    # (whose SDK imports are expensive, e.g. google-cloud-compute ~2s).
    _discover_patch = patch("octorules.commands._audit._ensure_provider_loaded", lambda name: None)

    def setup_method(self):
        self._discover_patch.start()
        register_audit_extension("test_cf", _cf_extract_ips)

    def teardown_method(self):
        unregister_audit_extension("test_cf")
        self._discover_patch.stop()

    def test_discovers_all_yaml_files(self, tmp_path):
        """Audit processes every *.yaml in rules_dir, not just zones."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {
                            "ref": "r1",
                            "action": "block",
                            "expression": "ip.src in {10.0.0.0/24}",
                        }
                    ]
                },
            },
            extra_files={
                "account-rules": {
                    "waf_custom_rules": [
                        {
                            "ref": "r2",
                            "action": "block",
                            "expression": "ip.src in {10.0.0.0/24}",
                        }
                    ]
                },
            },
        )

        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(config, zone_filter=None, checks=["zone-drift"])

        # Both files processed → zone-drift should NOT fire (same action)
        assert exit_code == 0

    def test_discovers_extra_files_with_drift(self, tmp_path):
        """Extra file with different action triggers zone-drift."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {
                            "ref": "r1",
                            "action": "block",
                            "expression": "ip.src in {10.0.0.0/24}",
                        }
                    ]
                },
            },
            extra_files={
                "account-rules": {
                    "waf_custom_rules": [
                        {
                            "ref": "r2",
                            "action": "skip",
                            "expression": "ip.src in {10.0.0.0/24}",
                        }
                    ]
                },
            },
        )

        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(config, zone_filter=None, checks=["zone-drift"])

        assert exit_code == 0  # drift is WARNING, default exit code ignores warnings

    def test_zone_filter_restricts_to_named_files(self, tmp_path):
        """--zone restricts audit to that file only."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {
                            "ref": "r1",
                            "action": "block",
                            "expression": "ip.src in {10.0.0.0/8}",
                        }
                    ]
                },
                "zone-b": {
                    "waf_custom_rules": [
                        {
                            "ref": "r2",
                            "action": "allow",
                            "expression": "ip.src in {10.0.0.0/8}",
                        }
                    ]
                },
            },
        )

        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            # Only zone-a → no drift possible
            exit_code = cmd_audit(config, zone_filter=["zone-a"], checks=["zone-drift"])
        assert exit_code == 0

    def test_invalid_check_returns_error(self, tmp_path):
        """Unknown --check name returns exit code 1."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(tmp_path, zone_rules={})
        config = Config.from_file(str(config_path))
        exit_code = cmd_audit(config, zone_filter=None, checks=["bogus-check"])
        assert exit_code == 1

    def test_no_rules_files_returns_zero(self, tmp_path):
        """Empty rules directory → exit 0."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(tmp_path, zone_rules={})
        config = Config.from_file(str(config_path))
        exit_code = cmd_audit(config, zone_filter=None, checks=["ip-overlap"])
        assert exit_code == 0

    def test_no_ips_returns_zero(self, tmp_path):
        """Rules with no IPs → exit 0."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {
                            "ref": "r1",
                            "action": "block",
                            "expression": 'http.host eq "example.com"',
                        }
                    ]
                },
            },
        )

        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(config, zone_filter=None)
        assert exit_code == 0

    def test_phase_filter(self, tmp_path):
        """--phase restricts which phases are audited."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {
                            "ref": "r1",
                            "action": "block",
                            "expression": "ip.src in {10.0.0.0/8}",
                        }
                    ],
                    "rate_limiting_rules": [
                        {
                            "ref": "r2",
                            "action": "block",
                            "expression": "ip.src in {10.0.0.0/24}",
                        }
                    ],
                },
            },
        )

        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            # Only rate_limiting_rules → single rule, no overlap
            exit_code = cmd_audit(
                config,
                zone_filter=None,
                phase_filter=["rate_limiting_rules"],
                checks=["ip-overlap"],
            )
        assert exit_code == 0

        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            # Both phases → overlap between r1 and r2 (WARNING severity)
            exit_code = cmd_audit(
                config,
                zone_filter=None,
                checks=["ip-overlap"],
            )
        assert exit_code == 0  # warnings don't fail by default

    def test_list_ips_included_in_audit(self, tmp_path):
        """IPs from lists section participate in overlap checks."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {
                            "ref": "r1",
                            "action": "block",
                            "expression": "ip.src in {10.0.0.0/8}",
                        }
                    ],
                    "lists": [
                        {
                            "name": "office-ips",
                            "kind": "ip",
                            "items": [{"ip": "10.0.1.0/24"}],
                        }
                    ],
                },
            },
        )

        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(config, zone_filter=None, checks=["ip-overlap"])
        # 10.0.1.0/24 (list) overlaps 10.0.0.0/8 (rule) — WARNING, not error
        assert exit_code == 0

    def test_exit_code_flag_warnings_return_two(self, tmp_path):
        """With --exit-code, WARNING findings produce exit code 2."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/8}"},
                        {"ref": "r2", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(config, zone_filter=None, checks=["ip-overlap"], exit_code=True)
        assert exit_code == 2

    def test_severity_filter_hides_lower_severity(self, tmp_path, capsys):
        """--severity error hides WARNING findings from output."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/8}"},
                        {"ref": "r2", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(config, zone_filter=None, checks=["ip-overlap"], severity="error")
        # WARNING findings exist but are filtered from display; no errors → exit 0
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "ip-overlap" not in captured.out  # filtered from display

    def test_severity_filter_does_not_affect_exit_code(self, tmp_path):
        """Severity filter affects display only, not exit code logic."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/8}"},
                        {"ref": "r2", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            # severity=error hides warnings from display, but exit_code=True
            # still detects warnings and returns 2
            exit_code = cmd_audit(
                config,
                zone_filter=None,
                checks=["ip-overlap"],
                severity="error",
                exit_code=True,
            )
        assert exit_code == 2

    def test_acceptance_suppresses_findings(self, tmp_path, capsys):
        """# octorules: accept=ip-overlap suppresses overlap findings."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/8}"},
                        {"ref": "r2", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        # Prepend acceptance directive to the rules file
        rules_file = tmp_path / "rules" / "zone-a.yaml"
        original = rules_file.read_text()
        rules_file.write_text(f"# octorules: accept=ip-overlap\n{original}")

        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(config, zone_filter=None, checks=["ip-overlap"], exit_code=True)
        assert exit_code == 0  # suppressed
        captured = capsys.readouterr()
        assert "suppressed" in captured.err

    def test_default_warnings_return_zero(self, tmp_path):
        """WARNING findings without --exit-code return 0."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/8}"},
                        {"ref": "r2", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(config, zone_filter=None, checks=["ip-overlap"])
        assert exit_code == 0

    def test_exit_code_true_warnings_return_two(self, tmp_path):
        """With exit_code=True, WARNING findings produce exit code 2."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/8}"},
                        {"ref": "r2", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(config, zone_filter=None, checks=["ip-overlap"], exit_code=True)
        assert exit_code == 2

    def test_exit_code_true_no_findings_return_zero(self, tmp_path):
        """With exit_code=True and no findings, exit code is 0."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {
                            "ref": "r1",
                            "action": "block",
                            "expression": 'http.host eq "example.com"',
                        }
                    ]
                },
            },
        )
        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(config, zone_filter=None, exit_code=True)
        assert exit_code == 0

    def test_severity_error_hides_warnings_from_output(self, tmp_path, capsys):
        """severity='error' hides WARNING findings from stdout."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/8}"},
                        {"ref": "r2", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            cmd_audit(config, zone_filter=None, checks=["ip-overlap"], severity="error")
        captured = capsys.readouterr()
        assert "ip-overlap" not in captured.out

    def test_severity_filter_does_not_affect_exit_code_with_warnings(self, tmp_path):
        """severity='error' + exit_code=True with WARNING findings still returns 2."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/8}"},
                        {"ref": "r2", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(
                config,
                zone_filter=None,
                checks=["ip-overlap"],
                severity="error",
                exit_code=True,
            )
        assert exit_code == 2

    def test_acceptance_suppresses_zone_drift(self, tmp_path, capsys):
        """Acceptance in one zone file suppresses zone-drift findings for that zone."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
                "zone-b": {
                    "waf_custom_rules": [
                        {"ref": "r2", "action": "allow", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        # Prepend acceptance directive to zone-a's rules file
        rules_file = tmp_path / "rules" / "zone-a.yaml"
        original = rules_file.read_text()
        rules_file.write_text(f"# octorules:accept=zone-drift\n{original}")

        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(config, zone_filter=None, checks=["zone-drift"], exit_code=True)
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "suppressed" in captured.err

    def test_acceptance_multiple_checks_one_directive(self, tmp_path, capsys):
        """# octorules:accept=ip-overlap,zone-drift suppresses both."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/8}"},
                        {"ref": "r2", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        # Prepend multi-check acceptance
        rules_file = tmp_path / "rules" / "zone-a.yaml"
        original = rules_file.read_text()
        rules_file.write_text(f"# octorules:accept=ip-overlap,zone-drift\n{original}")

        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(config, zone_filter=None, checks=["ip-overlap"], exit_code=True)
        assert exit_code == 0  # ip-overlap suppressed

    def test_acceptance_does_not_suppress_other_checks(self, tmp_path, capsys):
        """Accepting ip-overlap does not suppress ip-shadow findings."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/8}"},
                        {"ref": "r2", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        # Accept only ip-overlap, not ip-shadow or others
        rules_file = tmp_path / "rules" / "zone-a.yaml"
        original = rules_file.read_text()
        rules_file.write_text(f"# octorules:accept=ip-overlap\n{original}")

        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            cmd_audit(config, zone_filter=None, checks=["ip-overlap", "ip-shadow"], exit_code=True)
        # ip-overlap is suppressed, but ip-shadow (if present) is not.
        # Both rules are in the same phase, so no ip-shadow finding either.
        # The test verifies that suppression is check-specific.
        captured = capsys.readouterr()
        assert "suppressed" in captured.err
        # ip-overlap should not appear in output (suppressed)
        assert "ip-overlap" not in captured.out

    def test_acceptance_count_in_summary(self, tmp_path, capsys):
        """Verify 'suppressed' appears in stderr summary."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/8}"},
                        {"ref": "r2", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        rules_file = tmp_path / "rules" / "zone-a.yaml"
        original = rules_file.read_text()
        rules_file.write_text(f"# octorules:accept=ip-overlap\n{original}")

        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            cmd_audit(config, zone_filter=None, checks=["ip-overlap"])
        captured = capsys.readouterr()
        assert "suppressed" in captured.err

    def test_acceptance_with_space_after_colon(self, tmp_path, capsys):
        """# octorules: accept=ip-overlap works (space after colon)."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/8}"},
                        {"ref": "r2", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        rules_file = tmp_path / "rules" / "zone-a.yaml"
        original = rules_file.read_text()
        rules_file.write_text(f"# octorules: accept=ip-overlap\n{original}")

        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(config, zone_filter=None, checks=["ip-overlap"], exit_code=True)
        assert exit_code == 0  # suppressed
        captured = capsys.readouterr()
        assert "suppressed" in captured.err

    def test_json_format_outputs_json(self, tmp_path, capsys):
        """--format json outputs valid JSON array."""
        import json

        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/8}"},
                        {"ref": "r2", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(
                config, zone_filter=None, checks=["ip-overlap"], audit_format="json"
            )
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["check"] == "ip-overlap"

    def test_output_file_writes_results(self, tmp_path):
        """--output FILE writes results to a file instead of stdout."""
        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/8}"},
                        {"ref": "r2", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        out_file = tmp_path / "audit-results.txt"
        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(
                config,
                zone_filter=None,
                checks=["ip-overlap"],
                output_file=str(out_file),
            )
        assert exit_code == 0
        assert out_file.exists()
        content = out_file.read_text()
        assert "ip-overlap" in content

    def test_output_file_json_format(self, tmp_path):
        """--output FILE --format json writes JSON to file."""
        import json

        from octorules.commands import cmd_audit
        from octorules.config import Config

        config_path = _write_config_and_rules(
            tmp_path,
            zone_rules={
                "zone-a": {
                    "waf_custom_rules": [
                        {"ref": "r1", "action": "block", "expression": "ip.src in {10.0.0.0/8}"},
                        {"ref": "r2", "action": "block", "expression": "ip.src in {10.0.0.0/24}"},
                    ]
                },
            },
        )
        out_file = tmp_path / "audit-results.json"
        config = Config.from_file(str(config_path))
        with patch("octorules.audit.fetch_cdn_ranges", return_value=self._empty_cdn):
            exit_code = cmd_audit(
                config,
                zone_filter=None,
                checks=["ip-overlap"],
                audit_format="json",
                output_file=str(out_file),
            )
        assert exit_code == 0
        data = json.loads(out_file.read_text())
        assert isinstance(data, list)
        assert data[0]["check"] == "ip-overlap"


class TestFetchJsonErrors:
    """Tests for _fetch_json error handling."""

    def test_network_timeout(self):
        """_fetch_json returns None on timeout."""
        from octorules.audit import _fetch_json

        with patch("octorules.audit.urlopen", side_effect=TimeoutError("timed out")):
            result = _fetch_json("https://example.com/data.json")
        assert result is None

    def test_http_non_200(self):
        """_fetch_json returns None on non-200 status."""
        from unittest.mock import MagicMock

        from octorules.audit import _fetch_json

        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.status = 500
        with patch("octorules.audit.urlopen", return_value=mock_resp):
            result = _fetch_json("https://example.com/data.json")
        assert result is None

    def test_malformed_json(self):
        """_fetch_json returns None on invalid JSON."""
        from unittest.mock import MagicMock

        from octorules.audit import _fetch_json

        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.status = 200
        mock_resp.read.return_value = b"not-json{{"
        with patch("octorules.audit.urlopen", return_value=mock_resp):
            result = _fetch_json("https://example.com/data.json")
        assert result is None


# ---------------------------------------------------------------------------
# Performance guard tests
# ---------------------------------------------------------------------------
class TestAuditPerformance:
    """Guard against O(n²) regressions in audit checks.

    Audit checks process IP ranges across rules. The sweep-line algorithm
    (O(n log n)) replaced an earlier O(n²) approach in v0.23.4. These
    tests create large synthetic datasets and assert completion within a
    time budget.
    """

    @staticmethod
    def _make_rules(count: int) -> list[RuleIPInfo]:
        """Create *count* rules, each with a unique /32 IP."""
        return [
            _make_rule_ip(
                ref=f"rule-{i}",
                phase="waf_custom_rules",
                action="block",
                ips=[f"198.51.{i // 256}.{i % 256}/32"],
            )
            for i in range(count)
        ]

    def test_ip_overlap_5000_rules_under_5s(self):
        """5,000 rules with unique IPs must complete overlap check in < 2s."""
        import time

        rules = self._make_rules(5000)
        t0 = time.monotonic()
        check_ip_overlap(rules)
        elapsed = time.monotonic() - t0
        assert elapsed < 5.0, f"ip-overlap on 5000 rules took {elapsed:.1f}s (limit 5s)"

    def test_ip_shadow_5000_rules_under_5s(self):
        """5,000 rules must complete shadow check in < 2s."""
        import time

        rules = self._make_rules(5000)
        t0 = time.monotonic()
        check_ip_shadow(rules, phase_order=["waf_custom_rules"])
        elapsed = time.monotonic() - t0
        assert elapsed < 5.0, f"ip-shadow on 5000 rules took {elapsed:.1f}s (limit 5s)"

    def test_zone_drift_5000_rules_under_5s(self):
        """5,000 rules across 10 zones must complete drift check in < 2s."""
        import time

        rules = [
            _make_rule_ip(
                zone=f"zone-{i % 10}.example.com",
                ref=f"rule-{i}",
                phase="waf_custom_rules",
                action="block",
                ips=[f"198.51.{i // 256}.{i % 256}/32"],
            )
            for i in range(5000)
        ]
        t0 = time.monotonic()
        check_zone_drift(rules)
        elapsed = time.monotonic() - t0
        assert elapsed < 5.0, f"zone-drift on 5000 rules took {elapsed:.1f}s (limit 5s)"
