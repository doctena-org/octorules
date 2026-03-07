"""Tests for page_shield_policies serialization in the dumper."""

from __future__ import annotations

import yaml

from octorules.dumper import dump_zone_rules


class TestDumpPageShieldPolicies:
    """Tests for page_shield_policies serialization in dump_zone_rules."""

    def test_dump_with_page_shield_policies(self, tmp_path):
        policies = [
            {
                "id": "policy-123",
                "last_updated": "2026-01-01",
                "description": "CSP on all doctena.com",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "script-src 'self'",
            }
        ]
        result = dump_zone_rules("example.com", {}, tmp_path, page_shield_policies=policies)
        assert result is not None
        data = yaml.safe_load(result.read_text())
        assert "page_shield_policies" in data
        assert len(data["page_shield_policies"]) == 1
        policy = data["page_shield_policies"][0]
        assert policy["description"] == "CSP on all doctena.com"
        assert policy["action"] == "allow"
        assert policy["expression"] == "true"
        assert policy["enabled"] is True
        assert policy["value"] == "script-src 'self'"

    def test_dump_page_shield_policies_api_fields_stripped(self, tmp_path):
        policies = [
            {
                "id": "policy-uuid",
                "last_updated": "2026-02-01T00:00:00Z",
                "description": "Test",
                "action": "log",
                "expression": "true",
                "enabled": True,
                "value": "default-src 'self'",
            }
        ]
        result = dump_zone_rules("example.com", {}, tmp_path, page_shield_policies=policies)
        data = yaml.safe_load(result.read_text())
        policy = data["page_shield_policies"][0]
        assert "id" not in policy
        assert "last_updated" not in policy
        assert policy["description"] == "Test"

    def test_dump_page_shield_policies_sorted_by_description(self, tmp_path):
        policies = [
            {
                "description": "Zebra",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "v1",
            },
            {
                "description": "Alpha",
                "action": "log",
                "expression": "true",
                "enabled": True,
                "value": "v2",
            },
        ]
        result = dump_zone_rules("example.com", {}, tmp_path, page_shield_policies=policies)
        data = yaml.safe_load(result.read_text())
        assert data["page_shield_policies"][0]["description"] == "Alpha"
        assert data["page_shield_policies"][1]["description"] == "Zebra"

    def test_dump_page_shield_policies_none_no_section(self, tmp_path):
        result = dump_zone_rules("example.com", {}, tmp_path, page_shield_policies=None)
        data = yaml.safe_load(result.read_text())
        assert "page_shield_policies" not in (data or {})

    def test_dump_page_shield_policies_empty_no_section(self, tmp_path):
        result = dump_zone_rules("example.com", {}, tmp_path, page_shield_policies=[])
        data = yaml.safe_load(result.read_text())
        assert "page_shield_policies" not in (data or {})

    def test_dump_with_phase_rules_and_policies(self, tmp_path):
        rules = {
            "http_request_firewall_custom": [
                {"ref": "w1", "expression": "true", "action": "block", "enabled": True}
            ],
        }
        policies = [
            {
                "description": "CSP",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "v",
            },
        ]
        result = dump_zone_rules("example.com", rules, tmp_path, page_shield_policies=policies)
        data = yaml.safe_load(result.read_text())
        assert "waf_custom_rules" in data
        assert "page_shield_policies" in data

    def test_dump_page_shield_multiline_value_block_style(self, tmp_path):
        policies = [
            {
                "description": "CSP multi",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "script-src 'self';\nstyle-src 'self'",
            },
        ]
        result = dump_zone_rules("example.com", {}, tmp_path, page_shield_policies=policies)
        text = result.read_text()
        # Multiline values should use block style (|-), not escaped \n
        assert "|-" in text or "|" in text
        assert "\\n" not in text

    def test_dump_value_with_single_quotes_uses_double_quoted_style(self, tmp_path):
        """Strings containing single quotes should use YAML double-quoted style, not ''."""
        policies = [
            {
                "description": "CSP",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "script-src 'self' 'unsafe-inline'",
            }
        ]
        result = dump_zone_rules("example.com", {}, tmp_path, page_shield_policies=policies)
        text = result.read_text()
        # Must use double-quoted style, not single-quoted with '' escapes
        assert "''self''" not in text
        assert "\"script-src 'self' 'unsafe-inline'\"" in text

    def test_dump_long_csp_value_formatted_as_block(self, tmp_path):
        """Long CSP values should be formatted as multi-line block scalars."""
        long_csp = (
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
            " ajax.googleapis.com *.ajax.googleapis.com"
            " cdnjs.cloudflare.com *.cdnjs.cloudflare.com"
            " challenges.cloudflare.com *.challenges.cloudflare.com"
            " cookiefirst.com *.cookiefirst.com"
            " google.com *.google.com"
            " static.cloudflareinsights.com"
        )
        policies = [
            {
                "description": "CSP",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": long_csp,
            }
        ]
        result = dump_zone_rules("example.com", {}, tmp_path, page_shield_policies=policies)
        text = result.read_text()
        # Should use block scalar style
        assert "|" in text
        # Should not be on a single line
        data = yaml.safe_load(text)
        loaded_value = data["page_shield_policies"][0]["value"]
        # Loaded multi-line value should normalize back to original
        from octorules.expression import normalize_expression

        assert normalize_expression(loaded_value) == long_csp

    def test_round_trip_page_shield_policies(self, tmp_path):
        """Dumped policies should round-trip through diff with no changes."""
        from octorules.planner import diff_page_shield_policies

        cf_policies = [
            {
                "id": "policy-uuid",
                "last_updated": "2026-01-01T00:00:00Z",
                "description": "CSP on all",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "script-src 'self'",
            }
        ]
        result = dump_zone_rules("example.com", {}, tmp_path, page_shield_policies=cf_policies)
        data = yaml.safe_load(result.read_text())
        dumped_policies = data["page_shield_policies"]
        plans = diff_page_shield_policies(dumped_policies, cf_policies)
        assert not any(p.has_changes for p in plans)

    def test_round_trip_long_csp_value(self, tmp_path):
        """Long CSP values should round-trip through dump → load → diff with no changes."""
        from octorules.planner import diff_page_shield_policies

        long_csp = (
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
            " ajax.googleapis.com *.ajax.googleapis.com"
            " cdnjs.cloudflare.com *.cdnjs.cloudflare.com"
            " cookiefirst.com *.cookiefirst.com"
            " google.com *.google.com"
            " static.cloudflareinsights.com;"
            " worker-src 'self' blob:"
        )
        cf_policies = [
            {
                "id": "policy-uuid",
                "last_updated": "2026-01-01T00:00:00Z",
                "description": "CSP",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": long_csp,
            }
        ]
        result = dump_zone_rules("example.com", {}, tmp_path, page_shield_policies=cf_policies)
        data = yaml.safe_load(result.read_text())
        dumped_policies = data["page_shield_policies"]
        plans = diff_page_shield_policies(dumped_policies, cf_policies)
        assert not any(p.has_changes for p in plans)
