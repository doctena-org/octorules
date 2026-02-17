"""Tests for the dumper."""

from __future__ import annotations

import yaml

from octorules.dumper import _clean_rule, dump_zone_rules


class TestCleanRule:
    def test_strips_api_fields(self):
        rule = {
            "id": "abc",
            "version": "1",
            "last_updated": "2024-01-01",
            "ref": "my-rule",
            "expression": "true",
            "action": "redirect",
            "enabled": True,
        }
        cleaned = _clean_rule(rule, "redirect")
        assert "id" not in cleaned
        assert "version" not in cleaned
        assert cleaned["ref"] == "my-rule"  # ref is preserved (user-defined)
        assert "action" not in cleaned  # matches default
        assert cleaned["expression"] == "true"

    def test_ref_and_description_come_first(self):
        rule = {
            "action": "block",
            "action_parameters": {"status_code": 403},
            "expression": "true",
            "enabled": True,
            "ref": "my-rule",
            "description": "Block bad traffic",
        }
        cleaned = _clean_rule(rule, None)
        keys = list(cleaned.keys())
        assert keys[0] == "ref"
        assert keys[1] == "description"

    def test_keeps_non_default_action(self):
        rule = {"ref": "r1", "expression": "true", "action": "block"}
        cleaned = _clean_rule(rule, "redirect")
        assert cleaned["action"] == "block"

    def test_keeps_action_when_no_default(self):
        rule = {"ref": "r1", "expression": "true", "action": "block"}
        cleaned = _clean_rule(rule, None)
        assert cleaned["action"] == "block"

    def test_preserves_action_parameters(self):
        rule = {
            "ref": "r1",
            "expression": "true",
            "action": "redirect",
            "action_parameters": {"status_code": 301},
        }
        cleaned = _clean_rule(rule, "redirect")
        assert cleaned["action_parameters"] == {"status_code": 301}

    def test_strips_logging(self):
        rule = {
            "ref": "r1",
            "logging": {"enabled": True},
            "expression": "true",
            "action": "redirect",
        }
        cleaned = _clean_rule(rule, "redirect")
        assert "logging" not in cleaned

    def test_strips_categories(self):
        rule = {
            "ref": "r1",
            "categories": ["security"],
            "expression": "true",
            "action": "block",
        }
        cleaned = _clean_rule(rule, None)
        assert "categories" not in cleaned


class TestDumpZoneRules:
    def test_dump_creates_file(self, tmp_path):
        rules = {
            "http_request_dynamic_redirect": [
                {
                    "id": "abc",
                    "ref": "r1",
                    "expression": "true",
                    "action": "redirect",
                    "enabled": True,
                    "description": "Test redirect",
                    "action_parameters": {"target_url": {"value": "https://example.com"}},
                }
            ],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        assert result is not None
        assert result.exists()
        assert result.name == "example.com.yaml"

        data = yaml.safe_load(result.read_text())
        assert "redirect_rules" in data
        assert len(data["redirect_rules"]) == 1
        # Default action should be stripped
        assert "action" not in data["redirect_rules"][0]
        # API fields should be stripped, but ref preserved
        assert "id" not in data["redirect_rules"][0]
        assert data["redirect_rules"][0]["ref"] == "r1"
        assert result.read_text().startswith("---\n")

    def test_dump_empty_rules(self, tmp_path):
        result = dump_zone_rules("example.com", {}, tmp_path)
        assert result is not None
        assert result.read_text() == "---\n"

    def test_dump_unknown_phase_skipped(self, tmp_path):
        rules = {
            "unknown_phase": [{"ref": "r1", "expression": "true"}],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        assert result is not None
        assert result.read_text() == "---\n"

    def test_dump_creates_output_dir(self, tmp_path):
        output_dir = tmp_path / "sub" / "dir"
        rules = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
        }
        result = dump_zone_rules("example.com", rules, output_dir)
        assert result is not None
        assert output_dir.exists()

    def test_dump_multiple_phases(self, tmp_path):
        rules = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
            "http_request_cache_settings": [
                {
                    "ref": "c1",
                    "expression": "true",
                    "action": "set_cache_settings",
                    "enabled": True,
                }
            ],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        assert result is not None
        data = yaml.safe_load(result.read_text())
        assert "redirect_rules" in data
        assert "cache_rules" in data
        # Default actions should be stripped for both
        assert "action" not in data["redirect_rules"][0]
        assert "action" not in data["cache_rules"][0]

    def test_dump_waf_keeps_action(self, tmp_path):
        """WAF has no default action, so action should be preserved."""
        rules = {
            "http_request_firewall_custom": [
                {"ref": "w1", "expression": "true", "action": "block", "enabled": True}
            ],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        assert result is not None
        data = yaml.safe_load(result.read_text())
        assert "waf_custom_rules" in data
        assert data["waf_custom_rules"][0]["action"] == "block"

    def test_dump_multiple_rules_per_phase(self, tmp_path):
        rules = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "a", "action": "redirect", "enabled": True},
                {"ref": "r2", "expression": "b", "action": "redirect", "enabled": False},
            ],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        assert len(data["redirect_rules"]) == 2

    def test_dump_origin_rule(self, tmp_path):
        """Dump an Origin Rule with host_header routing."""
        rules = {
            "http_request_origin": [
                {
                    "id": "a1b2c3d4e5f6",
                    "version": "3",
                    "last_updated": "2025-06-15T10:30:00Z",
                    "ref": "api-redirect-dev",
                    "description": "Route API calls to API backend",
                    "expression": (
                        '(http.host eq "app.example.com"'
                        ' and starts_with(http.request.uri.path, "/api"))'
                    ),
                    "action": "route",
                    "action_parameters": {
                        "host_header": "api.example.com",
                    },
                    "enabled": True,
                    "logging": {"enabled": False},
                }
            ],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        assert result is not None
        data = yaml.safe_load(result.read_text())

        assert "origin_rules" in data
        rule = data["origin_rules"][0]
        # API fields stripped
        assert "id" not in rule
        assert "version" not in rule
        assert "last_updated" not in rule
        assert "logging" not in rule
        assert rule["ref"] == "api-redirect-dev"  # ref preserved
        # Default action (route) stripped
        assert "action" not in rule
        # User content preserved
        assert rule["description"] == "Route API calls to API backend"
        assert "app.example.com" in rule["expression"]
        assert rule["action_parameters"]["host_header"] == "api.example.com"
        assert rule["enabled"] is True


class TestCFApiResilience:
    """Tests for dumper resilience against Cloudflare API changes."""

    def test_new_unknown_field_preserved_in_dump(self, tmp_path):
        """New fields from CF not in DUMP_STRIP_FIELDS are preserved in dump output."""
        rules = {
            "http_request_dynamic_redirect": [
                {
                    "ref": "r1",
                    "expression": "true",
                    "action": "redirect",
                    "enabled": True,
                    "risk_score": 0.5,
                    "deployment_id": "dep-123",
                }
            ],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        rule = data["redirect_rules"][0]
        # Unknown fields are preserved (not stripped)
        assert rule["risk_score"] == 0.5
        assert rule["deployment_id"] == "dep-123"

    def test_dump_strip_fields_complete(self, tmp_path):
        """All DUMP_STRIP_FIELDS are stripped but ref is preserved."""
        rules = {
            "http_request_dynamic_redirect": [
                {
                    "id": "uuid",
                    "version": "42",
                    "last_updated": "2026-01-01",
                    "categories": ["security", "custom"],
                    "logging": {"enabled": True},
                    "ref": "my-rule",
                    "expression": "true",
                    "action": "redirect",
                    "enabled": True,
                }
            ],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        rule = data["redirect_rules"][0]
        assert "id" not in rule
        assert "version" not in rule
        assert "last_updated" not in rule
        assert "categories" not in rule
        assert "logging" not in rule
        assert rule["ref"] == "my-rule"

    def test_unknown_cf_phase_skipped_in_dump(self, tmp_path):
        """New CF phases not in PHASE_BY_CF are silently skipped during dump."""
        rules = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
            "http_request_new_future_phase": [
                {"ref": "f1", "expression": "true", "action": "new_action", "enabled": True}
            ],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        assert "redirect_rules" in data
        assert "new_future_phase" not in data  # Not in PHASE_BY_CF, so skipped
        assert len(data) == 1

    def test_all_unknown_phases_results_in_empty_dump(self, tmp_path):
        """If all phases from CF are unknown, dump produces an empty --- file."""
        rules = {
            "http_request_unknown_a": [{"ref": "r1", "expression": "true"}],
            "http_request_unknown_b": [{"ref": "r2", "expression": "true"}],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        assert result is not None
        assert result.read_text() == "---\n"

    def test_action_parameters_with_nested_new_fields(self, tmp_path):
        """New nested fields in action_parameters are preserved."""
        rules = {
            "http_request_dynamic_redirect": [
                {
                    "ref": "r1",
                    "expression": "true",
                    "action": "redirect",
                    "enabled": True,
                    "action_parameters": {
                        "from_value": {"target_url": {"value": "https://example.com"}},
                        "status_code": 301,
                        "new_param": {"nested": True},
                    },
                }
            ],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        ap = data["redirect_rules"][0]["action_parameters"]
        assert ap["new_param"] == {"nested": True}
        assert ap["status_code"] == 301

    def test_rule_without_ref_still_dumped(self, tmp_path):
        """CF rules without ref are still included in dump."""
        rules = {
            "http_request_dynamic_redirect": [
                {"expression": "managed-rule", "action": "redirect", "enabled": True},
            ],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        rule = data["redirect_rules"][0]
        assert "ref" not in rule
        assert rule["expression"] == "managed-rule"

    def test_clean_rule_preserves_enabled_false(self):
        """enabled=False from CF is preserved (not stripped as falsy)."""
        rule = {"ref": "r1", "expression": "true", "action": "redirect", "enabled": False}
        cleaned = _clean_rule(rule, "redirect")
        assert cleaned["enabled"] is False

    def test_clean_rule_preserves_empty_string_description(self):
        """Empty string description from CF is preserved."""
        rule = {
            "ref": "r1",
            "expression": "true",
            "action": "redirect",
            "description": "",
        }
        cleaned = _clean_rule(rule, "redirect")
        assert cleaned["description"] == ""

    def test_clean_rule_with_integer_values(self):
        """Integer field values from CF are preserved as-is."""
        rule = {
            "ref": "r1",
            "expression": "true",
            "action": "redirect",
            "action_parameters": {"status_code": 301},
            "position": 5,
        }
        cleaned = _clean_rule(rule, "redirect")
        assert cleaned["action_parameters"]["status_code"] == 301
        assert cleaned["position"] == 5


class TestRoundTripResilience:
    """Round-trip tests with extra/changed CF fields — dump → load → plan = zero changes."""

    def test_round_trip_with_extra_api_fields(self, tmp_path):
        """Extra API-only fields in CF data don't cause round-trip diff."""
        from octorules.planner import plan_zone

        cf_rules = {
            "http_request_dynamic_redirect": [
                {
                    "id": "uuid-123",
                    "version": "42",
                    "last_updated": "2026-02-16T12:00:00Z",
                    "categories": ["custom", "redirect"],
                    "logging": {"enabled": True},
                    "ref": "r1",
                    "expression": "true",
                    "action": "redirect",
                    "enabled": True,
                    "description": "Test rule",
                }
            ],
        }
        result = dump_zone_rules("example.com", cf_rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        zp = plan_zone("example.com", data, cf_rules)
        assert not zp.has_changes

    def test_round_trip_with_new_unknown_field_causes_diff(self, tmp_path):
        """New unknown CF fields ARE dumped, so round-trip matches (no diff).

        When CF adds a new field that's not in DUMP_STRIP_FIELDS, the dump
        preserves it. On re-plan, both desired (from dump) and current have
        the field, so there's no diff. This is the safe path.
        """
        from octorules.planner import plan_zone

        cf_rules = {
            "http_request_dynamic_redirect": [
                {
                    "id": "uuid-123",
                    "ref": "r1",
                    "expression": "true",
                    "action": "redirect",
                    "enabled": True,
                    "risk_score": 0.5,  # New CF field, not in any strip set
                }
            ],
        }
        result = dump_zone_rules("example.com", cf_rules, tmp_path)
        data = yaml.safe_load(result.read_text())

        # The dumped YAML includes risk_score
        assert data["redirect_rules"][0]["risk_score"] == 0.5

        # Re-planning with the dump against the original CF data → no changes
        zp = plan_zone("example.com", data, cf_rules)
        assert not zp.has_changes

    def test_round_trip_waf_with_extra_fields(self, tmp_path):
        """WAF round-trip with extra CF fields works correctly."""
        from octorules.planner import plan_zone

        cf_rules = {
            "http_request_firewall_custom": [
                {
                    "id": "waf-id",
                    "version": "5",
                    "categories": ["waf"],
                    "logging": {"enabled": True},
                    "ref": "w1",
                    "expression": "true",
                    "action": "block",
                    "enabled": True,
                    "last_updated": "2026-01-01",
                }
            ],
        }
        result = dump_zone_rules("example.com", cf_rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        # WAF action preserved (no default)
        assert data["waf_custom_rules"][0]["action"] == "block"
        zp = plan_zone("example.com", data, cf_rules)
        assert not zp.has_changes

    def test_round_trip_multiple_phases_with_extras(self, tmp_path):
        """Multi-phase round-trip with extra fields works correctly."""
        from octorules.planner import plan_zone

        cf_rules = {
            "http_request_dynamic_redirect": [
                {
                    "id": "r-id",
                    "version": "1",
                    "logging": {"enabled": False},
                    "ref": "r1",
                    "expression": "a",
                    "action": "redirect",
                    "enabled": True,
                }
            ],
            "http_request_cache_settings": [
                {
                    "id": "c-id",
                    "version": "2",
                    "categories": [],
                    "ref": "c1",
                    "expression": "b",
                    "action": "set_cache_settings",
                    "enabled": True,
                    "action_parameters": {"cache": True},
                }
            ],
            "http_request_origin": [
                {
                    "id": "o-id",
                    "ref": "o1",
                    "expression": "c",
                    "action": "route",
                    "enabled": True,
                    "action_parameters": {"host_header": "api.example.com"},
                }
            ],
        }
        result = dump_zone_rules("example.com", cf_rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        assert "redirect_rules" in data
        assert "cache_rules" in data
        assert "origin_rules" in data
        zp = plan_zone("example.com", data, cf_rules)
        assert not zp.has_changes, f"Unexpected changes: {zp.phase_plans}"
