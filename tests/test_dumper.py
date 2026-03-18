"""Tests for the dumper."""

from __future__ import annotations

import yaml

from octorules.config import _yaml_load
from octorules.dumper import _add_blank_lines, _clean_rule, _ensure_ref, dump_zone_rules


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

    def test_multiline_expression_uses_block_style(self, tmp_path):
        """Multiline expressions with trailing spaces must use YAML block style."""
        expr = (
            '(http.host eq "dev.doctena.fr" and \n'
            '        not http.request.uri.path contains "." and \n'
            '        not starts_with(http.request.uri.path, "/api"))'
        )
        rules = {
            "http_request_transform": [
                {
                    "ref": "r1",
                    "expression": expr,
                    "action": "rewrite",
                    "enabled": True,
                }
            ],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        text = result.read_text()
        # Must use block style (|-), not double-quoted with \n escapes
        assert "|-" in text
        assert "\\n" not in text
        assert '"dev.doctena.fr"' in text
        # Trailing whitespace stripped, round-trip preserves meaning
        data = yaml.safe_load(text)
        dumped_expr = data["url_rewrite_rules"][0]["expression"]
        assert "\n" in dumped_expr
        assert "dev.doctena.fr" in dumped_expr
        # No trailing spaces on any line
        for line in dumped_expr.split("\n"):
            assert line == line.rstrip()

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
        assert result.read_text() == "--- {}\n"

    def test_dump_unknown_phase_skipped(self, tmp_path):
        rules = {
            "unknown_phase": [{"ref": "r1", "expression": "true"}],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        assert result is not None
        assert result.read_text() == "--- {}\n"

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

    def test_unknown_provider_id_skipped_in_dump(self, tmp_path):
        """New provider phases not in PHASE_BY_PROVIDER_ID are silently skipped during dump."""
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
        assert "new_future_phase" not in data  # Not in PHASE_BY_PROVIDER_ID, so skipped
        assert len(data) == 1

    def test_all_unknown_phases_results_in_empty_dump(self, tmp_path):
        """If all phases from CF are unknown, dump produces an empty --- file."""
        rules = {
            "http_request_unknown_a": [{"ref": "r1", "expression": "true"}],
            "http_request_unknown_b": [{"ref": "r2", "expression": "true"}],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        assert result is not None
        assert result.read_text() == "--- {}\n"

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


class TestDumpNewPhases:
    """Tests for dumping rules from newly added phases."""

    def test_dump_bulk_redirect_strips_default_action(self, tmp_path):
        """bulk_redirect_rules has default action 'redirect' — should be stripped."""
        rules = {
            "http_request_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        assert "bulk_redirect_rules" in data
        assert "action" not in data["bulk_redirect_rules"][0]

    def test_dump_log_custom_fields_strips_default_action(self, tmp_path):
        """log_custom_fields has default action 'log_custom_field' — should be stripped."""
        rules = {
            "http_log_custom_fields": [
                {
                    "ref": "lcf1",
                    "expression": "true",
                    "action": "log_custom_field",
                    "action_parameters": {
                        "request_fields": [{"header_name": "X-Custom"}],
                    },
                }
            ],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        assert "log_custom_fields" in data
        assert "action" not in data["log_custom_fields"][0]
        assert data["log_custom_fields"][0]["action_parameters"] is not None

    def test_dump_ddos_l7_keeps_action(self, tmp_path):
        """http_ddos_rules has no default action — action should be preserved."""
        rules = {
            "ddos_l7": [{"ref": "d1", "expression": "true", "action": "managed_challenge"}],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        assert "http_ddos_rules" in data
        assert data["http_ddos_rules"][0]["action"] == "managed_challenge"

    def test_dump_magic_transit_keeps_action(self, tmp_path):
        """network_firewall_rules has no default action — action should be preserved."""
        rules = {
            "magic_transit": [{"ref": "mf1", "expression": "true", "action": "block"}],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        assert "network_firewall_rules" in data
        assert data["network_firewall_rules"][0]["action"] == "block"

    def test_dump_url_normalization_keeps_action(self, tmp_path):
        """url_normalization has no default action — action should be preserved."""
        rules = {
            "http_request_sanitize": [{"ref": "un1", "expression": "true", "action": "rewrite"}],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        assert "url_normalization" in data
        assert data["url_normalization"][0]["action"] == "rewrite"

    def test_dump_network_ddos_keeps_action(self, tmp_path):
        rules = {
            "ddos_l4": [{"ref": "nd1", "expression": "true", "action": "block"}],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        assert "network_ddos_rules" in data
        assert data["network_ddos_rules"][0]["action"] == "block"

    def test_dump_all_new_phases_together(self, tmp_path):
        """All new phases should appear correctly in a combined dump."""
        rules = {
            "ddos_l7": [{"ref": "d1", "expression": "true", "action": "block"}],
            "http_request_redirect": [{"ref": "br1", "expression": "true", "action": "redirect"}],
            "http_log_custom_fields": [
                {"ref": "lcf1", "expression": "true", "action": "log_custom_field"}
            ],
            "ddos_l4": [{"ref": "nd1", "expression": "true", "action": "block"}],
            "magic_transit": [{"ref": "mf1", "expression": "true", "action": "block"}],
            "magic_transit_managed": [{"ref": "mm1", "expression": "true", "action": "execute"}],
            "magic_transit_ratelimit": [{"ref": "mr1", "expression": "true", "action": "block"}],
            "magic_transit_ids_managed": [
                {"ref": "mi1", "expression": "true", "action": "execute"}
            ],
            "http_request_sanitize": [{"ref": "un1", "expression": "true", "action": "rewrite"}],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        assert "http_ddos_rules" in data
        assert "bulk_redirect_rules" in data
        assert "log_custom_fields" in data
        assert "network_ddos_rules" in data
        assert "network_firewall_rules" in data
        assert "network_firewall_managed" in data
        assert "network_firewall_ratelimit" in data
        assert "network_firewall_ids" in data
        assert "url_normalization" in data


class TestAddBlankLines:
    """Tests for the _add_blank_lines post-processor."""

    def test_blank_line_between_sections(self):
        text = "---\nredirect_rules:\n- ref: r1\n  expression: true\ncache_rules:\n- ref: c1\n"
        result = _add_blank_lines(text)
        assert "\n\ncache_rules:" in result

    def test_no_blank_line_after_document_start(self):
        text = "---\nredirect_rules:\n- ref: r1\n"
        result = _add_blank_lines(text)
        assert result.startswith("---\nredirect_rules:")

    def test_blank_line_between_items(self):
        text = "---\nredirect_rules:\n- ref: r1\n  expression: a\n- ref: r2\n  expression: b\n"
        result = _add_blank_lines(text)
        assert "  expression: a\n\n- ref: r2" in result

    def test_no_blank_line_after_section_header(self):
        """First item in a section should NOT get a blank line before it."""
        text = "---\nredirect_rules:\n- ref: r1\n"
        result = _add_blank_lines(text)
        assert "redirect_rules:\n- ref: r1" in result

    def test_nested_list_items_not_separated(self):
        """Indented list items (e.g. rules inside custom_rulesets) should not get blank lines."""
        text = "---\ncustom_rulesets:\n- id: rs1\n  rules:\n  - ref: r1\n  - ref: r2\n"
        result = _add_blank_lines(text)
        # Indented items should remain adjacent
        assert "  - ref: r1\n  - ref: r2" in result

    def test_single_section_single_item(self):
        text = "---\nredirect_rules:\n- ref: r1\n  expression: true\n"
        result = _add_blank_lines(text)
        # No blank lines added — only one section, one item
        assert result == text

    def test_empty_text(self):
        assert _add_blank_lines("") == ""

    def test_preserves_trailing_newline(self):
        text = "---\nredirect_rules:\n- ref: r1\n"
        result = _add_blank_lines(text)
        assert result.endswith("\n")


class TestDumpBlankLineFormatting:
    """Integration tests: dump_zone_rules produces blank lines in output."""

    def test_blank_line_between_phases(self, tmp_path):
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
        text = result.read_text()
        # Blank line between the two sections
        assert "\n\ncache_rules:" in text
        # Still valid YAML
        data = yaml.safe_load(text)
        assert "redirect_rules" in data
        assert "cache_rules" in data

    def test_blank_line_between_rules_in_phase(self, tmp_path):
        rules = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "a", "action": "redirect", "enabled": True},
                {"ref": "r2", "expression": "b", "action": "redirect", "enabled": True},
            ],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        text = result.read_text()
        assert "\n\n- ref: r2" in text
        data = yaml.safe_load(text)
        assert len(data["redirect_rules"]) == 2

    def test_blank_line_between_list_entries(self, tmp_path):
        lists = {
            "list_a": {"kind": "ip", "items": [{"ip": "1.2.3.4"}]},
            "list_b": {"kind": "ip", "items": [{"ip": "5.6.7.8"}]},
        }
        result = dump_zone_rules("example.com", {}, tmp_path, lists=lists)
        text = result.read_text()
        # Externalized list entries use !include at the list level
        assert "\n\n- !include" in text
        data = _yaml_load(result)
        assert len(data["lists"]) == 2

    def test_blank_line_between_custom_rulesets(self, tmp_path):
        custom_rulesets = {
            "rs1": {
                "name": "Alpha",
                "phase": "http_request_firewall_custom",
                "rules": [{"ref": "r1", "expression": "true", "action": "block"}],
            },
            "rs2": {
                "name": "Beta",
                "phase": "http_request_firewall_custom",
                "rules": [{"ref": "r2", "expression": "false", "action": "log"}],
            },
        }
        result = dump_zone_rules("example.com", {}, tmp_path, custom_rulesets=custom_rulesets)
        text = result.read_text()
        assert "\n\n- id: rs2" in text
        data = yaml.safe_load(text)
        assert len(data["custom_rulesets"]) == 2

    def test_blank_line_between_page_shield_policies(self, tmp_path):
        policies = [
            {
                "description": "Alpha",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "x",
            },
            {
                "description": "Beta",
                "action": "log",
                "expression": "true",
                "enabled": True,
                "value": "y",
            },
        ]
        result = dump_zone_rules("example.com", {}, tmp_path, page_shield_policies=policies)
        text = result.read_text()
        assert "\n\n- description: Beta" in text
        data = yaml.safe_load(text)
        assert len(data["page_shield_policies"]) == 2

    def test_full_dump_readability(self, tmp_path):
        """A dump with multiple sections and multiple items is readable."""
        rules = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "a", "action": "redirect", "enabled": True},
                {"ref": "r2", "expression": "b", "action": "redirect", "enabled": True},
            ],
            "http_request_firewall_custom": [
                {"ref": "w1", "expression": "c", "action": "block", "enabled": True},
            ],
        }
        result = dump_zone_rules("example.com", rules, tmp_path)
        text = result.read_text()
        # Blank line between r1 and r2
        assert "\n\n- ref: r2" in text
        # Blank line between redirect_rules section and waf_custom_rules section
        assert "\n\nwaf_custom_rules:" in text
        # Still valid YAML
        data = yaml.safe_load(text)
        assert len(data["redirect_rules"]) == 2
        assert len(data["waf_custom_rules"]) == 1


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

    def test_round_trip_trailing_whitespace_in_expression(self, tmp_path):
        """Trailing whitespace in CF expressions should not cause a round-trip diff.

        Cloudflare's expression builder adds trailing spaces before newlines.
        The dumper strips them (PyYAML requires this for block style), so the
        planner must also normalize when comparing.
        """
        from octorules.planner import plan_zone

        expr_with_trailing = (
            '(http.host eq "dev.doctena.fr" and \n'
            '        not http.request.uri.path contains "." and \n'
            '        not starts_with(http.request.uri.path, "/api"))'
        )
        cf_rules = {
            "http_request_transform": [
                {
                    "id": "uuid-456",
                    "ref": "r1",
                    "expression": expr_with_trailing,
                    "action": "rewrite",
                    "enabled": True,
                }
            ],
        }
        result = dump_zone_rules("example.com", cf_rules, tmp_path)
        data = yaml.safe_load(result.read_text())
        # Dumped expression has trailing spaces stripped
        dumped_expr = data["url_rewrite_rules"][0]["expression"]
        assert "and \n" not in dumped_expr
        # Round-trip should show no changes despite the whitespace difference
        zp = plan_zone("example.com", data, cf_rules)
        assert not zp.has_changes, f"Unexpected changes: {zp.phase_plans}"


class TestDumpErrorPaths:
    """Tests for dump_zone_rules error handling."""

    def test_mkdir_failure(self, tmp_path, monkeypatch):
        """dump_zone_rules returns None when output dir cannot be created."""
        # Create a file where the directory should be, so mkdir fails
        blocker = tmp_path / "output"
        blocker.write_text("not a directory")
        result = dump_zone_rules("example.com", {}, blocker / "sub")
        assert result is None

    def test_path_traversal_zone_name(self, tmp_path):
        """Zone name with path traversal returns None."""
        result = dump_zone_rules("../../../etc/passwd", {}, tmp_path)
        assert result is None

    def test_file_write_oserror(self, tmp_path, monkeypatch):
        """dump_zone_rules returns None when file write fails."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        # Make the output file path a directory so open() fails
        bad_path = output_dir / "example.com.yaml"
        bad_path.mkdir()

        rules = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
        }
        result = dump_zone_rules("example.com", rules, output_dir)
        assert result is None

    def test_list_write_mkdir_failure(self, tmp_path):
        """_write_list_file returns None when lists dir cannot be created."""
        from octorules.dumper import _write_list_file

        # Create a file where the lists directory should be
        blocker = tmp_path / "lists"
        blocker.write_text("not a directory")
        entry = {"name": "mylist", "kind": "ip", "items": []}
        result = _write_list_file(tmp_path, blocker, "mylist", entry)
        assert result is None

    def test_list_write_path_traversal(self, tmp_path):
        """_write_list_file returns None for path-traversal list names."""
        from octorules.dumper import _write_list_file

        lists_dir = tmp_path / "lists"
        result = _write_list_file(tmp_path, lists_dir, "../../etc/passwd", {"name": "bad"})
        assert result is None


class TestEnsureRef:
    """Tests for _ensure_ref helper."""

    def test_has_ref_unchanged(self):
        rule = {"ref": "r1", "id": "uuid", "expression": "true"}
        result = _ensure_ref(rule)
        assert result["ref"] == "r1"
        assert result is rule

    def test_no_ref_copies_id(self):
        rule = {"id": "uuid-123", "expression": "true", "action": "block"}
        result = _ensure_ref(rule)
        assert result["ref"] == "uuid-123"
        assert "ref" not in rule

    def test_no_ref_no_id_unchanged(self):
        rule = {"expression": "true", "action": "block"}
        result = _ensure_ref(rule)
        assert "ref" not in result
        assert result is rule
