"""Tests for custom_rulesets serialization in the dumper."""

from __future__ import annotations

import yaml

from octorules.dumper import dump_zone_rules


class TestDumpCustomRulesets:
    """Tests for custom_rulesets serialization in dump_zone_rules."""

    def test_dump_with_custom_rulesets(self, tmp_path):
        rules = {}
        custom_rulesets = {
            "rs1": {
                "name": "Block attackers",
                "phase": "http_request_firewall_custom",
                "rules": [
                    {"ref": "r1", "expression": "true", "action": "block", "enabled": True},
                    {"ref": "r2", "expression": "false", "action": "log"},
                ],
            }
        }
        result = dump_zone_rules("acct", rules, tmp_path, custom_rulesets=custom_rulesets)
        assert result is not None
        data = yaml.safe_load(result.read_text())
        assert "custom_rulesets" in data
        assert len(data["custom_rulesets"]) == 1
        cr = data["custom_rulesets"][0]
        assert cr["id"] == "rs1"
        assert cr["name"] == "Block attackers"
        assert cr["phase"] == "http_request_firewall_custom"
        assert len(cr["rules"]) == 2
        assert cr["rules"][0]["ref"] == "r1"

    def test_dump_custom_rulesets_sorted_by_name(self, tmp_path):
        custom_rulesets = {
            "rs2": {"name": "Zebra", "phase": "p", "rules": []},
            "rs1": {"name": "Alpha", "phase": "p", "rules": []},
        }
        result = dump_zone_rules("acct", {}, tmp_path, custom_rulesets=custom_rulesets)
        data = yaml.safe_load(result.read_text())
        assert data["custom_rulesets"][0]["name"] == "Alpha"
        assert data["custom_rulesets"][1]["name"] == "Zebra"

    def test_dump_custom_rulesets_ensure_ref_from_id(self, tmp_path):
        """Rules without ref but with id should get ref from id."""
        custom_rulesets = {
            "rs1": {
                "name": "Test",
                "phase": "p",
                "rules": [
                    {"id": "uuid-abc", "expression": "true", "action": "block"},
                ],
            }
        }
        result = dump_zone_rules("acct", {}, tmp_path, custom_rulesets=custom_rulesets)
        data = yaml.safe_load(result.read_text())
        rule = data["custom_rulesets"][0]["rules"][0]
        assert rule["ref"] == "uuid-abc"
        assert "id" not in rule

    def test_dump_custom_rulesets_api_fields_stripped(self, tmp_path):
        custom_rulesets = {
            "rs1": {
                "name": "Test",
                "phase": "p",
                "rules": [
                    {
                        "id": "uuid",
                        "version": "5",
                        "last_updated": "2026-01-01",
                        "ref": "r1",
                        "expression": "true",
                        "action": "block",
                    },
                ],
            }
        }
        result = dump_zone_rules("acct", {}, tmp_path, custom_rulesets=custom_rulesets)
        data = yaml.safe_load(result.read_text())
        rule = data["custom_rulesets"][0]["rules"][0]
        assert "id" not in rule
        assert "version" not in rule
        assert "last_updated" not in rule
        assert rule["ref"] == "r1"

    def test_dump_custom_rulesets_none_no_section(self, tmp_path):
        result = dump_zone_rules("acct", {}, tmp_path, custom_rulesets=None)
        data = yaml.safe_load(result.read_text())
        assert "custom_rulesets" not in (data or {})

    def test_dump_custom_rulesets_empty_no_section(self, tmp_path):
        result = dump_zone_rules("acct", {}, tmp_path, custom_rulesets={})
        data = yaml.safe_load(result.read_text())
        assert "custom_rulesets" not in (data or {})

    def test_dump_with_phase_rules_and_custom_rulesets(self, tmp_path):
        rules = {
            "http_request_firewall_custom": [
                {
                    "ref": "deploy1",
                    "expression": "true",
                    "action": "execute",
                    "action_parameters": {"id": "rs1"},
                    "enabled": True,
                }
            ],
        }
        custom_rulesets = {
            "rs1": {
                "name": "Block attackers",
                "phase": "http_request_firewall_custom",
                "rules": [
                    {"ref": "r1", "expression": "true", "action": "block"},
                ],
            }
        }
        result = dump_zone_rules("acct", rules, tmp_path, custom_rulesets=custom_rulesets)
        data = yaml.safe_load(result.read_text())
        assert "waf_custom_rules" in data
        assert "custom_rulesets" in data

    def test_round_trip_custom_ruleset(self, tmp_path):
        """Dumped custom ruleset should round-trip through diff with no changes."""
        from octorules.planner import diff_custom_ruleset

        cf_rules = [
            {
                "id": "uuid-1",
                "version": "3",
                "ref": "r1",
                "expression": "true",
                "action": "block",
                "enabled": True,
            }
        ]
        custom_rulesets = {
            "rs1": {
                "name": "Block",
                "phase": "http_request_firewall_custom",
                "rules": cf_rules,
            }
        }
        result = dump_zone_rules("acct", {}, tmp_path, custom_rulesets=custom_rulesets)
        data = yaml.safe_load(result.read_text())
        dumped_rules = data["custom_rulesets"][0]["rules"]
        crp = diff_custom_ruleset("rs1", "Block", "p", dumped_rules, cf_rules)
        assert not crp.has_changes
