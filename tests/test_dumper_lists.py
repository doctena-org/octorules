"""Tests for lists serialization in the dumper."""

from __future__ import annotations

import yaml

from octorules.config import _yaml_load
from octorules.dumper import dump_zone_rules


class TestDumpLists:
    """Tests for lists serialization in dump_zone_rules."""

    def test_dump_with_lists(self, tmp_path):
        lists = {
            "blocked_ips": {
                "id": "list-123",
                "kind": "ip",
                "description": "Bad actors",
                "items": [
                    {"ip": "1.2.3.4", "comment": "bad"},
                    {"ip": "5.6.7.8", "comment": "worse"},
                ],
            }
        }
        result = dump_zone_rules("example.com", {}, tmp_path, lists=lists)
        assert result is not None
        data = _yaml_load(result)
        assert "lists" in data
        assert len(data["lists"]) == 1
        entry = data["lists"][0]
        assert entry["name"] == "blocked_ips"
        assert entry["kind"] == "ip"
        assert entry["description"] == "Bad actors"
        assert len(entry["items"]) == 2
        assert entry["items"][0]["ip"] == "1.2.3.4"
        assert entry["items"][0]["comment"] == "bad"

    def test_dump_lists_sorted_by_name(self, tmp_path):
        lists = {
            "zebra_list": {
                "id": "z1",
                "kind": "ip",
                "description": "",
                "items": [{"ip": "9.9.9.9"}],
            },
            "alpha_list": {
                "id": "a1",
                "kind": "ip",
                "description": "",
                "items": [{"ip": "1.1.1.1"}],
            },
        }
        result = dump_zone_rules("example.com", {}, tmp_path, lists=lists)
        data = _yaml_load(result)
        assert data["lists"][0]["name"] == "alpha_list"
        assert data["lists"][1]["name"] == "zebra_list"

    def test_dump_lists_api_fields_stripped(self, tmp_path):
        lists = {
            "my_list": {
                "id": "list-1",
                "kind": "ip",
                "description": "test",
                "items": [
                    {
                        "id": "item-uuid",
                        "created_on": "2026-01-01T00:00:00Z",
                        "modified_on": "2026-02-01T00:00:00Z",
                        "ip": "10.0.0.1",
                        "comment": "internal",
                    },
                ],
            }
        }
        result = dump_zone_rules("example.com", {}, tmp_path, lists=lists)
        data = _yaml_load(result)
        item = data["lists"][0]["items"][0]
        assert "id" not in item
        assert "created_on" not in item
        assert "modified_on" not in item
        assert item["ip"] == "10.0.0.1"
        assert item["comment"] == "internal"

    def test_dump_lists_none_no_section(self, tmp_path):
        result = dump_zone_rules("example.com", {}, tmp_path, lists=None)
        data = yaml.safe_load(result.read_text())
        assert "lists" not in (data or {})

    def test_dump_lists_empty_no_section(self, tmp_path):
        result = dump_zone_rules("example.com", {}, tmp_path, lists={})
        data = yaml.safe_load(result.read_text())
        assert "lists" not in (data or {})

    def test_dump_lists_description_omitted_when_empty(self, tmp_path):
        lists = {
            "my_list": {
                "id": "list-1",
                "kind": "ip",
                "description": "",
                "items": [{"ip": "1.2.3.4"}],
            }
        }
        result = dump_zone_rules("example.com", {}, tmp_path, lists=lists)
        data = _yaml_load(result)
        entry = data["lists"][0]
        assert "description" not in entry

    def test_dump_with_phase_rules_and_lists(self, tmp_path):
        rules = {
            "http_request_firewall_custom": [
                {
                    "ref": "w1",
                    "expression": "true",
                    "action": "block",
                    "enabled": True,
                }
            ],
        }
        lists = {
            "blocked_ips": {
                "id": "list-1",
                "kind": "ip",
                "description": "blocklist",
                "items": [{"ip": "1.2.3.4"}],
            }
        }
        result = dump_zone_rules("example.com", rules, tmp_path, lists=lists)
        data = _yaml_load(result)
        assert "waf_custom_rules" in data
        assert "lists" in data

    def test_round_trip_list(self, tmp_path):
        """Dumped list items should round-trip through diff with no changes."""
        from octorules.planner import diff_list

        cf_items = [
            {
                "id": "item-uuid-1",
                "created_on": "2026-01-01T00:00:00Z",
                "modified_on": "2026-02-01T00:00:00Z",
                "ip": "10.0.0.1",
                "comment": "server A",
            },
            {
                "id": "item-uuid-2",
                "created_on": "2026-01-02T00:00:00Z",
                "modified_on": "2026-02-02T00:00:00Z",
                "ip": "10.0.0.2",
                "comment": "server B",
            },
        ]
        lists = {
            "servers": {
                "id": "list-abc",
                "kind": "ip",
                "description": "Server IPs",
                "items": cf_items,
            }
        }
        result = dump_zone_rules("example.com", {}, tmp_path, lists=lists)
        data = _yaml_load(result)
        dumped_items = data["lists"][0]["items"]
        lp = diff_list(
            "servers",
            "list-abc",
            "ip",
            dumped_items,
            cf_items,
            desired_description="Server IPs",
            current_description="Server IPs",
        )
        assert not lp.has_changes


class TestDumpListsExternalization:
    """Tests for list items being written to separate files via !include."""

    def test_creates_custom_lists_directory(self, tmp_path):
        lists = {
            "my_list": {
                "id": "list-1",
                "kind": "ip",
                "description": "test",
                "items": [{"ip": "1.2.3.4"}],
            }
        }
        dump_zone_rules("example.com", {}, tmp_path, lists=lists)
        assert (tmp_path / "custom_lists").is_dir()
        assert (tmp_path / "custom_lists" / "my_list.yaml").exists()

    def test_external_file_content_has_no_api_fields(self, tmp_path):
        lists = {
            "my_list": {
                "id": "list-1",
                "kind": "ip",
                "description": "test",
                "items": [
                    {
                        "id": "item-uuid",
                        "created_on": "2026-01-01T00:00:00Z",
                        "modified_on": "2026-02-01T00:00:00Z",
                        "ip": "10.0.0.1",
                        "comment": "internal",
                    },
                ],
            }
        }
        dump_zone_rules("example.com", {}, tmp_path, lists=lists)
        items_data = yaml.safe_load((tmp_path / "custom_lists" / "my_list.yaml").read_text())
        assert len(items_data) == 1
        assert "id" not in items_data[0]
        assert "created_on" not in items_data[0]
        assert "modified_on" not in items_data[0]
        assert items_data[0]["ip"] == "10.0.0.1"
        assert items_data[0]["comment"] == "internal"

    def test_empty_items_not_externalized(self, tmp_path):
        lists = {
            "empty_list": {
                "id": "list-1",
                "kind": "ip",
                "description": "empty",
                "items": [],
            }
        }
        result = dump_zone_rules("example.com", {}, tmp_path, lists=lists)
        assert not (tmp_path / "custom_lists").exists()
        data = _yaml_load(result)
        assert data["lists"][0]["items"] == []

    def test_multiple_lists_create_multiple_files(self, tmp_path):
        lists = {
            "list_a": {
                "id": "a1",
                "kind": "ip",
                "description": "",
                "items": [{"ip": "1.1.1.1"}],
            },
            "list_b": {
                "id": "b1",
                "kind": "ip",
                "description": "",
                "items": [{"ip": "2.2.2.2"}],
            },
        }
        dump_zone_rules("example.com", {}, tmp_path, lists=lists)
        assert (tmp_path / "custom_lists" / "list_a.yaml").exists()
        assert (tmp_path / "custom_lists" / "list_b.yaml").exists()

    def test_zone_file_contains_include_tag(self, tmp_path):
        lists = {
            "my_list": {
                "id": "list-1",
                "kind": "ip",
                "description": "test",
                "items": [{"ip": "1.2.3.4"}],
            }
        }
        result = dump_zone_rules("example.com", {}, tmp_path, lists=lists)
        text = result.read_text()
        assert "!include" in text
        assert "custom_lists/my_list.yaml" in text
        # Items should NOT be inlined in the zone file
        assert "1.2.3.4" not in text

    def test_round_trip_via_yaml_load_and_diff(self, tmp_path):
        """Full round-trip: dump -> _yaml_load -> diff_list = no changes."""
        from octorules.planner import diff_list

        cf_items = [
            {
                "id": "item-1",
                "created_on": "2026-01-01T00:00:00Z",
                "modified_on": "2026-02-01T00:00:00Z",
                "ip": "10.0.0.1",
                "comment": "server A",
            },
            {
                "id": "item-2",
                "created_on": "2026-01-02T00:00:00Z",
                "modified_on": "2026-02-02T00:00:00Z",
                "ip": "10.0.0.2",
                "comment": "server B",
            },
        ]
        lists = {
            "servers": {
                "id": "list-abc",
                "kind": "ip",
                "description": "Server IPs",
                "items": cf_items,
            }
        }
        result = dump_zone_rules("example.com", {}, tmp_path, lists=lists)
        data = _yaml_load(result)
        dumped_items = data["lists"][0]["items"]
        lp = diff_list(
            "servers",
            "list-abc",
            "ip",
            dumped_items,
            cf_items,
            desired_description="Server IPs",
            current_description="Server IPs",
        )
        assert not lp.has_changes

    def test_custom_lists_dir_parameter(self, tmp_path):
        """lists_dir controls where item files are written."""
        custom_dir = tmp_path / "my_lists"
        lists = {
            "my_list": {
                "id": "list-1",
                "kind": "ip",
                "description": "test",
                "items": [{"ip": "1.2.3.4"}],
            }
        }
        dump_zone_rules("example.com", {}, tmp_path, lists=lists, lists_dir=custom_dir)
        assert custom_dir.is_dir()
        assert (custom_dir / "my_list.yaml").exists()
        # Default location should NOT exist
        assert not (tmp_path / "custom_lists").exists()

    def test_include_path_relative_to_output_dir(self, tmp_path):
        """!include path in zone file is correct relative to output_dir."""
        custom_dir = tmp_path / "sub" / "lists"
        lists = {
            "my_list": {
                "id": "list-1",
                "kind": "ip",
                "description": "test",
                "items": [{"ip": "1.2.3.4"}],
            }
        }
        result = dump_zone_rules("example.com", {}, tmp_path, lists=lists, lists_dir=custom_dir)
        text = result.read_text()
        assert "!include" in text
        assert "sub/lists/my_list.yaml" in text

    def test_round_trip_with_custom_lists_dir(self, tmp_path):
        """Round-trip works when lists_dir is a subdirectory of output_dir."""
        from octorules.planner import diff_list

        custom_dir = tmp_path / "my_lists"
        cf_items = [
            {
                "id": "item-1",
                "created_on": "2026-01-01T00:00:00Z",
                "modified_on": "2026-02-01T00:00:00Z",
                "ip": "10.0.0.1",
                "comment": "server A",
            },
        ]
        lists = {
            "servers": {
                "id": "list-abc",
                "kind": "ip",
                "description": "Server IPs",
                "items": cf_items,
            }
        }
        result = dump_zone_rules("example.com", {}, tmp_path, lists=lists, lists_dir=custom_dir)
        data = _yaml_load(result)
        dumped_items = data["lists"][0]["items"]
        lp = diff_list(
            "servers",
            "list-abc",
            "ip",
            dumped_items,
            cf_items,
            desired_description="Server IPs",
            current_description="Server IPs",
        )
        assert not lp.has_changes
