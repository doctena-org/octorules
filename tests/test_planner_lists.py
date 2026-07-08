"""Tests for the diff engine (planner) – lists."""

import logging

import pytest

from octorules.config import ZoneConfig
from octorules.phases import get_phase
from octorules.planner import (
    ChangeType,
    ListPlan,
    PhasePlan,
    RuleChange,
    RuleValidationError,
    ZonePlan,
    _items_by_identity,
    check_safety,
    check_zone_sections,
    compute_checksum,
    diff_list,
    diff_lists_full,
    normalize_list_item,
    validate_list_entry,
)

REDIRECT_PHASE = get_phase("redirect_rules")
CACHE_PHASE = get_phase("cache_rules")
WAF_PHASE = get_phase("waf_custom_rules")


class TestListPlan:
    """Tests for ListPlan dataclass properties."""

    def test_no_changes_empty(self):
        """Empty ListPlan has no changes."""
        lp = ListPlan(list_name="test", list_id="id1", list_kind="ip")
        assert not lp.has_changes
        assert lp.total_changes == 0

    def test_create_has_changes(self):
        """create=True triggers has_changes."""
        lp = ListPlan(list_name="test", list_id=None, list_kind="ip", create=True)
        assert lp.has_changes
        assert lp.total_changes == 1

    def test_delete_has_changes(self):
        """delete=True triggers has_changes."""
        lp = ListPlan(list_name="test", list_id="id1", list_kind="ip", delete=True)
        assert lp.has_changes
        assert lp.total_changes == 1

    def test_description_change_has_changes(self):
        """description_change set triggers has_changes."""
        lp = ListPlan(
            list_name="test",
            list_id="id1",
            list_kind="ip",
            description_change=("old desc", "new desc"),
        )
        assert lp.has_changes
        assert lp.total_changes == 1

    def test_item_changes_has_changes(self):
        """Item-level changes trigger has_changes."""
        lp = ListPlan(
            list_name="test",
            list_id="id1",
            list_kind="ip",
            changes=[RuleChange(ChangeType.ADD, "10.0.0.1", REDIRECT_PHASE)],
        )
        assert lp.has_changes
        assert lp.total_changes == 1

    def test_total_changes_counting(self):
        """total_changes counts create + delete + description_change + len(changes)."""
        lp = ListPlan(
            list_name="test",
            list_id=None,
            list_kind="ip",
            create=True,
            description_change=(None, "new desc"),
            changes=[
                RuleChange(ChangeType.ADD, "10.0.0.1", REDIRECT_PHASE),
                RuleChange(ChangeType.ADD, "10.0.0.2", REDIRECT_PHASE),
            ],
        )
        # 1 (create) + 1 (description) + 2 (item changes) = 4
        assert lp.total_changes == 4

    def test_total_changes_delete_plus_items(self):
        """delete + item removals counted together."""
        lp = ListPlan(
            list_name="test",
            list_id="id1",
            list_kind="ip",
            delete=True,
            changes=[RuleChange(ChangeType.REMOVE, "10.0.0.1", REDIRECT_PHASE)],
        )
        assert lp.total_changes == 2


class TestValidateListEntry:
    """Tests for validate_list_entry."""

    def test_non_mapping_entry_raises_validation_error(self):
        """Scalar entries raise RuleValidationError, not AttributeError."""
        with pytest.raises(RuleValidationError, match="must be a mapping"):
            validate_list_entry(42, 0)

    def test_non_dict_item_raises_validation_error(self):
        """Bare-string items raise RuleValidationError, not AttributeError."""
        entry = {"name": "blocklist", "kind": "ip", "items": ["10.0.0.0/8"]}
        with pytest.raises(RuleValidationError, match="must be a mapping"):
            validate_list_entry(entry, 0)

    def test_valid_ip_list(self):
        """A valid IP list entry should pass validation."""
        entry = {
            "name": "blocklist",
            "kind": "ip",
            "items": [
                {"ip": "10.0.0.1"},
                {"ip": "192.168.1.0/24"},
            ],
        }
        validate_list_entry(entry, 0)  # Should not raise

    def test_valid_asn_list(self):
        """A valid ASN list entry should pass validation."""
        entry = {
            "name": "asn-block",
            "kind": "asn",
            "items": [
                {"asn": 64512},
                {"asn": 64513},
            ],
        }
        validate_list_entry(entry, 0)  # Should not raise

    def test_missing_name(self):
        entry = {"kind": "ip", "items": []}
        with pytest.raises(RuleValidationError, match="missing required 'name'"):
            validate_list_entry(entry, 0)

    def test_empty_name(self):
        entry = {"name": "", "kind": "ip", "items": []}
        with pytest.raises(RuleValidationError, match="invalid 'name'"):
            validate_list_entry(entry, 0)

    def test_missing_kind(self):
        entry = {"name": "blocklist", "items": []}
        with pytest.raises(RuleValidationError, match="missing required 'kind'"):
            validate_list_entry(entry, 0)

    def test_invalid_kind(self):
        entry = {"name": "blocklist", "kind": "bogus", "items": []}
        with pytest.raises(RuleValidationError, match="invalid 'kind' 'bogus'"):
            validate_list_entry(entry, 0)

    def test_items_not_a_list(self):
        entry = {"name": "blocklist", "kind": "ip", "items": "not-a-list"}
        with pytest.raises(RuleValidationError, match="'items' must be a list"):
            validate_list_entry(entry, 0)

    def test_missing_ip_field(self):
        """IP list item without 'ip' field should fail."""
        entry = {
            "name": "blocklist",
            "kind": "ip",
            "items": [{"comment": "no ip here"}],
        }
        with pytest.raises(RuleValidationError, match="missing required field for kind 'ip'"):
            validate_list_entry(entry, 0)

    def test_missing_asn_field(self):
        """ASN list item without 'asn' field should fail."""
        entry = {
            "name": "asn-block",
            "kind": "asn",
            "items": [{"comment": "no asn here"}],
        }
        with pytest.raises(RuleValidationError, match="missing required field for kind 'asn'"):
            validate_list_entry(entry, 0)

    def test_missing_hostname_field(self):
        """Hostname list item without proper hostname dict should fail."""
        entry = {
            "name": "hosts",
            "kind": "hostname",
            "items": [{"comment": "no hostname"}],
        }
        with pytest.raises(RuleValidationError, match="missing required field for kind 'hostname'"):
            validate_list_entry(entry, 0)

    def test_missing_redirect_field(self):
        """Redirect list item without proper redirect dict should fail."""
        entry = {
            "name": "redirects",
            "kind": "redirect",
            "items": [{"comment": "no redirect"}],
        }
        with pytest.raises(RuleValidationError, match="missing required field for kind 'redirect'"):
            validate_list_entry(entry, 0)

    def test_duplicate_identities(self):
        entry = {
            "name": "blocklist",
            "kind": "ip",
            "items": [
                {"ip": "10.0.0.1"},
                {"ip": "10.0.0.1"},
            ],
        }
        with pytest.raises(RuleValidationError, match="duplicate item '10.0.0.1'"):
            validate_list_entry(entry, 0)

    def test_valid_hostname_list(self):
        entry = {
            "name": "hosts",
            "kind": "hostname",
            "items": [
                {"hostname": {"url_hostname": "example.com"}},
                {"hostname": {"url_hostname": "other.com"}},
            ],
        }
        validate_list_entry(entry, 0)  # Should not raise

    def test_valid_redirect_list(self):
        entry = {
            "name": "redirects",
            "kind": "redirect",
            "items": [
                {"redirect": {"source_url": "example.com/old", "target_url": "example.com/new"}},
            ],
        }
        validate_list_entry(entry, 0)  # Should not raise

    def test_no_items_key_ok(self):
        """Entry without items key should pass (defaults to empty list)."""
        entry = {"name": "empty-list", "kind": "ip"}
        validate_list_entry(entry, 0)  # Should not raise

    def test_error_includes_index(self):
        """Error messages include the list index."""
        entry = {"kind": "ip", "items": []}
        with pytest.raises(RuleValidationError, match=r"lists\[3\]"):
            validate_list_entry(entry, 3)


class TestNormalizeListItem:
    """Tests for normalize_list_item."""

    def test_strips_api_fields(self):
        item = {
            "id": "item-uuid",
            "created_on": "2025-01-01",
            "modified_on": "2025-06-01",
            "ip": "10.0.0.1",
            "comment": "test",
        }
        result = normalize_list_item(item)
        assert "id" not in result
        assert "created_on" not in result
        assert "modified_on" not in result
        assert result["ip"] == "10.0.0.1"
        assert result["comment"] == "test"

    def test_preserves_user_fields(self):
        item = {"ip": "10.0.0.1", "comment": "test"}
        assert normalize_list_item(item) == item

    def test_empty_item(self):
        assert normalize_list_item({}) == {}


class TestDiffList:
    """Tests for diff_list function."""

    def test_no_changes(self):
        """Identical items produce no changes."""
        desired = [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}]
        current = [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}]
        lp = diff_list("blocklist", "id1", "ip", desired, current)
        assert not lp.has_changes
        assert lp.changes == []
        assert lp.prepared_items == desired

    def test_item_addition(self):
        """New item in desired triggers ADD change."""
        desired = [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}]
        current = [{"ip": "10.0.0.1"}]
        lp = diff_list("blocklist", "id1", "ip", desired, current)
        assert lp.has_changes
        adds = [c for c in lp.changes if c.change_type == ChangeType.ADD]
        assert len(adds) == 1
        assert adds[0].ref == "10.0.0.2"

    def test_item_removal(self):
        """Item in current but not desired triggers REMOVE change."""
        desired = [{"ip": "10.0.0.1"}]
        current = [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}]
        lp = diff_list("blocklist", "id1", "ip", desired, current)
        assert lp.has_changes
        removes = [c for c in lp.changes if c.change_type == ChangeType.REMOVE]
        assert len(removes) == 1
        assert removes[0].ref == "10.0.0.2"

    def test_item_modification(self):
        """Same identity but different content triggers MODIFY change."""
        desired = [{"ip": "10.0.0.1", "comment": "updated"}]
        current = [{"ip": "10.0.0.1", "comment": "original"}]
        lp = diff_list("blocklist", "id1", "ip", desired, current)
        assert lp.has_changes
        mods = [c for c in lp.changes if c.change_type == ChangeType.MODIFY]
        assert len(mods) == 1
        assert mods[0].ref == "10.0.0.1"

    def test_api_fields_ignored_in_item_comparison(self):
        """API-injected fields on current items should be stripped for comparison."""
        desired = [{"ip": "10.0.0.1", "comment": "test"}]
        current = [
            {
                "id": "item-uuid",
                "created_on": "2025-01-01",
                "modified_on": "2025-06-01",
                "ip": "10.0.0.1",
                "comment": "test",
            }
        ]
        lp = diff_list("blocklist", "id1", "ip", desired, current)
        assert not lp.has_changes

    def test_description_change(self):
        """Different descriptions produce a description_change."""
        desired = [{"ip": "10.0.0.1"}]
        current = [{"ip": "10.0.0.1"}]
        lp = diff_list(
            "blocklist",
            "id1",
            "ip",
            desired,
            current,
            desired_description="new desc",
            current_description="old desc",
        )
        assert lp.has_changes
        assert lp.description_change == ("old desc", "new desc")

    def test_no_description_change_when_same(self):
        """Same descriptions produce no description_change."""
        desired = [{"ip": "10.0.0.1"}]
        current = [{"ip": "10.0.0.1"}]
        lp = diff_list(
            "blocklist",
            "id1",
            "ip",
            desired,
            current,
            desired_description="same",
            current_description="same",
        )
        assert lp.description_change is None

    def test_create_new_list(self):
        """list_id=None triggers create=True with all items as ADD."""
        desired = [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}]
        lp = diff_list("blocklist", None, "ip", desired, [])
        assert lp.create is True
        assert lp.has_changes
        adds = [c for c in lp.changes if c.change_type == ChangeType.ADD]
        assert len(adds) == 2
        refs = {c.ref for c in adds}
        assert refs == {"10.0.0.1", "10.0.0.2"}

    def test_create_with_description(self):
        """Creating a new list with a description sets description_change."""
        lp = diff_list(
            "blocklist",
            None,
            "ip",
            [{"ip": "10.0.0.1"}],
            [],
            desired_description="My list",
        )
        assert lp.create is True
        assert lp.description_change == (None, "My list")

    def test_create_without_description(self):
        """Creating a new list without a description has no description_change."""
        lp = diff_list("blocklist", None, "ip", [{"ip": "10.0.0.1"}], [])
        assert lp.create is True
        assert lp.description_change is None

    def test_prepared_items_populated(self):
        """prepared_items should always be set to the desired items."""
        desired = [{"ip": "10.0.0.1"}]
        current = [{"ip": "10.0.0.2"}]
        lp = diff_list("blocklist", "id1", "ip", desired, current)
        assert lp.prepared_items == desired

    def test_prepared_items_on_create(self):
        """prepared_items should be set even on create."""
        desired = [{"ip": "10.0.0.1"}]
        lp = diff_list("blocklist", None, "ip", desired, [])
        assert lp.prepared_items == desired

    def test_asn_diff(self):
        """Diff works for ASN-type lists."""
        desired = [{"asn": 64512}, {"asn": 64513}]
        current = [{"asn": 64512}]
        lp = diff_list("asn-block", "id1", "asn", desired, current)
        assert lp.has_changes
        adds = [c for c in lp.changes if c.change_type == ChangeType.ADD]
        assert len(adds) == 1
        assert adds[0].ref == "64513"

    def test_hostname_diff(self):
        """Diff works for hostname-type lists."""
        desired = [{"hostname": {"url_hostname": "example.com"}}]
        current = [{"hostname": {"url_hostname": "old.com"}}]
        lp = diff_list("hosts", "id1", "hostname", desired, current)
        adds = [c for c in lp.changes if c.change_type == ChangeType.ADD]
        removes = [c for c in lp.changes if c.change_type == ChangeType.REMOVE]
        assert len(adds) == 1
        assert adds[0].ref == "example.com"
        assert len(removes) == 1
        assert removes[0].ref == "old.com"

    def test_redirect_diff(self):
        """Diff works for redirect-type lists."""
        desired = [{"redirect": {"source_url": "example.com/old", "target_url": "example.com/new"}}]
        lp = diff_list("redirects", None, "redirect", desired, [])
        assert lp.create is True
        adds = [c for c in lp.changes if c.change_type == ChangeType.ADD]
        assert len(adds) == 1
        assert adds[0].ref == "example.com/old"

    def test_synthetic_phase_name(self):
        """Changes should use a synthetic phase with the list name."""
        desired = [{"ip": "10.0.0.1"}]
        lp = diff_list("blocklist", None, "ip", desired, [])
        assert lp.changes[0].phase.friendly_name == "list:blocklist"
        assert lp.changes[0].phase.provider_id == "account_lists"

    def test_modify_has_cached_normalized(self):
        """MODIFY changes on list items should have pre-populated normalized values."""
        desired = [{"ip": "10.0.0.1", "comment": "updated"}]
        current = [{"ip": "10.0.0.1", "comment": "original"}]
        lp = diff_list("blocklist", "id1", "ip", desired, current)
        mods = [c for c in lp.changes if c.change_type == ChangeType.MODIFY]
        assert len(mods) == 1
        assert "normalized_current" in mods[0].__dict__
        assert "normalized_desired" in mods[0].__dict__

    def test_create_add_no_logging_in_normalized(self):
        """ADD changes on a CREATE use the list-item normalizer, not the rule
        normalizer, so they must not gain a spurious ``logging`` block."""
        lp = diff_list("blocklist", None, "ip", [{"ip": "10.0.0.1"}], [])
        add = next(c for c in lp.changes if c.change_type == ChangeType.ADD)
        # Pre-seeded (so the rule normalizer never runs on first access)...
        assert "normalized_desired" in add.__dict__
        # ...and free of the rule-only logging default.
        assert "logging" not in add.normalized_desired
        assert add.normalized_desired == {"ip": "10.0.0.1"}

    def test_item_add_remove_no_logging_in_normalized(self):
        """Adding/removing items on an EXISTING list must also avoid the
        rule-logging default on the per-item normalized values."""
        desired = [{"ip": "10.0.0.2"}]
        current = [{"ip": "10.0.0.1"}]
        lp = diff_list("blocklist", "id1", "ip", desired, current)
        add = next(c for c in lp.changes if c.change_type == ChangeType.ADD)
        remove = next(c for c in lp.changes if c.change_type == ChangeType.REMOVE)
        assert "logging" not in add.normalized_desired
        assert "logging" not in remove.normalized_current
        assert add.normalized_desired == {"ip": "10.0.0.2"}
        assert remove.normalized_current == {"ip": "10.0.0.1"}

    def test_description_change_none_to_value(self):
        """Adding description where none existed before."""
        lp = diff_list(
            "blocklist",
            "id1",
            "ip",
            [],
            [],
            desired_description="new",
            current_description=None,
        )
        assert lp.description_change == (None, "new")

    def test_description_change_value_to_none(self):
        """Removing description."""
        lp = diff_list(
            "blocklist",
            "id1",
            "ip",
            [],
            [],
            desired_description=None,
            current_description="old",
        )
        assert lp.description_change == ("old", None)

    def test_description_both_none_no_change(self):
        """Both descriptions None means no change."""
        lp = diff_list(
            "blocklist",
            "id1",
            "ip",
            [],
            [],
            desired_description=None,
            current_description=None,
        )
        assert lp.description_change is None


class TestDiffListsFull:
    """Tests for diff_lists_full function."""

    def test_no_changes(self):
        """Identical desired and current produce no plans."""
        desired = [{"name": "blocklist", "kind": "ip", "items": [{"ip": "10.0.0.1"}]}]
        current = {
            "blocklist": {
                "id": "id1",
                "kind": "ip",
                "items": [{"ip": "10.0.0.1"}],
            }
        }
        plans = diff_lists_full(desired, current)
        assert plans == []

    def test_create_new_list(self):
        """A list in desired but not current should produce a create plan."""
        desired = [
            {
                "name": "blocklist",
                "kind": "ip",
                "items": [{"ip": "10.0.0.1"}],
                "description": "My blocklist",
            }
        ]
        current = {}
        plans = diff_lists_full(desired, current)
        assert len(plans) == 1
        assert plans[0].list_name == "blocklist"
        assert plans[0].create is True
        assert plans[0].list_id is None
        assert plans[0].description_change == (None, "My blocklist")
        adds = [c for c in plans[0].changes if c.change_type == ChangeType.ADD]
        assert len(adds) == 1

    def test_delete_existing_list(self):
        """A list in current but not desired should produce a delete plan."""
        desired = []
        current = {
            "old-list": {
                "id": "id1",
                "kind": "ip",
                "items": [{"ip": "10.0.0.1"}],
            }
        }
        plans = diff_lists_full(desired, current)
        assert len(plans) == 1
        assert plans[0].list_name == "old-list"
        assert plans[0].delete is True
        assert plans[0].list_id == "id1"

    def test_mixed_changes(self):
        """Create, update, and delete in one call."""
        desired = [
            {
                "name": "new-list",
                "kind": "ip",
                "items": [{"ip": "10.0.0.1"}],
            },
            {
                "name": "existing-list",
                "kind": "ip",
                "items": [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}],
            },
        ]
        current = {
            "existing-list": {
                "id": "id2",
                "kind": "ip",
                "items": [{"ip": "10.0.0.1"}],
            },
            "removed-list": {
                "id": "id3",
                "kind": "ip",
                "items": [],
            },
        }
        plans = diff_lists_full(desired, current)
        names = {lp.list_name for lp in plans}
        assert "new-list" in names
        assert "existing-list" in names
        assert "removed-list" in names

        new_plan = next(lp for lp in plans if lp.list_name == "new-list")
        assert new_plan.create is True

        existing_plan = next(lp for lp in plans if lp.list_name == "existing-list")
        assert not existing_plan.create
        assert not existing_plan.delete
        adds = [c for c in existing_plan.changes if c.change_type == ChangeType.ADD]
        assert len(adds) == 1

        removed_plan = next(lp for lp in plans if lp.list_name == "removed-list")
        assert removed_plan.delete is True

    def test_existing_no_changes_excluded(self):
        """Existing list with no changes should NOT appear in plans."""
        desired = [{"name": "blocklist", "kind": "ip", "items": [{"ip": "10.0.0.1"}]}]
        current = {
            "blocklist": {
                "id": "id1",
                "kind": "ip",
                "items": [{"ip": "10.0.0.1"}],
            }
        }
        plans = diff_lists_full(desired, current)
        assert len(plans) == 0

    def test_description_change_included(self):
        """Description change on existing list should be included."""
        desired = [
            {
                "name": "blocklist",
                "kind": "ip",
                "items": [{"ip": "10.0.0.1"}],
                "description": "updated desc",
            }
        ]
        current = {
            "blocklist": {
                "id": "id1",
                "kind": "ip",
                "items": [{"ip": "10.0.0.1"}],
                "description": "old desc",
            }
        }
        plans = diff_lists_full(desired, current)
        assert len(plans) == 1
        assert plans[0].description_change == ("old desc", "updated desc")


class TestZonePlanWithLists:
    """Tests for ZonePlan including list plans."""

    def test_has_changes_with_list_plans_only(self):
        """ZonePlan with only list_plans should report has_changes."""
        lp = ListPlan(
            list_name="blocklist",
            list_id=None,
            list_kind="ip",
            create=True,
            changes=[RuleChange(ChangeType.ADD, "10.0.0.1", REDIRECT_PHASE)],
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        assert zp.has_changes

    def test_no_changes_empty_list_plans(self):
        """ZonePlan with empty list_plans list should not report has_changes."""
        zp = ZonePlan(zone_name="test.com", list_plans=[])
        assert not zp.has_changes

    def test_no_changes_unchanged_list_plan(self):
        """ZonePlan with a list_plan that has no changes should not report has_changes."""
        lp = ListPlan(list_name="blocklist", list_id="id1", list_kind="ip")
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        assert not zp.has_changes

    def test_total_changes_includes_list_plans(self):
        """total_changes should include list plan changes."""
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        lp = ListPlan(
            list_name="blocklist",
            list_id=None,
            list_kind="ip",
            create=True,
            description_change=(None, "desc"),
            changes=[
                RuleChange(ChangeType.ADD, "10.0.0.1", REDIRECT_PHASE),
                RuleChange(ChangeType.ADD, "10.0.0.2", REDIRECT_PHASE),
            ],
        )
        zp = ZonePlan(
            zone_name="test.com",
            phase_plans=[pp],
            list_plans=[lp],
        )
        # 1 (phase) + 1 (create) + 1 (desc) + 2 (items) = 5
        assert zp.total_changes == 5

    def test_total_changes_multiple_list_plans(self):
        """total_changes sums across multiple list plans."""
        lp1 = ListPlan(
            list_name="list-a",
            list_id=None,
            list_kind="ip",
            create=True,
        )
        lp2 = ListPlan(
            list_name="list-b",
            list_id="id2",
            list_kind="ip",
            delete=True,
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp1, lp2])
        assert zp.total_changes == 2


class TestComputeChecksumWithLists:
    """Tests for checksum including list plans."""

    def test_checksum_includes_lists(self):
        """Checksum should be valid when list plans are present."""
        lp = ListPlan(
            list_name="blocklist",
            list_id=None,
            list_kind="ip",
            create=True,
            changes=[
                RuleChange(ChangeType.ADD, "10.0.0.1", REDIRECT_PHASE, desired={"ip": "10.0.0.1"}),
            ],
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        h = compute_checksum([zp])
        assert len(h) == 64

    def test_checksum_differs_with_lists(self):
        """Different list plans produce different checksums."""
        lp1 = ListPlan(
            list_name="blocklist",
            list_id=None,
            list_kind="ip",
            create=True,
            changes=[
                RuleChange(ChangeType.ADD, "10.0.0.1", REDIRECT_PHASE, desired={"ip": "10.0.0.1"}),
            ],
        )
        lp2 = ListPlan(
            list_name="blocklist",
            list_id=None,
            list_kind="ip",
            create=True,
            changes=[
                RuleChange(ChangeType.ADD, "10.0.0.2", REDIRECT_PHASE, desired={"ip": "10.0.0.2"}),
            ],
        )
        zp1 = ZonePlan(zone_name="test.com", list_plans=[lp1])
        zp2 = ZonePlan(zone_name="test.com", list_plans=[lp2])
        assert compute_checksum([zp1]) != compute_checksum([zp2])

    def test_checksum_deterministic_with_lists(self):
        """Same list plan produces same checksum each time."""
        lp = ListPlan(
            list_name="blocklist",
            list_id="id1",
            list_kind="ip",
            description_change=("old", "new"),
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        assert compute_checksum([zp]) == compute_checksum([zp])

    def test_checksum_list_order_irrelevant(self):
        """Checksum should be the same regardless of list plan order."""
        lp1 = ListPlan(list_name="a-list", list_id="id1", list_kind="ip", delete=True)
        lp2 = ListPlan(list_name="b-list", list_id="id2", list_kind="ip", delete=True)
        zp1 = ZonePlan(zone_name="test.com", list_plans=[lp1, lp2])
        zp2 = ZonePlan(zone_name="test.com", list_plans=[lp2, lp1])
        assert compute_checksum([zp1]) == compute_checksum([zp2])

    def test_checksum_with_description_change(self):
        """Checksum should include description_change data."""
        lp_with = ListPlan(
            list_name="blocklist",
            list_id="id1",
            list_kind="ip",
            description_change=("old", "new"),
        )
        lp_without = ListPlan(
            list_name="blocklist",
            list_id="id1",
            list_kind="ip",
        )
        zp_with = ZonePlan(zone_name="test.com", list_plans=[lp_with])
        zp_without = ZonePlan(zone_name="test.com", list_plans=[lp_without])
        assert compute_checksum([zp_with]) != compute_checksum([zp_without])


class TestCheckSafetyWithLists:
    """Tests for safety checks including list changes."""

    def _zone_cfg(self, delete_threshold=30.0, update_threshold=30.0, min_existing=3):
        return ZoneConfig(
            name="test.com",
            zone_id="z1",
            sources=["rules"],
            delete_threshold=delete_threshold,
            update_threshold=update_threshold,
            min_existing=min_existing,
        )

    def test_list_delete_counted(self):
        """List delete=True should be counted as a delete in safety checks."""
        lp = ListPlan(
            list_name="blocklist",
            list_id="id1",
            list_kind="ip",
            delete=True,
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        # Need enough existing rules to be above min_existing
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(3)]}
        violations = check_safety(zp, current, self._zone_cfg(delete_threshold=30.0))
        assert len(violations) == 1
        assert violations[0].kind == "delete"
        assert "list:blocklist" in violations[0].phases

    def test_list_item_removals_counted(self):
        """Item REMOVE changes in a list should count toward delete totals."""
        from octorules.planner import _make_list_phase

        phase = _make_list_phase("blocklist")
        changes = [RuleChange(ChangeType.REMOVE, f"10.0.0.{i}", phase) for i in range(4)]
        lp = ListPlan(
            list_name="blocklist",
            list_id="id1",
            list_kind="ip",
            changes=changes,
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(10)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert len(violations) == 1
        assert violations[0].kind == "delete"
        assert violations[0].count == 4
        assert "list:blocklist" in violations[0].phases

    def test_list_item_modifications_counted(self):
        """Item MODIFY changes in a list should count toward update totals."""
        from octorules.planner import _make_list_phase

        phase = _make_list_phase("blocklist")
        changes = [RuleChange(ChangeType.MODIFY, f"10.0.0.{i}", phase) for i in range(4)]
        lp = ListPlan(
            list_name="blocklist",
            list_id="id1",
            list_kind="ip",
            changes=changes,
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(10)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert len(violations) == 1
        assert violations[0].kind == "update"
        assert violations[0].count == 4
        assert "list:blocklist" in violations[0].phases

    def test_list_add_no_violation(self):
        """ADD changes in a list should not trigger safety violations."""
        from octorules.planner import _make_list_phase

        phase = _make_list_phase("blocklist")
        changes = [RuleChange(ChangeType.ADD, f"10.0.0.{i}", phase) for i in range(5)]
        lp = ListPlan(
            list_name="blocklist",
            list_id="id1",
            list_kind="ip",
            changes=changes,
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(5)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert violations == []

    def test_list_and_phase_changes_combined(self):
        """List and phase changes should be summed together for safety checks."""
        from octorules.planner import _make_list_phase

        phase = _make_list_phase("blocklist")
        # 2 phase deletes + 2 list deletes = 4 total out of 10 = 40%
        phase_changes = [RuleChange(ChangeType.REMOVE, f"r{i}", REDIRECT_PHASE) for i in range(2)]
        pp = PhasePlan(phase=REDIRECT_PHASE, changes=phase_changes)
        list_changes = [RuleChange(ChangeType.REMOVE, f"10.0.0.{i}", phase) for i in range(2)]
        lp = ListPlan(
            list_name="blocklist",
            list_id="id1",
            list_kind="ip",
            changes=list_changes,
        )
        zp = ZonePlan(zone_name="test.com", phase_plans=[pp], list_plans=[lp])
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(10)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert len(violations) == 1
        assert violations[0].kind == "delete"
        assert violations[0].count == 4
        assert "redirect_rules" in violations[0].phases
        assert "list:blocklist" in violations[0].phases


class TestWarnUnknownPhaseKeysLists:
    """Test that 'lists' key does not trigger unknown phase warning."""

    def test_lists_not_warned(self, caplog):
        """The 'lists' key should be recognized as a non-phase key."""
        rules_data = {"redirect_rules": [], "lists": []}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            check_zone_sections(rules_data, "account")
        assert "lists" not in caplog.text

    def test_lists_and_custom_rulesets_not_warned(self, caplog):
        """Both 'lists' and 'custom_rulesets' should be recognized."""
        rules_data = {"redirect_rules": [], "lists": [], "custom_rulesets": []}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            check_zone_sections(rules_data, "account")
        assert "lists" not in caplog.text
        assert "custom_rulesets" not in caplog.text

    def test_lists_with_unknown_still_warned(self, caplog):
        """Unknown keys should still be warned even when 'lists' is present."""
        rules_data = {"lists": [], "bogus_phase": []}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            check_zone_sections(rules_data, "account")
        assert "lists" not in caplog.text
        assert "bogus_phase" in caplog.text


class TestItemsByIdentity:
    """Tests for _items_by_identity helper."""

    def test_ip_items_indexed(self):
        items = [{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}]
        result = _items_by_identity(items, "ip")
        assert result == {"1.2.3.4": {"ip": "1.2.3.4"}, "5.6.7.8": {"ip": "5.6.7.8"}}

    def test_empty_identity_skipped_with_warning(self, caplog):
        """Items with empty identity keys should be skipped and a warning logged."""
        items = [{"ip": "1.2.3.4"}, {"wrong_field": "value"}]
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = _items_by_identity(items, "ip")
        assert len(result) == 1
        assert "1.2.3.4" in result
        assert "empty identity key" in caplog.text

    def test_hostname_items_indexed(self):
        items = [
            {"hostname": {"url_hostname": "example.com"}},
            {"hostname": {"url_hostname": "other.com"}},
        ]
        result = _items_by_identity(items, "hostname")
        assert "example.com" in result
        assert "other.com" in result

    def test_duplicate_identity_warns(self, caplog):
        """Duplicate identity keys should log a warning."""
        items = [{"ip": "1.2.3.4", "comment": "first"}, {"ip": "1.2.3.4", "comment": "second"}]
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = _items_by_identity(items, "ip")
        assert len(result) == 1
        assert result["1.2.3.4"]["comment"] == "second"
        assert "Duplicate list item identity" in caplog.text


class TestItemIdentity:
    """Tests for _item_identity helper."""

    def test_asn_none_returns_empty(self):
        """ASN with None value should return empty string, not 'None'."""
        from octorules.planner import _item_identity

        assert _item_identity({"asn": None}, "asn") == ""

    def test_asn_missing_returns_empty(self):
        from octorules.planner import _item_identity

        assert _item_identity({}, "asn") == ""

    def test_asn_int_returns_string(self):
        from octorules.planner import _item_identity

        assert _item_identity({"asn": 64512}, "asn") == "64512"

    def test_asn_string_returns_string(self):
        from octorules.planner import _item_identity

        assert _item_identity({"asn": "64512"}, "asn") == "64512"
