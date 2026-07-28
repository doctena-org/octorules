"""Tests for the shared provider-linter helpers."""

import ipaddress

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.linter.helpers import (
    CATCH_ALL_CIDRS,
    count_phase_rules,
    find_duplicate_priorities,
    find_duplicates_by_key,
    find_first_priority_gap,
    find_overlapping_cidrs,
    is_strict_int,
    iter_provider_phases,
    lint_result,
    normalize_host_bits,
)


class TestLintResult:
    def test_builds_lint_result(self):
        r = lint_result("XX100", Severity.ERROR, "boom", "some_phase", "r1", field="f")
        assert isinstance(r, LintResult)
        assert (r.rule_id, r.severity, r.message) == ("XX100", Severity.ERROR, "boom")
        assert (r.phase, r.ref, r.field, r.suggestion) == ("some_phase", "r1", "f", "")


class TestIsStrictInt:
    def test_int_passes(self):
        assert is_strict_int(5)
        assert is_strict_int(0)

    def test_bool_rejected(self):
        assert not is_strict_int(True)
        assert not is_strict_int(False)

    def test_non_int_rejected(self):
        assert not is_strict_int("5")
        assert not is_strict_int(5.0)
        assert not is_strict_int(None)


class TestIterProviderPhases:
    NAMES = frozenset({"alpha_rules", "beta_rules"})

    def test_yields_only_provider_list_phases(self):
        data = {
            "alpha_rules": [{"ref": "a"}],
            "beta_rules": "not-a-list",
            "other_provider_rules": [{"ref": "x"}],
        }
        out = list(iter_provider_phases(data, LintContext(), self.NAMES | {"other"}))
        # beta is non-list, other_provider isn't in phase_names, and
        # names absent from PHASE_BY_NAME are skipped — with conftest's
        # registered phases none of these synthetic names resolve.
        assert out == []

    def test_respects_phase_filter_and_registry(self):
        # Use phases the conftest registers for real.
        data = {"fakeprov.redirect_rules": [{"ref": "a"}], "fakeprov.cache_rules": [{"ref": "b"}]}
        names = frozenset(data)
        assert dict(iter_provider_phases(data, LintContext(), names)) == data
        ctx = LintContext(phase_filter=["fakeprov.cache_rules"])
        assert dict(iter_provider_phases(data, ctx, names)) == {
            "fakeprov.cache_rules": [{"ref": "b"}]
        }

    def test_skip_suffixes(self):
        data = {"fakeprov.redirect_rules": [], "fakeprov.cache_rules": []}
        out = dict(
            iter_provider_phases(data, LintContext(), frozenset(data), skip_suffixes=("_rules",))
        )
        assert out == {}


class TestFindOverlappingCidrs:
    @staticmethod
    def _nets(*values):
        return [(v, ipaddress.ip_network(v)) for v in values]

    def test_contained_range_flagged(self):
        findings = find_overlapping_cidrs(self._nets("10.0.0.0/8", "10.1.2.0/24"))
        assert len(findings) == 1
        val, net, parent_val, parent_net = findings[0]
        assert val == "10.1.2.0/24"
        assert parent_val == "10.0.0.0/8"
        assert net != parent_net

    def test_exact_duplicate_flagged(self):
        findings = find_overlapping_cidrs(
            [("a", ipaddress.ip_network("10.0.0.0/24")), ("b", ipaddress.ip_network("10.0.0.0/24"))]
        )
        assert len(findings) == 1
        _, net, _, parent_net = findings[0]
        assert net == parent_net

    def test_disjoint_ranges_clean(self):
        assert find_overlapping_cidrs(self._nets("10.0.0.0/24", "10.1.0.0/24")) == []

    def test_adjacent_ranges_not_flagged(self):
        # 10.0.0.255 broadcast is directly adjacent to 10.0.1.0 — the sweep
        # must pop the earlier range, not treat adjacency as containment.
        assert find_overlapping_cidrs(self._nets("10.0.0.0/24", "10.0.1.0/24")) == []

    def test_nested_chain_attributes_nearest_parent(self):
        findings = find_overlapping_cidrs(self._nets("10.0.0.0/8", "10.0.0.0/16", "10.0.0.0/24"))
        assert [(f[0], f[2]) for f in findings] == [
            ("10.0.0.0/16", "10.0.0.0/8"),
            ("10.0.0.0/24", "10.0.0.0/16"),
        ]

    def test_mixed_families_never_match(self):
        # v4 and v6 with numerically-overlapping integer addresses.
        findings = find_overlapping_cidrs(self._nets("::/8", "10.0.0.0/8"))
        assert findings == []

    def test_v6_containment(self):
        findings = find_overlapping_cidrs(self._nets("2001:db8::/32", "2001:db8:1::/48"))
        assert [(f[0], f[2]) for f in findings] == [("2001:db8:1::/48", "2001:db8::/32")]


class TestNormalizeHostBits:
    def test_host_bits_set(self):
        assert normalize_host_bits("10.0.0.1/24") == "10.0.0.0/24"

    def test_clean_cidr(self):
        assert normalize_host_bits("10.0.0.0/24") is None

    def test_single_host(self):
        assert normalize_host_bits("10.0.0.1/32") is None

    def test_garbage(self):
        assert normalize_host_bits("not-an-ip") is None


class TestFindDuplicatesByKey:
    def test_groups_only_duplicates(self):
        pairs = [("k1", "a"), ("k2", "b"), ("k1", "c")]
        assert find_duplicates_by_key(pairs) == {"k1": ["a", "c"]}

    def test_empty(self):
        assert find_duplicates_by_key([]) == {}

    def test_preserves_ref_order(self):
        pairs = [("k", 3), ("k", 1), ("k", 2)]
        assert find_duplicates_by_key(pairs) == {"k": [3, 1, 2]}


class TestCountPhaseRules:
    DATA = {
        "alpha": [{"ref": "a"}, {"ref": "b"}, "junk"],
        "beta": [{"ref": "c"}],
        "other": [{"ref": "d"}],
        "gamma": "not-a-list",
    }

    def test_counts_dicts_in_named_phases(self):
        assert count_phase_rules(self.DATA, {"alpha", "beta", "gamma"}) == 3

    def test_exclude(self):
        assert count_phase_rules(self.DATA, {"alpha", "beta"}, exclude={"beta"}) == 2

    def test_raw_lengths(self):
        assert count_phase_rules(self.DATA, {"alpha"}, dict_only=False) == 3


class TestCatchAllCidrs:
    def test_contains_both_ip_versions(self):
        assert "0.0.0.0/0" in CATCH_ALL_CIDRS
        assert "::/0" in CATCH_ALL_CIDRS
        assert len(CATCH_ALL_CIDRS) == 2

    def test_is_immutable(self):
        assert isinstance(CATCH_ALL_CIDRS, frozenset)


class TestFindDuplicatePriorities:
    def test_empty_mapping(self):
        assert find_duplicate_priorities({}) == []

    def test_no_duplicates(self):
        assert find_duplicate_priorities({1: ["a"], 2: ["b"]}) == []

    def test_single_duplicate(self):
        assert find_duplicate_priorities({5: ["a", "b"], 6: ["c"]}) == [(5, ["a", "b"])]

    def test_multiple_duplicates_sorted_by_priority(self):
        seen = {30: ["e", "f"], 10: ["a", "b", "c"], 20: ["d"]}
        assert find_duplicate_priorities(seen) == [
            (10, ["a", "b", "c"]),
            (30, ["e", "f"]),
        ]

    def test_ref_order_preserved(self):
        assert find_duplicate_priorities({1: ["z", "a"]}) == [(1, ["z", "a"])]


class TestFindFirstPriorityGap:
    def test_empty(self):
        assert find_first_priority_gap([]) is None

    def test_single_priority(self):
        assert find_first_priority_gap([7]) is None

    def test_contiguous(self):
        assert find_first_priority_gap([1, 2, 3, 4]) is None

    def test_simple_gap(self):
        assert find_first_priority_gap([1, 2, 5]) == (2, 5)

    def test_only_first_gap_reported(self):
        assert find_first_priority_gap([1, 3, 10]) == (1, 3)

    def test_unsorted_input(self):
        assert find_first_priority_gap([5, 1, 2]) == (2, 5)

    def test_duplicate_values_collapse(self):
        # Duplicates are a different finding (duplicate-priority rules);
        # they must not mask or fabricate a gap.
        assert find_first_priority_gap([1, 1, 2, 2]) is None
        assert find_first_priority_gap([1, 1, 4]) == (1, 4)

    def test_negative_priorities(self):
        assert find_first_priority_gap([-5, -4, -1]) == (-4, -1)
