"""Tests for the shared provider-linter helpers."""

from octorules.linter.helpers import (
    CATCH_ALL_CIDRS,
    find_duplicate_priorities,
    find_first_priority_gap,
)


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
