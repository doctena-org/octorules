"""Shared mock classes for provider tests."""

from __future__ import annotations


class MockRuleset:
    def __init__(self, rules=None):
        self.rules = rules


class MockRule:
    def __init__(self, data: dict):
        self._data = data

    def model_dump(self, exclude_none=False):
        if exclude_none:
            return {k: v for k, v in self._data.items() if v is not None}
        return dict(self._data)


class MockRuleWithToDict:
    """Mock rule that only has to_dict (no model_dump)."""

    def __init__(self, data: dict):
        self._data = data

    def to_dict(self):
        return dict(self._data)


class MockRuleIterableOnly:
    """Mock rule that is iterable (has __iter__) but no model_dump or to_dict."""

    def __init__(self, data: dict):
        self._data = data

    def __iter__(self):
        return iter(self._data.items())
