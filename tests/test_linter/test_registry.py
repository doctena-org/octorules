"""Tests for the schema registry loader (_registry.py)."""

from __future__ import annotations

from unittest.mock import patch

from octorules.linter.schemas._registry import (
    _build_from_wirefilter,
    _load_fallback,
    _load_overlay,
    load_managed_list_kinds,
    load_managed_lists,
    load_schema,
)


class TestLoadManagedLists:
    def test_returns_frozenset(self):
        result = load_managed_lists()
        assert isinstance(result, frozenset)
        assert len(result) > 0

    def test_contains_known_managed_list(self):
        result = load_managed_lists()
        # All managed lists should have the cf. prefix
        assert all(name.startswith("cf.") for name in result)


class TestLoadManagedListKinds:
    def test_returns_dict(self):
        result = load_managed_list_kinds()
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_ip_kinds_present(self):
        result = load_managed_list_kinds()
        # Managed lists are ip kind
        ip_kinds = [k for k, v in result.items() if v == "ip"]
        assert len(ip_kinds) > 0


class TestLoadSchema:
    def test_returns_dict_with_fields_and_functions(self):
        result = load_schema()
        assert isinstance(result, dict)
        assert "fields" in result
        assert "functions" in result

    def test_fields_have_name_and_type(self):
        result = load_schema()
        for field in result["fields"]:
            assert "name" in field, f"Field missing 'name': {field}"
            assert "type" in field, f"Field {field['name']} missing 'type'"

    def test_functions_have_name(self):
        result = load_schema()
        for func in result["functions"]:
            assert "name" in func, f"Function missing 'name': {func}"


class TestLoadFallback:
    def test_returns_valid_schema(self):
        result = _load_fallback()
        assert isinstance(result, dict)
        assert "fields" in result
        assert "functions" in result
        assert len(result["fields"]) > 0
        assert len(result["functions"]) > 0


class TestErrorPaths:
    def test_load_schema_falls_back_when_wirefilter_unavailable(self):
        """load_schema() uses schemas.json when wirefilter import fails."""
        with patch("octorules.linter.schemas._registry._build_from_wirefilter", return_value=None):
            result = load_schema()
        assert "fields" in result
        assert "functions" in result

    def test_build_from_wirefilter_returns_none_without_wirefilter(self):
        """_build_from_wirefilter() returns None when octorules_wirefilter is missing."""
        with patch.dict("sys.modules", {"octorules_wirefilter": None}):
            result = _build_from_wirefilter()
        assert result is None

    def test_load_overlay_returns_dict(self):
        result = _load_overlay()
        assert isinstance(result, dict)
        assert "fields" in result or "managed_lists" in result

    def test_load_fallback_matches_wirefilter_fields(self):
        """Fallback schemas.json should contain the same fields as wirefilter."""
        fallback = _load_fallback()
        wirefilter = load_schema()
        fallback_names = {f["name"] for f in fallback["fields"]}
        wirefilter_names = {f["name"] for f in wirefilter["fields"]}
        # Fallback may lag behind wirefilter, but should not contain unknown fields
        assert fallback_names <= wirefilter_names, (
            f"Fallback has fields not in wirefilter: {fallback_names - wirefilter_names}"
        )

    def test_load_managed_list_kinds_empty_overlay(self):
        """Returns empty dict when overlay has no managed_lists section."""
        with patch("octorules.linter.schemas._registry._load_overlay", return_value={}):
            result = load_managed_list_kinds()
        assert result == {}

    def test_load_managed_lists_empty_overlay(self):
        """Returns empty frozenset when overlay has no managed_lists section."""
        with patch("octorules.linter.schemas._registry._load_overlay", return_value={}):
            result = load_managed_lists()
        assert result == frozenset()
