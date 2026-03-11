"""Tests for the schema registry loader (_registry.py)."""

from __future__ import annotations

from octorules.linter.schemas._registry import (
    _load_fallback,
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
