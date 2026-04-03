"""Tests for octorules.provider.utils — shared provider helpers."""

from unittest.mock import MagicMock

import pytest

from octorules.provider.exceptions import ProviderAuthError, ProviderError
from octorules.provider.utils import (
    denormalize_fields,
    fetch_parallel,
    normalize_fields,
    to_plain_dict,
)


# ---------------------------------------------------------------------------
# to_plain_dict
# ---------------------------------------------------------------------------
class TestToPlainDict:
    def test_dict_passthrough(self):
        d = {"a": 1}
        assert to_plain_dict(d) is d

    def test_pydantic_v2_model_dump(self):
        obj = MagicMock(spec=["model_dump"])
        obj.model_dump.return_value = {"x": 1}
        assert to_plain_dict(obj) == {"x": 1}
        obj.model_dump.assert_called_once_with(exclude_none=True)

    def test_proto_plus_to_dict(self):
        """proto-plus style: type(obj).to_dict(obj)."""

        class FakeProto:
            @staticmethod
            def to_dict(obj):
                return {"proto": True}

        obj = FakeProto()
        assert to_plain_dict(obj) == {"proto": True}

    def test_to_dict_instance_method_fallback(self):
        """Falls back to instance to_dict if classmethod raises."""

        class Quirky:
            @staticmethod
            def to_dict(obj=None):
                if obj is not None:
                    raise TypeError("no")
                return {"fallback": True}

        obj = Quirky()
        assert to_plain_dict(obj) == {"fallback": True}

    def test_dict_constructor_fallback(self):
        items = [("k", "v")]
        assert to_plain_dict(items) == {"k": "v"}

    def test_unconvertible_raises(self):
        with pytest.raises(ProviderError, match="Cannot convert"):
            to_plain_dict(42)


# ---------------------------------------------------------------------------
# normalize_fields / denormalize_fields
# ---------------------------------------------------------------------------
class TestFieldMapping:
    def test_normalize(self):
        rule = {"Name": "block-bots", "Action": "block", "Priority": 1}
        mapping = {"Name": "ref", "Priority": "priority"}
        result = normalize_fields(rule, mapping)
        assert result == {"ref": "block-bots", "Action": "block", "priority": 1}

    def test_denormalize(self):
        rule = {"ref": "block-bots", "Action": "block", "priority": 1}
        mapping = {"Name": "ref", "Priority": "priority"}
        result = denormalize_fields(rule, mapping)
        assert result == {"Name": "block-bots", "Action": "block", "Priority": 1}

    def test_roundtrip(self):
        mapping = {"Name": "ref", "Priority": "priority"}
        original = {"Name": "r1", "Priority": 5, "Extra": "x"}
        assert denormalize_fields(normalize_fields(original, mapping), mapping) == original

    def test_empty(self):
        assert normalize_fields({}, {"a": "b"}) == {}
        assert denormalize_fields({}, {"a": "b"}) == {}


# ---------------------------------------------------------------------------
# fetch_parallel
# ---------------------------------------------------------------------------
class TestFetchParallel:
    def test_basic(self):
        results, failed = fetch_parallel(
            ["a", "b"],
            submit_fn=lambda ex, item: ex.submit(str.upper, item),
            key_fn=lambda item: item,
            result_fn=lambda item, value: (item, value),
            label="test",
        )
        assert results == {"a": "A", "b": "B"}
        assert failed == []

    def test_empty_items(self):
        results, failed = fetch_parallel(
            [],
            submit_fn=lambda ex, item: ex.submit(lambda: None),
            key_fn=lambda item: item,
            result_fn=lambda item, value: (item, value),
            label="test",
        )
        assert results == {}
        assert failed == []

    def test_transient_error_collected(self):
        def boom(item):
            if item == "bad":
                raise ProviderError("transient")
            return item.upper()

        results, failed = fetch_parallel(
            ["good", "bad"],
            submit_fn=lambda ex, item: ex.submit(boom, item),
            key_fn=lambda item: item,
            result_fn=lambda item, value: (item, value),
            label="test",
        )
        assert "good" in results
        assert "bad" in failed

    def test_auth_error_propagates(self):
        def boom(item):
            raise ProviderAuthError("invalid token")

        with pytest.raises(ProviderAuthError):
            fetch_parallel(
                ["a"],
                submit_fn=lambda ex, item: ex.submit(boom, item),
                key_fn=lambda item: item,
                result_fn=lambda item, value: (item, value),
                label="test",
            )

    def test_result_fn_none_skips(self):
        results, failed = fetch_parallel(
            ["a", "b"],
            submit_fn=lambda ex, item: ex.submit(str.upper, item),
            key_fn=lambda item: item,
            result_fn=lambda item, value: None if item == "b" else (item, value),
            label="test",
        )
        assert results == {"a": "A"}
        assert failed == []
