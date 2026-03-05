"""Tests for the field scheme generator script."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Add scripts dir so we can import the module
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from generate_fields import (
    FieldEntry,
    classify_field,
    generate_python_fields,
    generate_rust_fields,
    load_fields,
    replace_between_sentinels,
)


class TestClassifyField:
    def test_string_type(self):
        entry = {"name": "http.host", "data_type": "String", "categories": []}
        fe = classify_field(entry)
        assert fe is not None
        assert fe.rust_type == "Type::Bytes"
        assert fe.py_type == "FieldType.STRING"

    def test_integer_type(self):
        entry = {"name": "cf.threat_score", "data_type": "Integer", "categories": []}
        fe = classify_field(entry)
        assert fe is not None
        assert fe.rust_type == "Type::Int"
        assert fe.py_type == "FieldType.INT"

    def test_number_type(self):
        entry = {"name": "cf.waf.score", "data_type": "Number", "categories": []}
        fe = classify_field(entry)
        assert fe is not None
        assert fe.rust_type == "Type::Int"
        assert fe.py_type == "FieldType.INT"

    def test_boolean_type(self):
        entry = {"name": "ssl", "data_type": "Boolean", "categories": []}
        fe = classify_field(entry)
        assert fe is not None
        assert fe.rust_type == "Type::Bool"
        assert fe.py_type == "FieldType.BOOL"

    def test_ip_address_type(self):
        entry = {"name": "ip.src", "data_type": "IP address", "categories": []}
        fe = classify_field(entry)
        assert fe is not None
        assert fe.rust_type == "Type::Ip"
        assert fe.py_type == "FieldType.IP"

    def test_bytes_type(self):
        entry = {"name": "cf.random_seed", "data_type": "Bytes", "categories": []}
        fe = classify_field(entry)
        assert fe is not None
        assert fe.rust_type == "Type::Bytes"
        assert fe.py_type == "FieldType.BYTES"

    def test_array_string_type(self):
        entry = {
            "name": "http.request.headers.names",
            "data_type": "Array<String>",
            "categories": [],
        }
        fe = classify_field(entry)
        assert fe is not None
        assert fe.rust_type == "Type::Array(Type::Bytes.into())"
        assert fe.py_type == "FieldType.ARRAY_STRING"

    def test_array_integer_type(self):
        entry = {
            "name": "cf.bot_management.detection_ids",
            "data_type": "Array<Integer>",
            "categories": [],
        }
        fe = classify_field(entry)
        assert fe is not None
        assert fe.rust_type == "Type::Array(Type::Int.into())"
        assert fe.py_type == "FieldType.ARRAY_INT"

    def test_map_array_string_type(self):
        entry = {
            "name": "http.request.headers",
            "data_type": "Map<Array<String>>",
            "categories": [],
        }
        fe = classify_field(entry)
        assert fe is not None
        assert fe.rust_type == "Type::Map(Type::Array(Type::Bytes.into()).into())"
        assert fe.py_type == "FieldType.MAP_ARRAY_STRING"

    def test_map_array_integer_type(self):
        entry = {
            "name": "http.request.jwt.claims.iat.sec",
            "data_type": "Map<Array<Integer>>",
            "categories": [],
        }
        fe = classify_field(entry)
        assert fe is not None
        assert fe.py_type == "FieldType.MAP_ARRAY_INT"

    def test_array_array_string_type(self):
        entry = {
            "name": "http.request.body.multipart.names",
            "data_type": "Array<Array<String>>",
            "categories": [],
        }
        fe = classify_field(entry)
        assert fe is not None
        assert fe.py_type == "FieldType.ARRAY_ARRAY_STRING"

    def test_unknown_type_returns_none(self):
        entry = {"name": "unknown", "data_type": "SomeNewType", "categories": []}
        assert classify_field(entry) is None

    def test_response_category(self):
        entry = {
            "name": "http.response.code",
            "data_type": "Integer",
            "categories": ["Response"],
        }
        fe = classify_field(entry)
        assert fe is not None
        assert fe.is_response is True

    def test_enterprise_plan(self):
        entry = {
            "name": "cf.waf.score",
            "data_type": "Integer",
            "categories": [],
            "plan_info_label": "Enterprise",
        }
        fe = classify_field(entry)
        assert fe is not None
        assert fe.requires_plan == "enterprise"

    def test_pro_plan(self):
        entry = {
            "name": "http.request.cookies",
            "data_type": "Map<Array<String>>",
            "categories": [],
            "plan_info_label": "Pro or above",
        }
        fe = classify_field(entry)
        assert fe is not None
        assert fe.requires_plan == "pro"

    def test_no_plan(self):
        entry = {"name": "http.host", "data_type": "String", "categories": []}
        fe = classify_field(entry)
        assert fe is not None
        assert fe.requires_plan == ""


class TestGenerateRustFields:
    def test_output_format(self):
        fields = [
            FieldEntry("http.host", "Type::Bytes", "FieldType.STRING"),
            FieldEntry("ip.src", "Type::Ip", "FieldType.IP"),
        ]
        result = generate_rust_fields(fields)
        assert '    b.add_field("http.host", Type::Bytes).unwrap();' in result
        assert '    b.add_field("ip.src", Type::Ip).unwrap();' in result

    def test_empty(self):
        assert generate_rust_fields([]) == ""


class TestGeneratePythonFields:
    def test_basic_field(self):
        fields = [FieldEntry("http.host", "Type::Bytes", "FieldType.STRING")]
        result = generate_python_fields(fields)
        assert '_f("http.host", FieldType.STRING)' in result

    def test_response_field(self):
        fields = [FieldEntry("http.response.code", "Type::Int", "FieldType.INT", is_response=True)]
        result = generate_python_fields(fields)
        assert '_f("http.response.code", FieldType.INT, is_response=True)' in result

    def test_plan_field(self):
        fields = [
            FieldEntry(
                "cf.waf.score",
                "Type::Int",
                "FieldType.INT",
                requires_plan="enterprise",
            )
        ]
        result = generate_python_fields(fields)
        assert '_f("cf.waf.score", FieldType.INT, requires_plan="enterprise")' in result

    def test_response_and_plan(self):
        fields = [
            FieldEntry(
                "x.field",
                "Type::Int",
                "FieldType.INT",
                is_response=True,
                requires_plan="pro",
            )
        ]
        result = generate_python_fields(fields)
        assert 'is_response=True, requires_plan="pro"' in result


class TestReplaceBetweenSentinels:
    def test_basic_replacement(self):
        content = (
            "before\n# --- BEGIN GENERATED FIELDS ---\n"
            "old stuff\n# --- END GENERATED FIELDS ---\nafter\n"
        )
        result = replace_between_sentinels(content, "new stuff")
        assert "new stuff" in result
        assert "old stuff" not in result
        assert "before" in result
        assert "after" in result

    def test_preserves_sentinels(self):
        content = "# --- BEGIN GENERATED FIELDS ---\nold\n# --- END GENERATED FIELDS ---\n"
        result = replace_between_sentinels(content, "new")
        assert "BEGIN GENERATED FIELDS" in result
        assert "END GENERATED FIELDS" in result

    def test_missing_begin_raises(self):
        with pytest.raises(ValueError, match="Begin sentinel"):
            replace_between_sentinels("no sentinels", "new")

    def test_missing_end_raises(self):
        with pytest.raises(ValueError, match="End sentinel"):
            replace_between_sentinels("# --- BEGIN GENERATED FIELDS ---\ndata\n", "new")


class TestLoadFields:
    def test_loads_from_yaml(self):
        yaml_text = """
entries:
  - name: http.host
    data_type: String
    categories: []
  - name: ip.src
    data_type: IP address
    categories: []
"""
        fields = load_fields(yaml_text)
        names = [f.name for f in fields]
        assert "http.host" in names
        assert "ip.src" in names

    def test_excludes_uri_path(self):
        yaml_text = """
entries:
  - name: http.request.uri.path
    data_type: String
    categories: []
"""
        fields = load_fields(yaml_text)
        assert len(fields) == 0

    def test_skips_unknown_types(self):
        yaml_text = """
entries:
  - name: unknown
    data_type: SomeNewType
    categories: []
"""
        fields = load_fields(yaml_text)
        assert len(fields) == 0

    def test_sorted_by_name(self):
        yaml_text = """
entries:
  - name: zzz.field
    data_type: String
    categories: []
  - name: aaa.field
    data_type: String
    categories: []
"""
        fields = load_fields(yaml_text)
        assert fields[0].name == "aaa.field"
        assert fields[1].name == "zzz.field"
