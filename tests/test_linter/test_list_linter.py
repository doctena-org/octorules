"""Tests for list validation (Category Q)."""

from __future__ import annotations

from octorules.linter.engine import LintContext
from octorules.linter.list_linter import lint_lists


def _lint(rules_data, **kwargs):
    ctx = LintContext(**kwargs)
    lint_lists(rules_data, ctx)
    return ctx


def _ids(ctx):
    return [r.rule_id for r in ctx.results]


class TestListStructure:
    def test_q001_missing_name(self):
        ctx = _lint({"lists": [{"kind": "ip", "items": []}]})
        assert "Q001" in _ids(ctx)

    def test_q001_duplicate_name(self):
        ctx = _lint(
            {
                "lists": [
                    {"name": "mylist", "kind": "ip", "items": []},
                    {"name": "mylist", "kind": "ip", "items": []},
                ]
            }
        )
        assert "Q001" in _ids(ctx)

    def test_q002_missing_kind(self):
        ctx = _lint({"lists": [{"name": "mylist", "items": []}]})
        assert "Q002" in _ids(ctx)

    def test_q002_invalid_kind(self):
        ctx = _lint({"lists": [{"name": "mylist", "kind": "bogus", "items": []}]})
        assert "Q002" in _ids(ctx)

    def test_valid_list_no_errors(self):
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [{"ip": "1.2.3.4"}, {"ip": "5.6.7.0/24"}],
                    }
                ]
            }
        )
        assert _ids(ctx) == []


class TestIPListItems:
    def test_q003_missing_ip_field(self):
        ctx = _lint({"lists": [{"name": "myips", "kind": "ip", "items": [{"comment": "oops"}]}]})
        assert "Q003" in _ids(ctx)

    def test_q004_invalid_ip(self):
        ctx = _lint({"lists": [{"name": "myips", "kind": "ip", "items": [{"ip": "not-an-ip"}]}]})
        assert "Q004" in _ids(ctx)

    def test_q006_duplicate_ip(self):
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [{"ip": "1.2.3.4"}, {"ip": "1.2.3.4"}],
                    }
                ]
            }
        )
        assert "Q006" in _ids(ctx)

    def test_valid_ips(self):
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myips",
                        "kind": "ip",
                        "items": [
                            {"ip": "1.2.3.4"},
                            {"ip": "10.0.0.0/8"},
                            {"ip": "2001:db8::/32"},
                        ],
                    }
                ]
            }
        )
        assert _ids(ctx) == []


class TestASNListItems:
    def test_q005_invalid_asn_type(self):
        ctx = _lint({"lists": [{"name": "myasns", "kind": "asn", "items": [{"asn": "not-int"}]}]})
        assert "Q005" in _ids(ctx)

    def test_q005_asn_boolean_true_rejected(self):
        """bool is a subclass of int in Python — True should not be accepted as ASN."""
        ctx = _lint({"lists": [{"name": "myasns", "kind": "asn", "items": [{"asn": True}]}]})
        assert "Q005" in _ids(ctx)

    def test_q005_asn_boolean_false_rejected(self):
        """bool is a subclass of int in Python — False should not be accepted as ASN."""
        ctx = _lint({"lists": [{"name": "myasns", "kind": "asn", "items": [{"asn": False}]}]})
        assert "Q005" in _ids(ctx)

    def test_q005_asn_out_of_range(self):
        ctx = _lint({"lists": [{"name": "myasns", "kind": "asn", "items": [{"asn": -1}]}]})
        assert "Q005" in _ids(ctx)

    def test_q006_duplicate_asn(self):
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myasns",
                        "kind": "asn",
                        "items": [{"asn": 12345}, {"asn": 12345}],
                    }
                ]
            }
        )
        assert "Q006" in _ids(ctx)

    def test_valid_asns(self):
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "myasns",
                        "kind": "asn",
                        "items": [{"asn": 12345}, {"asn": 67890}],
                    }
                ]
            }
        )
        assert _ids(ctx) == []


class TestHostnameListItems:
    def test_q006_duplicate_hostname(self):
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "hosts",
                        "kind": "hostname",
                        "items": [
                            {"hostname": {"url_hostname": "evil.com"}},
                            {"hostname": {"url_hostname": "evil.com"}},
                        ],
                    }
                ]
            }
        )
        assert "Q006" in _ids(ctx)


class TestRedirectListItems:
    def test_q003_missing_redirect_field(self):
        ctx = _lint(
            {"lists": [{"name": "redirects", "kind": "redirect", "items": [{"bogus": "val"}]}]}
        )
        assert "Q003" in _ids(ctx)

    def test_q006_duplicate_redirect_source(self):
        ctx = _lint(
            {
                "lists": [
                    {
                        "name": "redirects",
                        "kind": "redirect",
                        "items": [
                            {
                                "redirect": {
                                    "source_url": "example.com/old",
                                    "target_url": "https://example.com/new",
                                }
                            },
                            {
                                "redirect": {
                                    "source_url": "example.com/old",
                                    "target_url": "https://example.com/other",
                                }
                            },
                        ],
                    }
                ]
            }
        )
        assert "Q006" in _ids(ctx)


class TestNoListsSection:
    def test_no_lists_no_errors(self):
        ctx = _lint({"waf_custom_rules": []})
        assert _ids(ctx) == []
