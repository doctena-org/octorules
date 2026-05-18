"""Tests for lint engine — framework tests (no provider-specific logic)."""

import textwrap

from octorules.linter.engine import (
    LintContext,
    LintResult,
    Severity,
    check_catch_all,
    is_always_false,
    is_always_true,
    lint_zone_file,
)
from octorules.linter.plugin import (
    LintPlugin,
    register_linter,
    unregister_linter,
)
from octorules.linter.suppressions import parse_suppressions


class TestLintResult:
    def test_str_representation(self):
        r = LintResult(
            rule_id="M001",
            severity=Severity.ERROR,
            message="Missing ref",
            phase="redirect_rules",
            ref="test",
        )
        s = str(r)
        assert "ERROR" in s
        assert "M001" in s
        assert "Missing ref" in s
        assert "redirect_rules" in s

    def test_str_with_suggestion(self):
        r = LintResult(
            rule_id="G001",
            severity=Severity.WARNING,
            message="Method should be uppercase",
            suggestion="Use GET",
        )
        s = str(r)
        assert "[fix: Use GET]" in s


class TestLintContext:
    def test_add_respects_severity_filter(self):
        ctx = LintContext(severity_filter=Severity.WARNING)
        ctx.add(LintResult(rule_id="O001", severity=Severity.INFO, message="info"))
        ctx.add(LintResult(rule_id="M001", severity=Severity.ERROR, message="error"))
        ctx.add(LintResult(rule_id="G001", severity=Severity.WARNING, message="warning"))
        assert len(ctx.results) == 2
        assert all(r.severity <= Severity.WARNING for r in ctx.results)

    def test_add_respects_rule_filter(self):
        ctx = LintContext(rule_filter=["M001"])
        ctx.add(LintResult(rule_id="M001", severity=Severity.ERROR, message="m001"))
        ctx.add(LintResult(rule_id="M002", severity=Severity.ERROR, message="m002"))
        assert len(ctx.results) == 1
        assert ctx.results[0].rule_id == "M001"

    def test_add_respects_phase_filter(self):
        ctx = LintContext(phase_filter=["redirect_rules"])
        ctx.add(
            LintResult(rule_id="M001", severity=Severity.ERROR, message="r", phase="redirect_rules")
        )
        ctx.add(
            LintResult(rule_id="M001", severity=Severity.ERROR, message="c", phase="cache_rules")
        )
        assert len(ctx.results) == 1

    def test_errors_property(self):
        ctx = LintContext()
        ctx.add(LintResult(rule_id="M001", severity=Severity.ERROR, message="e"))
        ctx.add(LintResult(rule_id="G001", severity=Severity.WARNING, message="w"))
        assert len(ctx.errors) == 1
        assert len(ctx.warnings) == 1

    def test_has_errors(self):
        ctx = LintContext()
        assert not ctx.has_errors
        ctx.add(LintResult(rule_id="M001", severity=Severity.ERROR, message="e"))
        assert ctx.has_errors

    def test_has_warnings(self):
        ctx = LintContext()
        assert not ctx.has_warnings
        ctx.add(LintResult(rule_id="G001", severity=Severity.WARNING, message="w"))
        assert ctx.has_warnings
        assert not ctx.has_errors


class TestPluginDispatch:
    """Tests for plugin-based lint dispatch."""

    def _make_plugin(self, name="test", rule_ids=None):
        calls = []

        def lint_fn(rules_data, ctx):
            calls.append(rules_data)
            ctx.add(LintResult(rule_id="T001", severity=Severity.ERROR, message="test"))

        plugin = LintPlugin(
            name=name,
            lint_fn=lint_fn,
            rule_ids=frozenset(rule_ids or ["T001"]),
        )
        return plugin, calls

    def test_returns_lint_context(self):
        """lint_zone_file always returns a LintContext."""
        ctx = lint_zone_file({"redirect_rules": [{"ref": "test", "expression": "true"}]})
        assert isinstance(ctx, LintContext)

    def test_plugin_is_called(self):
        """Registered plugin's lint_fn is called by lint_zone_file."""
        plugin, calls = self._make_plugin(name="test-dispatch")
        register_linter(plugin)
        try:
            data = {"test_phase": []}
            lint_zone_file(data)
            assert data in calls
        finally:
            unregister_linter("test-dispatch")

    def test_multiple_plugins_called(self):
        """Multiple registered plugins are all called."""
        p1, calls1 = self._make_plugin(name="test-p1", rule_ids=["T001"])
        p2, calls2 = self._make_plugin(name="test-p2", rule_ids=["T002"])
        register_linter(p1)
        register_linter(p2)
        try:
            data = {"test_phase": []}
            lint_zone_file(data)
            assert len(calls1) == 1
            assert len(calls2) == 1
        finally:
            unregister_linter("test-p1")
            unregister_linter("test-p2")

    def test_target_plugins_filter_selects_one(self):
        """``target_plugins`` filter — only the named plugin is invoked."""
        p1, calls1 = self._make_plugin(name="cloudflare", rule_ids=["CF001"])
        p2, calls2 = self._make_plugin(name="aws", rule_ids=["WA001"])
        register_linter(p1)
        register_linter(p2)
        try:
            data = {"some_phase": []}
            lint_zone_file(data, target_plugins={"cloudflare"})
            assert len(calls1) == 1
            assert len(calls2) == 0
        finally:
            unregister_linter("cloudflare")
            unregister_linter("aws")

    def test_target_plugins_filter_selects_multiple(self):
        """``target_plugins`` with multiple names invokes only those plugins."""
        p1, calls1 = self._make_plugin(name="alpha", rule_ids=["A001"])
        p2, calls2 = self._make_plugin(name="beta", rule_ids=["B001"])
        p3, calls3 = self._make_plugin(name="gamma", rule_ids=["G001"])
        register_linter(p1)
        register_linter(p2)
        register_linter(p3)
        try:
            lint_zone_file({"x": []}, target_plugins={"alpha", "gamma"})
            assert len(calls1) == 1
            assert len(calls2) == 0
            assert len(calls3) == 1
        finally:
            unregister_linter("alpha")
            unregister_linter("beta")
            unregister_linter("gamma")

    def test_target_plugins_none_runs_all(self):
        """``target_plugins=None`` keeps legacy behaviour (every plugin)."""
        p1, calls1 = self._make_plugin(name="x1", rule_ids=["X001"])
        p2, calls2 = self._make_plugin(name="x2", rule_ids=["X002"])
        register_linter(p1)
        register_linter(p2)
        try:
            lint_zone_file({"x": []}, target_plugins=None)
            assert len(calls1) == 1
            assert len(calls2) == 1
        finally:
            unregister_linter("x1")
            unregister_linter("x2")

    def test_target_plugins_empty_set_runs_nothing(self):
        """An empty ``target_plugins`` set is honoured — no plugins run."""
        p1, calls1 = self._make_plugin(name="solo", rule_ids=["S001"])
        register_linter(p1)
        try:
            lint_zone_file({"x": []}, target_plugins=set())
            assert len(calls1) == 0
        finally:
            unregister_linter("solo")

    def test_get_known_rule_ids_aggregates_plugins(self):
        """get_known_rule_ids returns union of all plugin rule_ids."""
        from octorules.linter.engine import get_known_rule_ids

        p, _ = self._make_plugin(name="test-ids", rule_ids=["X001", "X002"])
        register_linter(p)
        try:
            ids = get_known_rule_ids()
            assert "X001" in ids
            assert "X002" in ids
        finally:
            unregister_linter("test-ids")

    def test_register_duplicate_raises(self):
        """Registering a plugin with the same name raises ValueError."""
        import pytest

        p1, _ = self._make_plugin(name="test-dup")
        p2, _ = self._make_plugin(name="test-dup")
        register_linter(p1)
        try:
            with pytest.raises(ValueError, match="already registered"):
                register_linter(p2)
        finally:
            unregister_linter("test-dup")

    def test_unregister_missing_raises(self):
        """Unregistering a non-existent plugin raises KeyError."""
        import pytest

        with pytest.raises(KeyError, match="not registered"):
            unregister_linter("nonexistent-plugin")


class TestSuppressions:
    """Tests for # octorules:disable suppression directives."""

    def test_rule_level_suppression(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            textwrap.dedent("""\
            redirect_rules:
              # octorules:disable=M013
              - ref: catch-all
                expression: (true)
        """)
        )
        suppressions = parse_suppressions(f)
        assert "M013" in suppressions.get("catch-all", set())

    def test_file_level_suppression(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            textwrap.dedent("""\
            # octorules:disable=O002
            redirect_rules:
              - ref: my-rule
                expression: 'raw.http.request.uri.path eq "/x"'
        """)
        )
        suppressions = parse_suppressions(f)
        assert "O002" in suppressions.get("*", set())

    def test_multiple_ids_comma_separated(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            textwrap.dedent("""\
            redirect_rules:
              # octorules:disable=M013,O001
              - ref: catch-all
                expression: (true)
        """)
        )
        suppressions = parse_suppressions(f)
        assert suppressions["catch-all"] == {"M013", "O001"}

    def test_no_directives(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            textwrap.dedent("""\
            redirect_rules:
              - ref: my-rule
                expression: 'http.host eq "example.com"'
        """)
        )
        suppressions = parse_suppressions(f)
        assert suppressions == {}

    def test_suppression_filters_results(self):
        ctx = LintContext(suppressions={"catch-all": {"M013"}})
        ctx.add(
            LintResult(
                rule_id="M013",
                severity=Severity.WARNING,
                message="always true",
                ref="catch-all",
            )
        )
        ctx.add(
            LintResult(
                rule_id="M013",
                severity=Severity.WARNING,
                message="always true",
                ref="other-rule",
            )
        )
        assert len(ctx.results) == 1
        assert ctx.results[0].ref == "other-rule"
        assert ctx.suppressed_count == 1

    def test_file_level_suppresses_all_refs(self):
        ctx = LintContext(suppressions={"*": {"O002"}})
        ctx.add(
            LintResult(
                rule_id="O002",
                severity=Severity.INFO,
                message="use normalized",
                ref="rule-a",
            )
        )
        ctx.add(
            LintResult(
                rule_id="O002",
                severity=Severity.INFO,
                message="use normalized",
                ref="rule-b",
            )
        )
        assert len(ctx.results) == 0
        assert ctx.suppressed_count == 2

    def test_suppression_does_not_affect_other_rules(self):
        ctx = LintContext(suppressions={"my-ref": {"M013"}})
        ctx.add(
            LintResult(
                rule_id="G010",
                severity=Severity.WARNING,
                message="deprecated field",
                ref="my-ref",
            )
        )
        assert len(ctx.results) == 1

    def test_lint_zone_file_with_suppressions(self):
        """lint_zone_file passes suppressions to the context."""
        ctx = lint_zone_file(
            {
                "request_header_rules": [
                    {"ref": "catch-all", "expression": "(true)"},
                ]
            },
            suppressions={"catch-all": {"M013"}},
        )
        m013 = [r for r in ctx.results if r.rule_id == "M013"]
        assert len(m013) == 0
        # May or may not have suppressed_count depending on whether CF plugin is loaded
        # The key assertion is M013 is not in results

    def test_missing_file_returns_empty(self):
        suppressions = parse_suppressions("/nonexistent/path.yaml")
        assert suppressions == {}

    def test_unknown_rule_id_warns(self, tmp_path, caplog):
        """Suppressing an unknown rule ID logs a warning and drops it."""
        import logging

        f = tmp_path / "test.yaml"
        f.write_text("# octorules:disable=X999\n- ref: foo\n  expression: 'true'\n")
        with caplog.at_level(logging.WARNING, logger="octorules.linter"):
            suppressions = parse_suppressions(f, known_rules={"M001", "M002"})
        assert "Unknown rule ID 'X999'" in caplog.text
        # X999 should not appear in suppressions
        all_ids = set()
        for ids in suppressions.values():
            all_ids |= ids
        assert "X999" not in all_ids

    def test_known_rule_id_not_warned(self, tmp_path, caplog):
        """Known rule IDs should not produce warnings."""
        import logging

        f = tmp_path / "test.yaml"
        f.write_text("# octorules:disable=M001\n- ref: foo\n  expression: 'true'\n")
        with caplog.at_level(logging.WARNING, logger="octorules.linter"):
            suppressions = parse_suppressions(f, known_rules={"M001", "M002"})
        assert "Unknown rule ID" not in caplog.text
        assert "M001" in suppressions.get("foo", set())


class TestDescriptionSuppressions:
    """Tests for Page Shield description-based suppression anchors."""

    def test_bare_description_suppression(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            "page_shield_policies:\n"
            "  # octorules:disable=M013\n"
            "  - description: my-csp-policy\n"
            "    expression: 'true'\n"
        )
        suppressions = parse_suppressions(f)
        assert "M013" in suppressions.get("my-csp-policy", set())

    def test_bare_multiword_description_suppression(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            "page_shield_policies:\n"
            "  # octorules:disable=M013\n"
            "  - description: Allow all scripts\n"
            "    expression: 'true'\n"
        )
        suppressions = parse_suppressions(f)
        assert "M013" in suppressions.get("Allow all scripts", set())

    def test_double_quoted_description_suppression(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            "page_shield_policies:\n"
            "  # octorules:disable=M013\n"
            '  - description: "Allow all scripts"\n'
            "    expression: 'true'\n"
        )
        suppressions = parse_suppressions(f)
        assert "M013" in suppressions.get("Allow all scripts", set())

    def test_single_quoted_description_suppression(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            "page_shield_policies:\n"
            "  # octorules:disable=M013\n"
            "  - description: 'Block bad scripts'\n"
            "    expression: 'true'\n"
        )
        suppressions = parse_suppressions(f)
        assert "M013" in suppressions.get("Block bad scripts", set())

    def test_description_suppression_filters_results(self):
        ctx = LintContext(suppressions={"Allow all scripts": {"M013"}})
        ctx.add(
            LintResult(
                rule_id="M013",
                severity=Severity.WARNING,
                message="always true",
                ref="Allow all scripts",
            )
        )
        ctx.add(
            LintResult(
                rule_id="M013",
                severity=Severity.WARNING,
                message="always true",
                ref="Other policy",
            )
        )
        assert len(ctx.results) == 1
        assert ctx.results[0].ref == "Other policy"
        assert ctx.suppressed_count == 1

    def test_file_level_suppression_still_works_with_descriptions(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            "# octorules:disable=O002\n"
            "page_shield_policies:\n"
            "  - description: my-policy\n"
            "    expression: 'true'\n"
        )
        suppressions = parse_suppressions(f)
        assert "O002" in suppressions.get("*", set())


class TestCheckCatchAll:
    """Tests for the DRY check_catch_all() helper."""

    def test_always_true_fires_m013(self):
        ctx = LintContext()
        check_catch_all("true", "waf_custom_rules", "test-ref", ctx)
        m013 = [r for r in ctx.results if r.rule_id == "M013"]
        assert len(m013) == 1
        assert m013[0].phase == "waf_custom_rules"
        assert m013[0].ref == "test-ref"
        assert "catch-all rule" in m013[0].message

    def test_always_false_fires_m014(self):
        ctx = LintContext()
        check_catch_all("false", "redirect_rules", "dead-rule", ctx)
        m014 = [r for r in ctx.results if r.rule_id == "M014"]
        assert len(m014) == 1
        assert "never match" in m014[0].message

    def test_entity_policy(self):
        ctx = LintContext()
        check_catch_all("true", "page_shield_policies", "my-policy", ctx, entity="policy")
        m013 = [r for r in ctx.results if r.rule_id == "M013"]
        assert len(m013) == 1
        assert "catch-all policy" in m013[0].message

    def test_normal_expression_no_findings(self):
        ctx = LintContext()
        check_catch_all('http.host eq "example.com"', "waf_custom_rules", "r", ctx)
        assert len(ctx.results) == 0

    def test_parenthesized_true(self):
        ctx = LintContext()
        check_catch_all("((true))", "redirect_rules", "r", ctx)
        assert any(r.rule_id == "M013" for r in ctx.results)


class TestIsAlwaysTrue:
    def test_bare_true(self):
        assert is_always_true("true")

    def test_single_paren(self):
        assert is_always_true("(true)")

    def test_double_paren(self):
        assert is_always_true("((true))")

    def test_triple_paren(self):
        assert is_always_true("(((true)))")

    def test_many_parens(self):
        assert is_always_true("(((((true)))))")

    def test_not_true(self):
        assert not is_always_true("false")
        assert not is_always_true("(false)")

    def test_expression_not_always_true(self):
        assert not is_always_true('http.host eq "example.com"')

    def test_unbalanced_parens_not_stripped(self):
        assert not is_always_true("(true) and (true)")

    def test_empty(self):
        assert not is_always_true("")


class TestIsAlwaysFalse:
    def test_bare_false(self):
        assert is_always_false("false")

    def test_single_paren(self):
        assert is_always_false("(false)")

    def test_double_paren(self):
        assert is_always_false("((false))")

    def test_triple_paren(self):
        assert is_always_false("(((false)))")

    def test_many_parens(self):
        assert is_always_false("(((((false)))))")

    def test_not_false(self):
        assert not is_always_false("true")

    def test_expression_not_always_false(self):
        assert not is_always_false('http.host eq "example.com"')


class TestLintPerformance:
    """Guard against O(n²) regressions in lint plugins.

    Any provider's linter that processes large rule sets (IP lists, access
    lists, etc.) must use O(n log n) algorithms, not brute-force pairwise
    comparison.  These tests create large synthetic data and assert that
    lint completes within a time budget.
    """

    def test_large_ip_list_lint_under_5s(self):
        """A 5,000-item IP list must lint in under 5 seconds.

        The O(n²) brute-force overlap check that shipped in
        octorules-cloudflare v0.7.7 took 26s+ on a ~10,000-item list;
        the sweep-line replacement (v0.7.8) takes < 0.1s.
        """
        import time

        items = [{"ip": f"198.51.{i // 256}.{i % 256}"} for i in range(5000)]
        rules_data = {"lists": [{"name": "perf-test", "kind": "ip", "items": items}]}
        t0 = time.monotonic()
        lint_zone_file(rules_data)
        elapsed = time.monotonic() - t0
        assert elapsed < 5.0, f"Lint with 5000-item IP list took {elapsed:.1f}s (limit 5s)"

    def test_large_rule_set_lint_under_5s(self):
        """500 rules in a single phase must lint in under 5 seconds."""
        import time

        rules = [
            {
                "ref": f"rule-{i}",
                "expression": f'http.host eq "test-{i}.example.com"',
                "action": "block",
                "enabled": True,
            }
            for i in range(500)
        ]
        rules_data = {"waf_custom_rules": rules}
        t0 = time.monotonic()
        lint_zone_file(rules_data)
        elapsed = time.monotonic() - t0
        assert elapsed < 5.0, f"Lint with 500 rules took {elapsed:.1f}s (limit 5s)"


class TestProviderNameForClassPath:
    """Convention: ``octorules_<plugin_name>.*`` → ``<plugin_name>``."""

    def test_cloudflare_class_path(self):
        from octorules.linter.plugin import provider_name_for_class_path

        assert (
            provider_name_for_class_path("octorules_cloudflare.provider.CloudflareProvider")
            == "cloudflare"
        )

    def test_aws_class_path(self):
        from octorules.linter.plugin import provider_name_for_class_path

        assert provider_name_for_class_path("octorules_aws.provider.AwsWafProvider") == "aws"

    def test_non_octorules_class_path_returns_none(self):
        from octorules.linter.plugin import provider_name_for_class_path

        assert provider_name_for_class_path("acme.provider.AcmeProvider") is None
        assert provider_name_for_class_path("myorg.cloudflare.Provider") is None

    def test_empty_or_none(self):
        from octorules.linter.plugin import provider_name_for_class_path

        assert provider_name_for_class_path("") is None
        assert provider_name_for_class_path(None) is None

    def test_bare_package_name(self):
        """A class path that's only the package name still resolves."""
        from octorules.linter.plugin import provider_name_for_class_path

        assert provider_name_for_class_path("octorules_bunny") == "bunny"
