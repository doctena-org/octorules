"""Tests for core lint rules (CORE002, CORE003, CORE004, CORE006, CORE011)."""

import pytest

from octorules.commands._lint import _core_lint_orphaned_files, _core_lint_zone
from octorules.config import Config, ZoneConfig
from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.testing.lint import assert_lint, assert_no_lint


# ---------------------------------------------------------------------------
# CORE003: All rules disabled in phase
# ---------------------------------------------------------------------------
class TestCore003AllDisabled:
    def test_all_disabled_warns(self):
        ctx = LintContext(zone_name="test.com")
        desired = {
            "fakeprov.redirect_rules": [
                {"ref": "r1", "enabled": False, "expression": "true"},
                {"ref": "r2", "enabled": False, "expression": "true"},
            ]
        }
        _core_lint_zone(desired, ctx)
        assert_lint(ctx, "CORE003")
        assert "disabled" in ctx.results[0].message

    def test_some_enabled_ok(self):
        ctx = LintContext(zone_name="test.com")
        desired = {
            "fakeprov.redirect_rules": [
                {"ref": "r1", "enabled": False, "expression": "true"},
                {"ref": "r2", "enabled": True, "expression": "true"},
            ]
        }
        _core_lint_zone(desired, ctx)
        assert_no_lint(ctx, "CORE003")

    def test_no_enabled_field_defaults_true(self):
        """Rules without 'enabled' key are considered enabled."""
        ctx = LintContext(zone_name="test.com")
        desired = {
            "fakeprov.redirect_rules": [
                {"ref": "r1", "expression": "true"},
            ]
        }
        _core_lint_zone(desired, ctx)
        assert_no_lint(ctx, "CORE003")

    def test_single_disabled_rule_not_flagged(self):
        """A single disabled rule is CF018/WA600's job, not CORE003."""
        ctx = LintContext(zone_name="test.com")
        desired = {
            "fakeprov.redirect_rules": [
                {"ref": "r1", "enabled": False, "expression": "true"},
            ]
        }
        _core_lint_zone(desired, ctx)
        assert_no_lint(ctx, "CORE003")

    def test_empty_phase_not_flagged(self):
        """Phase with no rules doesn't trigger CORE003."""
        ctx = LintContext(zone_name="test.com")
        desired = {"fakeprov.redirect_rules": []}
        _core_lint_zone(desired, ctx)
        assert_no_lint(ctx, "CORE003")


# ---------------------------------------------------------------------------
# CORE004: Ref collision across phases
# ---------------------------------------------------------------------------
class TestCore004RefCollision:
    def test_same_ref_different_phases_warns(self):
        ctx = LintContext(zone_name="test.com")
        desired = {
            "fakeprov.redirect_rules": [{"ref": "block-bots", "expression": "true"}],
            "fakeprov.cache_rules": [{"ref": "block-bots", "expression": "true"}],
        }
        _core_lint_zone(desired, ctx)
        assert_lint(ctx, "CORE004")
        assert "block-bots" in ctx.results[0].message
        assert "fakeprov.redirect_rules" in ctx.results[0].message
        assert "fakeprov.cache_rules" in ctx.results[0].message

    def test_same_ref_same_phase_not_flagged(self):
        """Duplicate refs within a single phase are NOT a CORE004 issue
        (that's a provider-specific check like CF018 or WA022)."""
        ctx = LintContext(zone_name="test.com")
        desired = {
            "fakeprov.redirect_rules": [
                {"ref": "r1", "expression": "true"},
                {"ref": "r1", "expression": "false"},
            ],
        }
        _core_lint_zone(desired, ctx)
        assert_no_lint(ctx, "CORE004")

    def test_same_ref_three_phases(self):
        """CORE004 fires when ref appears in 3+ different phases."""
        ctx = LintContext(zone_name="test.com")
        desired = {
            "fakeprov.redirect_rules": [{"ref": "block-bots", "expression": "true"}],
            "fakeprov.cache_rules": [{"ref": "block-bots", "expression": "true"}],
            "fakeprov.waf_custom_rules": [{"ref": "block-bots", "expression": "true"}],
        }
        _core_lint_zone(desired, ctx)
        assert_lint(ctx, "CORE004")
        msg = ctx.results[0].message
        assert "fakeprov.cache_rules" in msg
        assert "fakeprov.redirect_rules" in msg
        assert "fakeprov.waf_custom_rules" in msg

    def test_different_refs_ok(self):
        ctx = LintContext(zone_name="test.com")
        desired = {
            "fakeprov.redirect_rules": [{"ref": "r1", "expression": "true"}],
            "fakeprov.cache_rules": [{"ref": "r2", "expression": "true"}],
        }
        _core_lint_zone(desired, ctx)
        assert_no_lint(ctx, "CORE004")


# ---------------------------------------------------------------------------
# CORE006: Empty rules file
# ---------------------------------------------------------------------------
class TestCore003EdgeCases:
    def test_phase_with_non_dict_entries_skipped(self):
        """Non-dict entries in a phase list are ignored, not counted."""
        ctx = LintContext(zone_name="test.com")
        desired = {
            "fakeprov.redirect_rules": [
                None,
                "not-a-dict",
                {"ref": "r1", "enabled": False},
                {"ref": "r2", "enabled": False},
            ],
        }
        _core_lint_zone(desired, ctx)
        # 2 dict rules, both disabled → CORE003 (non-dicts filtered out)
        assert_lint(ctx, "CORE003")

    def test_multiple_phases_only_one_all_disabled(self):
        """CORE003 fires only for the phase where ALL rules are disabled."""
        ctx = LintContext(zone_name="test.com")
        desired = {
            "fakeprov.redirect_rules": [
                {"ref": "r1", "enabled": False},
                {"ref": "r2", "enabled": False},
            ],
            "fakeprov.cache_rules": [
                {"ref": "r3", "enabled": True},
            ],
        }
        _core_lint_zone(desired, ctx)
        core003 = [r for r in ctx.results if r.rule_id == "CORE003"]
        assert len(core003) == 1
        assert "fakeprov.redirect_rules" in core003[0].phase

    def test_non_list_phase_value_skipped(self):
        """Phase with non-list value (e.g., string) is silently skipped."""
        ctx = LintContext(zone_name="test.com")
        desired = {"fakeprov.redirect_rules": "not-a-list"}
        _core_lint_zone(desired, ctx)
        assert_no_lint(ctx, "CORE003")


class TestCore006EmptyFile:
    def test_no_rules_flags_info(self):
        ctx = LintContext(zone_name="test.com")
        desired = {"fakeprov.redirect_rules": [], "fakeprov.cache_rules": []}
        _core_lint_zone(desired, ctx)
        assert_lint(ctx, "CORE006", severity=Severity.INFO)

    def test_has_rules_ok(self):
        ctx = LintContext(zone_name="test.com")
        desired = {"fakeprov.redirect_rules": [{"ref": "r1", "expression": "true"}]}
        _core_lint_zone(desired, ctx)
        assert_no_lint(ctx, "CORE006")

    def test_only_non_phase_keys_flags(self):
        """File with only 'lists' section (non-phase key) has no rules."""
        ctx = LintContext(zone_name="test.com")
        desired = {"lists": [{"name": "blocklist", "kind": "ip", "items": []}]}
        _core_lint_zone(desired, ctx)
        assert_lint(ctx, "CORE006")


# ---------------------------------------------------------------------------
# CORE002: Orphaned rules files
# ---------------------------------------------------------------------------
class TestCore002OrphanedFiles:
    def test_orphaned_file_detected(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text("redirect_rules: []\n")
        (rules_dir / "orphan.yaml").write_text("redirect_rules: []\n")

        config = Config(
            rules_dir=rules_dir,
            zones={"example.com": ZoneConfig(name="example.com")},
        )
        results = _core_lint_orphaned_files(config, ["example.com"])
        ids = {r.rule_id for r in results}
        assert "CORE002" in ids
        assert any("orphan.yaml" in r.message for r in results)

    def test_no_orphans(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text("redirect_rules: []\n")

        config = Config(
            rules_dir=rules_dir,
            zones={"example.com": ZoneConfig(name="example.com")},
        )
        results = _core_lint_orphaned_files(config, ["example.com"])
        assert len(results) == 0

    def test_empty_rules_dir(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        config = Config(
            rules_dir=rules_dir,
            zones={"example.com": ZoneConfig(name="example.com")},
        )
        results = _core_lint_orphaned_files(config, ["example.com"])
        assert len(results) == 0


# ---------------------------------------------------------------------------
# CORE007: Phase section fails the plan-time prepare pipeline
# ---------------------------------------------------------------------------
class TestCore007PrepareFailures:
    def test_missing_ref_errors(self):
        ctx = LintContext(zone_name="test.com")
        desired = {"fakeprov.redirect_rules": [{"expression": "true", "action": "redirect"}]}
        _core_lint_zone(desired, ctx)
        assert_lint(ctx, "CORE007", severity=Severity.ERROR)
        core007 = next(r for r in ctx.results if r.rule_id == "CORE007")
        assert "ref" in core007.message
        assert core007.phase == "fakeprov.redirect_rules"

    def test_duplicate_ref_errors(self):
        ctx = LintContext(zone_name="test.com")
        desired = {
            "fakeprov.redirect_rules": [
                {"ref": "dup", "expression": "true", "action": "redirect"},
                {"ref": "dup", "expression": "false", "action": "redirect"},
            ]
        }
        _core_lint_zone(desired, ctx)
        assert_lint(ctx, "CORE007")
        assert "dup" in next(r for r in ctx.results if r.rule_id == "CORE007").message

    def test_valid_rules_pass(self):
        ctx = LintContext(zone_name="test.com")
        desired = {
            "fakeprov.redirect_rules": [{"ref": "r1", "expression": "true", "action": "redirect"}]
        }
        _core_lint_zone(desired, ctx)
        assert_no_lint(ctx, "CORE007")

    def test_ignored_rules_still_validated(self):
        """Ignored rules go through ref validation before being filtered."""
        ctx = LintContext(zone_name="test.com")
        desired = {
            "fakeprov.redirect_rules": [
                {"expression": "true", "action": "redirect", "octorules": {"ignored": True}}
            ]
        }
        _core_lint_zone(desired, ctx)
        assert_lint(ctx, "CORE007")

    def test_unknown_section_is_not_core007(self):
        ctx = LintContext(zone_name="test.com")
        _core_lint_zone({"typo_rules": [{"no": "ref"}]}, ctx)
        assert_no_lint(ctx, "CORE007")

    def test_prepare_does_not_mutate_input(self):
        """Prepare hooks must not leak into the shared rules cache."""
        rules = [{"ref": "r1", "expression": "true\n  and true", "action": "redirect"}]
        desired = {"fakeprov.redirect_rules": rules}
        before = repr(desired)
        _core_lint_zone(desired, LintContext(zone_name="test.com"))
        assert repr(desired) == before


# ---------------------------------------------------------------------------
# CORE008 / CORE009: malformed lists / custom_rulesets entries
# ---------------------------------------------------------------------------
class TestCore008ListsShape:
    def test_missing_kind_errors(self):
        ctx = LintContext(zone_name="test.com")
        desired = {"lists": [{"name": "office", "items": []}]}
        _core_lint_zone(desired, ctx)
        assert_lint(ctx, "CORE008", severity=Severity.ERROR)
        assert "lists" in next(r for r in ctx.results if r.rule_id == "CORE008").message

    def test_missing_name_errors(self):
        ctx = LintContext(zone_name="test.com")
        desired = {"lists": [{"kind": "ip", "items": []}]}
        _core_lint_zone(desired, ctx)
        assert_lint(ctx, "CORE008")

    def test_valid_entry_passes(self):
        ctx = LintContext(zone_name="test.com")
        desired = {"lists": [{"name": "office", "kind": "ip", "items": [{"ip": "10.0.0.1"}]}]}
        _core_lint_zone(desired, ctx)
        assert_no_lint(ctx, "CORE008")

    def test_non_list_section_ignored(self):
        ctx = LintContext(zone_name="test.com")
        _core_lint_zone({"lists": "nonsense"}, ctx)
        assert_no_lint(ctx, "CORE008")

    def test_string_item_errors_instead_of_crashing(self):
        """Bare-string items are a shape error, not an AttributeError."""
        ctx = LintContext(zone_name="test.com")
        desired = {"lists": [{"name": "office", "kind": "ip", "items": ["10.0.0.0/8"]}]}
        _core_lint_zone(desired, ctx)
        assert_lint(ctx, "CORE008")
        assert "mapping" in next(r for r in ctx.results if r.rule_id == "CORE008").message


class TestCore009CustomRulesetsShape:
    def test_missing_required_rule_field_errors(self):
        ctx = LintContext(zone_name="test.com")
        desired = {
            "custom_rulesets": [
                {
                    "name": "Block attackers",
                    "phase": "fake_http_request_firewall_custom",
                    "capacity": 10,
                    "rules": [{"ref": "r1", "expression": "true"}],  # no action
                }
            ]
        }
        _core_lint_zone(desired, ctx)
        assert_lint(ctx, "CORE009", severity=Severity.ERROR)

    def test_valid_ruleset_passes(self):
        ctx = LintContext(zone_name="test.com")
        desired = {
            "custom_rulesets": [
                {
                    "name": "Block attackers",
                    "phase": "fake_http_request_firewall_custom",
                    "capacity": 10,
                    "rules": [{"ref": "r1", "expression": "true", "action": "block"}],
                }
            ]
        }
        _core_lint_zone(desired, ctx)
        assert_no_lint(ctx, "CORE009")


# ---------------------------------------------------------------------------
# CORE010: extension section fails its registered validation hook
# ---------------------------------------------------------------------------
class TestCore010ExtensionValidation:
    def test_extension_errors_surface_as_lint_results(self):
        from octorules.extensions import (
            register_validate_extension,
            unregister_validate_extension,
        )

        def _hook(desired, zone_name, errors, lines):
            if "broken_section" in desired:
                errors.append(f"  {zone_name}/broken_section: entry 0 is invalid")

        register_validate_extension(_hook)
        try:
            ctx = LintContext(zone_name="test.com")
            _core_lint_zone({"broken_section": [{}]}, ctx)
            assert_lint(ctx, "CORE010", severity=Severity.ERROR)
            core010 = next(r for r in ctx.results if r.rule_id == "CORE010")
            assert "broken_section" in core010.message
        finally:
            unregister_validate_extension(_hook)

    def test_clean_extension_section_passes(self):
        ctx = LintContext(zone_name="test.com")
        _core_lint_zone({"fakeprov.redirect_rules": []}, ctx)
        assert_no_lint(ctx, "CORE010")


class TestCoreRuleSuppressions:
    def test_core007_file_wide_suppression(self):
        ctx = LintContext(zone_name="test.com", suppressions={"*": {"CORE007"}})
        desired = {"fakeprov.redirect_rules": [{"expression": "true", "action": "redirect"}]}
        _core_lint_zone(desired, ctx)
        assert_no_lint(ctx, "CORE007")
        assert ctx.suppressed_count == 1


class TestCoreRuleRobustness:
    """Lint is a reporting tool — hook/validator exceptions become findings."""

    def test_core007_hook_exception_reported_not_raised(self):
        from octorules.phases import Phase, register_phase, unregister_phase

        def _boom(rule, phase):
            raise AttributeError("hook exploded")

        register_phase(
            Phase(
                friendly_name="boom_rules",
                provider_id="test_boom_rules",
                default_action="block",
                prepare_rule=_boom,
            )
        )
        try:
            ctx = LintContext(zone_name="test.com")
            _core_lint_zone(
                {"boom_rules": [{"ref": "r", "expression": "true", "action": "block"}]}, ctx
            )
            assert_lint(ctx, "CORE007")
            assert (
                "AttributeError" in next(r for r in ctx.results if r.rule_id == "CORE007").message
            )
        finally:
            unregister_phase("boom_rules")

    def test_core008_non_mapping_entry_reported_not_raised(self):
        ctx = LintContext(zone_name="test.com")
        _core_lint_zone({"lists": [42]}, ctx)
        assert_lint(ctx, "CORE008")
        assert "mapping" in next(r for r in ctx.results if r.rule_id == "CORE008").message

    def test_core009_non_mapping_entry_reported_not_raised(self):
        ctx = LintContext(zone_name="test.com")
        _core_lint_zone({"custom_rulesets": [42]}, ctx)
        assert_lint(ctx, "CORE009")
        assert "mapping" in next(r for r in ctx.results if r.rule_id == "CORE009").message

    def test_core010_raising_hook_reported_not_raised(self):
        from octorules.extensions import (
            register_validate_extension,
            unregister_validate_extension,
        )

        def _bad_hook(desired, zone_name, errors, lines):
            raise RuntimeError("broken hook")

        register_validate_extension(_bad_hook)
        try:
            ctx = LintContext(zone_name="test.com")
            _core_lint_zone({"fakeprov.redirect_rules": []}, ctx)
            assert_lint(ctx, "CORE010")
            assert "RuntimeError" in next(r for r in ctx.results if r.rule_id == "CORE010").message
        finally:
            unregister_validate_extension(_bad_hook)


# ---------------------------------------------------------------------------
# CORE011: unknown zone-file section (would not be managed)
# ---------------------------------------------------------------------------
@pytest.fixture
def fake_namespace():
    """Register a throwaway provider namespace and yield its name."""
    from octorules.phases import register_namespace, unregister_namespace

    register_namespace("core11prov", ["waf_custom_rules"])
    yield "core11prov"
    unregister_namespace("core11prov")


class TestCore011UnknownSection:
    """Sections plan/sync skip outright must fail lint on their own.

    Provider plugins cannot own this check: ``cmd_lint`` routes each file
    to its target provider's plugin only, and four of the five providers
    ship no file-level unknown-section rule — so a typo'd section used to
    lint completely clean.
    """

    def test_unknown_bare_key_is_error(self):
        ctx = LintContext(zone_name="example.com")
        _core_lint_zone({"totally_bogus_section": [{"ref": "r1"}]}, ctx)
        found = assert_lint(ctx, "CORE011", count=1, severity=Severity.ERROR)
        assert "totally_bogus_section" in found[0].message
        assert "will not be managed" in found[0].message

    def test_near_miss_key_suggests_the_real_phase(self):
        ctx = LintContext(zone_name="example.com")
        _core_lint_zone({"redirect_rulez": []}, ctx)
        found = assert_lint(ctx, "CORE011", count=1, severity=Severity.ERROR)
        assert "fakeprov.redirect_rules" in found[0].suggestion

    def test_known_phase_and_non_phase_keys_are_clean(self):
        ctx = LintContext(zone_name="example.com")
        _core_lint_zone(
            {"fakeprov.redirect_rules": [{"ref": "r1"}], "lists": [], "custom_rulesets": []}, ctx
        )
        assert_no_lint(ctx, "CORE011")

    def test_registered_namespace_and_scoped_core_sections_are_clean(self, fake_namespace):
        ctx = LintContext(zone_name="example.com")
        _core_lint_zone(
            {fake_namespace: {}, f"{fake_namespace}.lists": [], "fakeprov.redirect_rules": []}, ctx
        )
        assert_no_lint(ctx, "CORE011")

    def test_unknown_namespace_member_reports_the_dotted_spelling(self, fake_namespace):
        """The author wrote a nested member, so the diagnostic must echo
        the nesting rather than the internal ``ns:member`` scoped key."""
        ctx = LintContext(zone_name="example.com")
        _core_lint_zone({f"{fake_namespace}.waf_custom_rulez": []}, ctx)
        found = assert_lint(ctx, "CORE011", count=1, severity=Severity.ERROR)
        assert f"'{fake_namespace}.waf_custom_rulez'" in found[0].message
        assert f"{fake_namespace}:" not in found[0].message
        assert f"not a section of the '{fake_namespace}' namespace" in found[0].message

    def test_mistyped_namespace_member_suggests_a_member(self, fake_namespace):
        """Suggestions must come from the namespace's own member names.
        Matching a nested member against the flat registry would miss for
        every provider whose nested spelling drops a flat prefix."""
        ctx = LintContext(zone_name="example.com")
        _core_lint_zone({f"{fake_namespace}.waf_custom_rulez": []}, ctx)
        found = assert_lint(ctx, "CORE011", count=1)
        assert f"Did you mean '{fake_namespace}.waf_custom_rules'?" in found[0].message
        assert found[0].suggestion == f"Rename to '{fake_namespace}.waf_custom_rules'"

    def test_mistyped_scoped_core_section_suggests_it(self, fake_namespace):
        ctx = LintContext(zone_name="example.com")
        _core_lint_zone({f"{fake_namespace}.listz": []}, ctx)
        found = assert_lint(ctx, "CORE011", count=1)
        assert f"Did you mean '{fake_namespace}.lists'?" in found[0].message

    def test_defers_to_a_plugin_that_already_reported_the_key(self):
        """CF010 names the exact replacement for a removed alias; a generic
        CORE011 on the same key would be a second error for one defect."""
        ctx = LintContext(zone_name="example.com")
        ctx.add(
            LintResult(
                rule_id="CF010",
                severity=Severity.ERROR,
                message="Phase 'waf_managed_exceptions' has been renamed",
                phase="waf_managed_exceptions",
            )
        )
        _core_lint_zone({"waf_managed_exceptions": []}, ctx)
        assert_no_lint(ctx, "CORE011")

    def test_still_fires_for_keys_no_plugin_claimed(self):
        ctx = LintContext(zone_name="example.com")
        ctx.add(
            LintResult(
                rule_id="CF010",
                severity=Severity.ERROR,
                message="unrelated",
                phase="some_other_key",
            )
        )
        _core_lint_zone({"some_other_key": [], "an_unclaimed_typo": []}, ctx)
        found = assert_lint(ctx, "CORE011", count=1)
        assert "an_unclaimed_typo" in found[0].message


class TestLintSetsAndSuppressibility:
    """manager.lint.sets selects which rules run; some cannot be waived."""

    def test_rule_outside_the_enabled_sets_does_not_run(self):
        """A rule in `default` only is silent when just `strict` is enabled."""
        from octorules.linter.engine import LintResult, Severity

        ctx = LintContext(zone_name="z", enabled_sets=frozenset({"strict"}))
        # CORE006 is a default-set rule.
        ctx.add(LintResult(rule_id="CORE006", severity=Severity.INFO, message="x"))
        assert [r.rule_id for r in ctx.results] == []

    def test_rule_in_an_enabled_set_runs(self):
        from octorules.linter.engine import LintResult, Severity

        ctx = LintContext(zone_name="z", enabled_sets=frozenset({"default"}))
        ctx.add(LintResult(rule_id="CORE006", severity=Severity.INFO, message="x"))
        assert [r.rule_id for r in ctx.results] == ["CORE006"]

    def test_none_enabled_sets_runs_everything(self):
        """A caller with no config — a single-file lint — gets every rule."""
        from octorules.linter.engine import LintResult, Severity

        ctx = LintContext(zone_name="z")
        assert ctx.enabled_sets is None
        ctx.add(LintResult(rule_id="CORE006", severity=Severity.INFO, message="x"))
        assert [r.rule_id for r in ctx.results] == ["CORE006"]

    def test_core011_is_declared_non_suppressible(self):
        from octorules.linter.engine import get_known_rule_ids
        from octorules.linter.rules.registry import is_suppressible

        get_known_rule_ids()
        assert is_suppressible("CORE011") is False
        assert is_suppressible("CORE006") is True

    def test_unknown_rule_defaults_to_suppressible(self):
        """A provider rule we have no metadata for must not become unwaivable."""
        from octorules.linter.rules.registry import is_suppressible

        assert is_suppressible("ZZ999") is True

    def test_directive_cannot_waive_a_non_suppressible_rule(self):
        """The guard holds, and the author is told the directive did nothing."""
        from octorules.linter.engine import LintResult, Severity

        ctx = LintContext(zone_name="z", suppressions={"*": {"CORE011"}})
        ctx.add(LintResult(rule_id="CORE011", severity=Severity.ERROR, message="skipped"))
        assert [r.rule_id for r in ctx.results] == ["CORE011"]
        assert ctx.suppressed_count == 0
        assert any("cannot be suppressed" in reason for _, reason in ctx.ineffective_suppressions)

    def test_directive_waives_a_suppressible_rule(self):
        from octorules.linter.engine import LintResult, Severity

        ctx = LintContext(zone_name="z", suppressions={"*": {"CORE006"}})
        ctx.add(LintResult(rule_id="CORE006", severity=Severity.INFO, message="empty"))
        assert ctx.results == []
        assert ctx.suppressed_count == 1
        assert ctx.ineffective_suppressions == []

    def test_core012_reports_a_directive_for_an_inactive_rule(self):
        from octorules.commands._lint import _report_ineffective_suppressions
        from octorules.linter.engine import get_known_rule_ids

        get_known_rule_ids()
        ctx = LintContext(
            zone_name="z",
            enabled_sets=frozenset({"strict"}),
            suppressions={"*": {"CORE006"}},
        )
        _report_ineffective_suppressions(ctx)
        found = [r for r in ctx.results if r.rule_id == "CORE012"]
        assert len(found) == 1
        assert "no enabled validator set contains it" in found[0].message

    def test_core012_stays_active_in_every_set(self):
        """Selecting a set must not silence the rule that explains the choice."""
        from octorules.linter.engine import get_known_rule_ids
        from octorules.linter.rules.registry import get_rule_meta

        get_known_rule_ids()
        assert get_rule_meta("CORE012").sets == frozenset({"default", "strict"})


class TestPlanEnforcementFollowsTheRegistry:
    """Plan reads the same rule lint does, rather than its own switch."""

    def test_strict_enabled_makes_a_skipped_section_fatal(self):
        from octorules.planner import section_skip_is_fatal

        assert section_skip_is_fatal(frozenset({"default", "strict"})) is True

    def test_strict_disabled_downgrades_to_a_warning(self):
        """Dropping strict must warn, not go silent — the old strict_sections:
        false behaviour."""
        from octorules.planner import section_skip_is_fatal

        assert section_skip_is_fatal(frozenset({"default"})) is False

    def test_default_matches_the_config_default(self):
        from octorules.config import DEFAULT_LINT_SETS
        from octorules.planner import section_skip_is_fatal

        assert section_skip_is_fatal() is section_skip_is_fatal(frozenset(DEFAULT_LINT_SETS))


class TestUninstalledProviderNamespace:
    """A partial install must not fail a correct multi-provider file.

    A shared zone file may carry an `aws:` block while only the Cloudflare
    package is present. That file is correct; erroring on it would punish it
    for the environment it happened to be linted in — and with strict on by
    default, it would abort `plan`, not just lint.
    """

    def test_mapping_valued_unknown_key_is_a_warning(self):
        from octorules.linter.engine import Severity

        ctx = LintContext(zone_name="example.com")
        _core_lint_zone({"someprov": {"waf_custom_rules": [{"ref": "r1"}]}}, ctx)
        found = assert_lint(ctx, "CORE011", count=1, severity=Severity.WARNING)
        assert "no package installed" in found[0].message
        assert "octorules-someprov" in found[0].suggestion

    def test_list_valued_unknown_key_is_still_an_error(self):
        """A mistyped phase holds a list of rules, so it stays fatal."""
        from octorules.linter.engine import Severity

        ctx = LintContext(zone_name="example.com")
        _core_lint_zone({"typo_rules": [{"ref": "r1"}]}, ctx)
        assert_lint(ctx, "CORE011", count=1, severity=Severity.ERROR)

    def test_plan_does_not_abort_on_an_uninstalled_namespace(self):
        from octorules.planner import check_zone_sections

        # Would raise if it were treated like a typo.
        check_zone_sections(
            {"someprov": {"waf_custom_rules": []}},
            "example.com",
            enabled_sets={"default", "strict"},
        )

    def test_plan_still_aborts_on_a_mistyped_phase(self):
        from octorules.config import ConfigError
        from octorules.planner import check_zone_sections

        with pytest.raises(ConfigError, match="CORE011"):
            check_zone_sections(
                {"typo_rules": [{"ref": "r1"}]},
                "example.com",
                enabled_sets={"default", "strict"},
            )
