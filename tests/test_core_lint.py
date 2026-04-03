"""Tests for core lint rules (CORE002, CORE003, CORE004, CORE006)."""

from octorules.commands._lint import _core_lint_orphaned_files, _core_lint_zone
from octorules.config import Config, ZoneConfig
from octorules.linter.engine import LintContext, Severity


def _ids(ctx: LintContext) -> set[str]:
    return {r.rule_id for r in ctx.results}


# ---------------------------------------------------------------------------
# CORE003: All rules disabled in phase
# ---------------------------------------------------------------------------
class TestCore003AllDisabled:
    def test_all_disabled_warns(self):
        ctx = LintContext(zone_name="test.com")
        desired = {
            "redirect_rules": [
                {"ref": "r1", "enabled": False, "expression": "true"},
                {"ref": "r2", "enabled": False, "expression": "true"},
            ]
        }
        _core_lint_zone(desired, ctx)
        assert "CORE003" in _ids(ctx)
        assert "disabled" in ctx.results[0].message

    def test_some_enabled_ok(self):
        ctx = LintContext(zone_name="test.com")
        desired = {
            "redirect_rules": [
                {"ref": "r1", "enabled": False, "expression": "true"},
                {"ref": "r2", "enabled": True, "expression": "true"},
            ]
        }
        _core_lint_zone(desired, ctx)
        assert "CORE003" not in _ids(ctx)

    def test_no_enabled_field_defaults_true(self):
        """Rules without 'enabled' key are considered enabled."""
        ctx = LintContext(zone_name="test.com")
        desired = {
            "redirect_rules": [
                {"ref": "r1", "expression": "true"},
            ]
        }
        _core_lint_zone(desired, ctx)
        assert "CORE003" not in _ids(ctx)

    def test_single_disabled_rule_not_flagged(self):
        """A single disabled rule is CF018/WA600's job, not CORE003."""
        ctx = LintContext(zone_name="test.com")
        desired = {
            "redirect_rules": [
                {"ref": "r1", "enabled": False, "expression": "true"},
            ]
        }
        _core_lint_zone(desired, ctx)
        assert "CORE003" not in _ids(ctx)

    def test_empty_phase_not_flagged(self):
        """Phase with no rules doesn't trigger CORE003."""
        ctx = LintContext(zone_name="test.com")
        desired = {"redirect_rules": []}
        _core_lint_zone(desired, ctx)
        assert "CORE003" not in _ids(ctx)


# ---------------------------------------------------------------------------
# CORE004: Ref collision across phases
# ---------------------------------------------------------------------------
class TestCore004RefCollision:
    def test_same_ref_different_phases_warns(self):
        ctx = LintContext(zone_name="test.com")
        desired = {
            "redirect_rules": [{"ref": "block-bots", "expression": "true"}],
            "cache_rules": [{"ref": "block-bots", "expression": "true"}],
        }
        _core_lint_zone(desired, ctx)
        assert "CORE004" in _ids(ctx)
        assert "block-bots" in ctx.results[0].message
        assert "redirect_rules" in ctx.results[0].message
        assert "cache_rules" in ctx.results[0].message

    def test_same_ref_same_phase_not_flagged(self):
        """Duplicate refs within a single phase are NOT a CORE004 issue
        (that's a provider-specific check like CF018 or WA022)."""
        ctx = LintContext(zone_name="test.com")
        desired = {
            "redirect_rules": [
                {"ref": "r1", "expression": "true"},
                {"ref": "r1", "expression": "false"},
            ],
        }
        _core_lint_zone(desired, ctx)
        assert "CORE004" not in _ids(ctx)

    def test_same_ref_three_phases(self):
        """CORE004 fires when ref appears in 3+ different phases."""
        ctx = LintContext(zone_name="test.com")
        desired = {
            "redirect_rules": [{"ref": "block-bots", "expression": "true"}],
            "cache_rules": [{"ref": "block-bots", "expression": "true"}],
            "waf_custom_rules": [{"ref": "block-bots", "expression": "true"}],
        }
        _core_lint_zone(desired, ctx)
        assert "CORE004" in _ids(ctx)
        msg = ctx.results[0].message
        assert "cache_rules" in msg
        assert "redirect_rules" in msg
        assert "waf_custom_rules" in msg

    def test_different_refs_ok(self):
        ctx = LintContext(zone_name="test.com")
        desired = {
            "redirect_rules": [{"ref": "r1", "expression": "true"}],
            "cache_rules": [{"ref": "r2", "expression": "true"}],
        }
        _core_lint_zone(desired, ctx)
        assert "CORE004" not in _ids(ctx)


# ---------------------------------------------------------------------------
# CORE006: Empty rules file
# ---------------------------------------------------------------------------
class TestCore003EdgeCases:
    def test_phase_with_non_dict_entries_skipped(self):
        """Non-dict entries in a phase list are ignored, not counted."""
        ctx = LintContext(zone_name="test.com")
        desired = {
            "redirect_rules": [
                None,
                "not-a-dict",
                {"ref": "r1", "enabled": False},
                {"ref": "r2", "enabled": False},
            ],
        }
        _core_lint_zone(desired, ctx)
        # 2 dict rules, both disabled → CORE003 (non-dicts filtered out)
        assert "CORE003" in _ids(ctx)

    def test_multiple_phases_only_one_all_disabled(self):
        """CORE003 fires only for the phase where ALL rules are disabled."""
        ctx = LintContext(zone_name="test.com")
        desired = {
            "redirect_rules": [
                {"ref": "r1", "enabled": False},
                {"ref": "r2", "enabled": False},
            ],
            "cache_rules": [
                {"ref": "r3", "enabled": True},
            ],
        }
        _core_lint_zone(desired, ctx)
        core003 = [r for r in ctx.results if r.rule_id == "CORE003"]
        assert len(core003) == 1
        assert "redirect_rules" in core003[0].phase

    def test_non_list_phase_value_skipped(self):
        """Phase with non-list value (e.g., string) is silently skipped."""
        ctx = LintContext(zone_name="test.com")
        desired = {"redirect_rules": "not-a-list"}
        _core_lint_zone(desired, ctx)
        assert "CORE003" not in _ids(ctx)


class TestCore006EmptyFile:
    def test_no_rules_flags_info(self):
        ctx = LintContext(zone_name="test.com")
        desired = {"redirect_rules": [], "cache_rules": []}
        _core_lint_zone(desired, ctx)
        assert "CORE006" in _ids(ctx)
        assert ctx.results[0].severity == Severity.INFO

    def test_has_rules_ok(self):
        ctx = LintContext(zone_name="test.com")
        desired = {"redirect_rules": [{"ref": "r1", "expression": "true"}]}
        _core_lint_zone(desired, ctx)
        assert "CORE006" not in _ids(ctx)

    def test_only_non_phase_keys_flags(self):
        """File with only 'lists' section (non-phase key) has no rules."""
        ctx = LintContext(zone_name="test.com")
        desired = {"lists": [{"name": "blocklist", "kind": "ip", "items": []}]}
        _core_lint_zone(desired, ctx)
        assert "CORE006" in _ids(ctx)


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
