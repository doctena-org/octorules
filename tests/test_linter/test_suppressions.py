"""Unit tests for the suppression parser (parse_suppressions / is_suppressed)."""

from __future__ import annotations

from octorules.linter.suppressions import is_suppressed, parse_suppressions


class TestParseSuppressions:
    """Tests for parse_suppressions()."""

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.yaml"
        f.write_text("")
        assert parse_suppressions(f) == {}

    def test_no_directives(self, tmp_path):
        f = tmp_path / "rules.yaml"
        f.write_text("- ref: r1\n  expression: true\n")
        assert parse_suppressions(f) == {}

    def test_file_level_suppression(self, tmp_path):
        f = tmp_path / "rules.yaml"
        f.write_text("# octorules:disable=M013\nredirect_rules:\n- ref: r1\n")
        result = parse_suppressions(f)
        assert result == {"*": {"M013"}}

    def test_rule_level_suppression_ref(self, tmp_path):
        f = tmp_path / "rules.yaml"
        f.write_text("# octorules:disable=M013\n- ref: r1\n  expression: true\n")
        result = parse_suppressions(f)
        assert result == {"r1": {"M013"}}

    def test_rule_level_suppression_description(self, tmp_path):
        """Directive before a - description: line attaches to that description."""
        f = tmp_path / "rules.yaml"
        f.write_text('# octorules:disable=S001\n- description: "My policy"\n')
        result = parse_suppressions(f)
        assert result == {"My policy": {"S001"}}

    def test_description_bare(self, tmp_path):
        """Bare (unquoted) description anchor."""
        f = tmp_path / "rules.yaml"
        f.write_text("# octorules:disable=S002\n- description: My bare policy\n")
        result = parse_suppressions(f)
        assert result == {"My bare policy": {"S002"}}

    def test_description_single_quoted(self, tmp_path):
        """Single-quoted description anchor."""
        f = tmp_path / "rules.yaml"
        f.write_text("# octorules:disable=S003\n- description: 'Quoted policy'\n")
        result = parse_suppressions(f)
        assert result == {"Quoted policy": {"S003"}}

    def test_multi_rule_suppression(self, tmp_path):
        f = tmp_path / "rules.yaml"
        f.write_text("# octorules:disable=M013,O001\n- ref: r1\n")
        result = parse_suppressions(f)
        assert result == {"r1": {"M013", "O001"}}

    def test_whitespace_tolerance(self, tmp_path):
        f = tmp_path / "rules.yaml"
        f.write_text("#  octorules:disable = M013 , O001\n- ref: r1\n")
        result = parse_suppressions(f)
        assert result == {"r1": {"M013", "O001"}}

    def test_unknown_ids_filtered(self, tmp_path):
        f = tmp_path / "rules.yaml"
        f.write_text("# octorules:disable=M013,X999\n- ref: r1\n")
        result = parse_suppressions(f, known_rules={"M013"})
        assert result == {"r1": {"M013"}}

    def test_all_unknown_ids(self, tmp_path):
        """When all IDs are unknown, nothing is suppressed."""
        f = tmp_path / "rules.yaml"
        f.write_text("# octorules:disable=X001,X002\n- ref: r1\n")
        result = parse_suppressions(f, known_rules={"M013"})
        assert result == {}

    def test_oserror_returns_empty(self, tmp_path):
        """Non-existent file returns empty dict (no crash)."""
        result = parse_suppressions(tmp_path / "nonexistent.yaml")
        assert result == {}

    def test_pending_ids_at_eof_file_level(self, tmp_path):
        """Pending IDs at EOF before any anchor are file-level."""
        f = tmp_path / "rules.yaml"
        f.write_text("# octorules:disable=M013\n")
        result = parse_suppressions(f)
        assert result == {"*": {"M013"}}

    def test_pending_ids_at_eof_after_anchor_discarded(self, tmp_path):
        """Pending IDs at EOF after an anchor has been seen are discarded."""
        f = tmp_path / "rules.yaml"
        f.write_text("- ref: r1\n# octorules:disable=M013\n")
        result = parse_suppressions(f)
        # After the first anchor, pending IDs at EOF are NOT file-level
        assert result == {}

    def test_mixed_ref_and_description_anchors(self, tmp_path):
        """Directives before different anchor types."""
        f = tmp_path / "rules.yaml"
        f.write_text(
            "# octorules:disable=M013\n"
            "- ref: r1\n"
            "  expression: true\n"
            "# octorules:disable=S001\n"
            '- description: "My CSP"\n'
        )
        result = parse_suppressions(f)
        assert result == {"r1": {"M013"}, "My CSP": {"S001"}}

    def test_directive_not_followed_by_anchor_after_first_anchor(self, tmp_path):
        """Directive followed by non-anchor line after first anchor is discarded."""
        f = tmp_path / "rules.yaml"
        f.write_text("- ref: r1\n  expression: true\n# octorules:disable=M013\nsome_key: value\n")
        result = parse_suppressions(f)
        assert result == {}


class TestIsSuppressed:
    """Tests for is_suppressed()."""

    def test_file_level_suppression(self):
        suppressions = {"*": {"M013"}}
        assert is_suppressed(suppressions, "any-ref", "M013") is True

    def test_ref_level_suppression(self):
        suppressions = {"r1": {"M013"}}
        assert is_suppressed(suppressions, "r1", "M013") is True

    def test_not_suppressed(self):
        suppressions = {"r1": {"M013"}}
        assert is_suppressed(suppressions, "r1", "O001") is False
        assert is_suppressed(suppressions, "r2", "M013") is False

    def test_empty_suppressions(self):
        assert is_suppressed({}, "r1", "M013") is False

    def test_file_level_overrides_ref(self):
        """File-level suppression applies to all refs."""
        suppressions = {"*": {"M013"}}
        assert is_suppressed(suppressions, "r1", "M013") is True
        assert is_suppressed(suppressions, "r2", "M013") is True

    def test_empty_ref(self):
        """Empty string ref should not match file-level wildcard."""
        suppressions = {"r1": {"M013"}}
        assert is_suppressed(suppressions, "", "M013") is False
