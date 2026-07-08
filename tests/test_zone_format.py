"""Tests for provider namespaces and the nested zone-file format.

Covers ``register_namespace()`` / ``unregister_namespace()`` and
``normalize_zone_format()`` — the load-boundary transform that flattens
namespace blocks to the canonical internal keys.
"""

import pytest

from octorules.config import ConfigError, _yaml_load, normalize_zone_format
from octorules.phases import (
    KNOWN_NON_PHASE_KEYS,
    NAMESPACE_OF_KEY,
    PROVIDER_NAMESPACES,
    register_namespace,
    unregister_namespace,
)

_ALPHA_KEYS = {
    "custom_rules": "alpha_custom_rules",
    "rate_rules": "alpha_rate_rules",
    "settings": "alphaprov_settings",
}
_BETA_KEYS = {
    "custom_rules": "beta_custom_rules",
    "shield": "betaprov_shield",
}


@pytest.fixture
def namespaces():
    register_namespace("alphaprov", _ALPHA_KEYS)
    register_namespace("betaprov", _BETA_KEYS)
    yield
    unregister_namespace("alphaprov")
    unregister_namespace("betaprov")


class TestDisplayPhaseName:
    def test_owned_flat_key_renders_dotted(self, namespaces):
        from octorules.phases import display_phase_name

        assert display_phase_name("alpha_custom_rules") == "alphaprov.custom_rules"

    def test_scoped_core_section_renders_dotted(self, namespaces):
        from octorules.phases import display_phase_name

        assert display_phase_name("alphaprov:lists") == "alphaprov.lists"

    def test_unowned_names_pass_through(self):
        from octorules.phases import display_phase_name

        assert display_phase_name("redirect_rules") == "redirect_rules"
        assert display_phase_name("lists") == "lists"
        assert display_phase_name("custom_ruleset:Block") == "custom_ruleset:Block"
        assert display_phase_name("list:blocked-ips") == "list:blocked-ips"

    def test_unknown_scoped_member_renders_dotted(self, namespaces):
        """Diagnostics about a mistyped nested section must echo the
        nesting the author wrote, not the internal scoped spelling."""
        from octorules.phases import display_phase_name

        assert display_phase_name("alphaprov:custom_rulez") == "alphaprov.custom_rulez"

    def test_unregistered_namespace_prefix_passes_through(self):
        """Only registered namespaces dot — synthetic prefixes and
        namespace-qualified pseudo-refs must survive intact."""
        from octorules.phases import display_phase_name

        assert display_phase_name("notaprov:custom_rules") == "notaprov:custom_rules"
        assert display_phase_name("list:alphaprov:blocked-ips") == "list:alphaprov:blocked-ips"


class TestRegisterNamespace:
    def test_registers_mapping_and_derived_maps(self, namespaces):
        assert PROVIDER_NAMESPACES["alphaprov"] == _ALPHA_KEYS
        assert NAMESPACE_OF_KEY["alpha_custom_rules"] == ("alphaprov", "custom_rules")
        assert "alphaprov" in KNOWN_NON_PHASE_KEYS
        assert "alphaprov:lists" in KNOWN_NON_PHASE_KEYS
        assert "alphaprov:custom_rulesets" in KNOWN_NON_PHASE_KEYS

    def test_identical_reregistration_is_noop(self, namespaces):
        register_namespace("alphaprov", dict(_ALPHA_KEYS))

    def test_conflicting_reregistration_raises(self, namespaces):
        with pytest.raises(ValueError, match="already registered"):
            register_namespace("alphaprov", {"other": "alpha_custom_rules"})

    def test_key_owned_by_other_namespace_raises(self, namespaces):
        with pytest.raises(ValueError, match="already owned"):
            register_namespace("gammaprov", {"rules": "alpha_custom_rules"})

    def test_unregister_cleans_up(self):
        register_namespace("tempprov", {"x": "tempprov_x"})
        unregister_namespace("tempprov")
        assert "tempprov" not in PROVIDER_NAMESPACES
        assert "tempprov_x" not in NAMESPACE_OF_KEY
        assert "tempprov" not in KNOWN_NON_PHASE_KEYS
        assert "tempprov:lists" not in KNOWN_NON_PHASE_KEYS

    def test_core_sections_carry_no_ownership(self):
        """Several providers register lists/custom_rulesets as non-phase
        keys and may map them in their namespace — the core sections must
        never be owned, or the second provider to register would raise
        and plain flat files would warn."""
        register_namespace("tempprov1", {"custom_rulesets": "custom_rulesets", "a": "t1_a"})
        try:
            register_namespace("tempprov2", {"custom_rulesets": "custom_rulesets", "b": "t2_b"})
            assert "custom_rulesets" not in NAMESPACE_OF_KEY
            assert "lists" not in NAMESPACE_OF_KEY
            # Flat files with core sections don't warn as deprecated.
            data = {"custom_rulesets": [], "lists": []}
            assert normalize_zone_format(data) is data
        finally:
            unregister_namespace("tempprov1")
            unregister_namespace("tempprov2")


class TestNormalizeZoneFormat:
    def test_no_namespaces_passthrough(self):
        data = {"some_phase": [], "lists": []}
        assert normalize_zone_format(data) is data

    def test_single_namespace_flattens(self, namespaces):
        data = {
            "alphaprov": {
                "custom_rules": [{"ref": "r1"}],
                "settings": {"mode": "on"},
                "lists": [{"name": "l1"}],
                "custom_rulesets": [{"name": "cr1"}],
            },
            "plan_outputs": [{"type": "text"}],
        }
        result = normalize_zone_format(data, source="zone.yaml")
        assert result == {
            "alpha_custom_rules": [{"ref": "r1"}],
            "alphaprov_settings": {"mode": "on"},
            "lists": [{"name": "l1"}],
            "custom_rulesets": [{"name": "cr1"}],
            "plan_outputs": [{"type": "text"}],
        }

    def test_flat_spelling_warns(self, namespaces, caplog):
        data = {"alpha_custom_rules": []}
        with caplog.at_level("WARNING", logger="octorules.config"):
            result = normalize_zone_format(data, source="zone.yaml")
        assert result is data
        assert "deprecated flat spelling" in caplog.text
        assert "'alphaprov:'" in caplog.text

    def test_nested_spelling_does_not_warn(self, namespaces, caplog):
        data = {"alphaprov": {"custom_rules": []}}
        with caplog.at_level("WARNING", logger="octorules.config"):
            normalize_zone_format(data, source="zone.yaml")
        assert "deprecated" not in caplog.text

    def test_both_forms_same_section_raises(self, namespaces):
        data = {
            "alpha_custom_rules": [{"ref": "flat"}],
            "alphaprov": {"custom_rules": [{"ref": "nested"}]},
        }
        with pytest.raises(ConfigError, match="both flat and nested"):
            normalize_zone_format(data, source="zone.yaml")

    def test_non_mapping_namespace_block_raises(self, namespaces):
        with pytest.raises(ConfigError, match="must be a mapping"):
            normalize_zone_format({"alphaprov": []}, source="zone.yaml")

    def test_unknown_member_warns_and_is_kept_scoped(self, namespaces, caplog):
        data = {"alphaprov": {"mystery": {"a": 1}}}
        with caplog.at_level("WARNING", logger="octorules.config"):
            result = normalize_zone_format(data, source="zone.yaml")
        assert result["alphaprov:mystery"] == {"a": 1}
        assert "unknown key 'mystery'" in caplog.text

    def test_two_namespaces_flatten_side_by_side(self, namespaces):
        data = {
            "alphaprov": {"custom_rules": [{"ref": "a"}], "lists": [{"name": "al"}]},
            "betaprov": {"custom_rules": [{"ref": "b"}], "lists": [{"name": "bl"}]},
        }
        result = normalize_zone_format(data, source="zone.yaml")
        assert result["alpha_custom_rules"] == [{"ref": "a"}]
        assert result["beta_custom_rules"] == [{"ref": "b"}]
        # Core sections stay per-provider in a multi-provider file.
        assert result["alphaprov:lists"] == [{"name": "al"}]
        assert result["betaprov:lists"] == [{"name": "bl"}]
        assert "lists" not in result

    def test_context_dict_wrapper_preserved(self, namespaces):
        """The rebuilt flat view keeps the ContextDict file:line context."""
        from octorules.config import ContextDict

        data = ContextDict({"alphaprov": {"custom_rules": []}}, context="zone.yaml:1")
        result = normalize_zone_format(data, source="zone.yaml")
        assert isinstance(result, ContextDict)
        assert result.context == "zone.yaml:1"

    def test_top_level_lists_ambiguous_with_two_namespaces(self, namespaces):
        data = {
            "alphaprov": {"custom_rules": []},
            "betaprov": {"custom_rules": []},
            "lists": [{"name": "whose"}],
        }
        with pytest.raises(ConfigError, match="ambiguous"):
            normalize_zone_format(data, source="zone.yaml")


class TestDumpNested:
    def test_dump_groups_owned_keys_under_namespace(self, namespaces, tmp_path):
        import yaml

        from octorules.dumper import _nest_output, dump_zone_rules

        output = {
            "alpha_custom_rules": [{"ref": "r1"}],
            "alphaprov_settings": {"mode": "on"},
            "lists": [{"name": "l1", "kind": "ip", "items": []}],
            "unowned_key": [],
        }
        nested = _nest_output(dict(output))
        assert nested["alphaprov"] == {
            "custom_rules": [{"ref": "r1"}],
            "settings": {"mode": "on"},
            "lists": [{"name": "l1", "kind": "ip", "items": []}],
        }
        assert nested["unowned_key"] == []
        assert "alpha_custom_rules" not in nested

        # And a written dump round-trips through the loader.
        from octorules.config import normalize_zone_format

        path = dump_zone_rules(
            "example.com",
            {},
            tmp_path,
            extra_sections={"alphaprov_settings": {"mode": "on"}},
        )
        data = yaml.safe_load(path.read_text())
        assert "alphaprov" in data
        flat = normalize_zone_format(data, source="dumped")
        assert flat["alphaprov_settings"] == {"mode": "on"}

    def test_dump_without_namespaces_unchanged(self):
        from octorules.dumper import _nest_output

        output = {"some_phase": [], "lists": []}
        assert _nest_output(output) is output

    def test_dump_two_namespaces_split_blocks(self, namespaces):
        from octorules.dumper import _nest_output

        nested = _nest_output(
            {
                "alpha_custom_rules": [{"ref": "a"}],
                "beta_custom_rules": [{"ref": "b"}],
            }
        )
        assert nested == {
            "alphaprov": {"custom_rules": [{"ref": "a"}]},
            "betaprov": {"custom_rules": [{"ref": "b"}]},
        }

    def test_dump_folds_scoped_core_sections_into_blocks(self, namespaces):
        """Namespace-scoped core sections ("alphaprov:lists") fold into
        their namespace block instead of leaking as top-level keys."""
        from octorules.dumper import _nest_output

        nested = _nest_output(
            {
                "alpha_custom_rules": [{"ref": "a"}],
                "alphaprov:lists": [{"name": "al"}],
                "betaprov:lists": [{"name": "bl"}],
            }
        )
        assert nested == {
            "alphaprov": {"custom_rules": [{"ref": "a"}], "lists": [{"name": "al"}]},
            "betaprov": {"lists": [{"name": "bl"}]},
        }
        # Even with no owned keys at all, scoped sections still nest.
        only_scoped = _nest_output({"alphaprov:lists": [{"name": "al"}]})
        assert only_scoped == {"alphaprov": {"lists": [{"name": "al"}]}}


class TestDottedPhaseFilter:
    def test_dotted_phase_resolves_to_flat_name(self, namespaces):
        from octorules.commands._helpers import _validate_phases
        from octorules.phases import Phase, register_phase, unregister_phase

        register_phase(Phase("alpha_custom_rules", "alpha_custom", None))
        try:
            assert _validate_phases(["alphaprov.custom_rules"]) == ["alpha_custom_rules"]
            assert _validate_phases(["alpha_custom_rules"]) == ["alpha_custom_rules"]
        finally:
            unregister_phase("alpha_custom_rules")

    def test_unknown_dotted_phase_raises(self, namespaces):
        import pytest

        from octorules.commands._helpers import _validate_phases
        from octorules.config import ConfigError

        with pytest.raises(ConfigError):
            _validate_phases(["alphaprov.nope"])


class TestLintFileNested:
    def test_lint_file_accepts_nested_format(self, namespaces, tmp_path):
        from octorules.commands._lint import cmd_lint_file
        from octorules.phases import Phase, register_phase, unregister_phase

        register_phase(Phase("alpha_custom_rules", "alpha_custom", None))
        try:
            f = tmp_path / "zone.yaml"
            f.write_text("alphaprov:\n  custom_rules:\n    - ref: r1\n      expression: 'true'\n")
            assert cmd_lint_file(str(f)) == 0
        finally:
            unregister_phase("alpha_custom_rules")

    def test_lint_file_rejects_both_forms(self, namespaces, tmp_path):
        from octorules.commands._lint import cmd_lint_file

        f = tmp_path / "zone.yaml"
        f.write_text("alpha_custom_rules: []\nalphaprov:\n  custom_rules: []\n")
        assert cmd_lint_file(str(f)) == 1


class TestProviderView:
    def test_scopes_to_namespace(self, namespaces):
        from octorules.commands._helpers import _provider_view

        class _Alpha:
            NAMESPACE = "alphaprov"

        merged = {
            "alpha_custom_rules": [{"ref": "a"}],
            "alphaprov_settings": {"mode": "on"},
            "beta_custom_rules": [{"ref": "b"}],
            "betaprov_shield": {},
            "alphaprov:lists": [{"name": "al"}],
            "betaprov:lists": [{"name": "bl"}],
            "plan_outputs": [{"type": "text"}],
        }
        view = _provider_view(merged, _Alpha())
        assert view == {
            "alpha_custom_rules": [{"ref": "a"}],
            "alphaprov_settings": {"mode": "on"},
            "lists": [{"name": "al"}],
            "plan_outputs": [{"type": "text"}],
        }

    def test_provider_without_namespace_sees_everything(self, namespaces):
        from octorules.commands._helpers import _provider_view

        class _Legacy:
            pass

        merged = {"alpha_custom_rules": [], "beta_custom_rules": []}
        assert _provider_view(merged, _Legacy()) is merged


class TestSuppressionsNested:
    def test_directive_anchors_at_nested_indentation(self, namespaces, tmp_path):
        from octorules.linter.suppressions import parse_suppressions

        f = tmp_path / "zone.yaml"
        f.write_text(
            "alphaprov:\n"
            "  custom_rules:\n"
            "    # octorules:disable=CF010\n"
            "    - ref: r1\n"
            "      expression: 'true'\n"
        )
        result = parse_suppressions(f, known_rules={"CF010"})
        assert result.get("r1") == {"CF010"}


class TestPerTargetZoneIdentity:
    """Multi-provider zones resolve one id per target; zone_names maps a
    target to its provider-resource name (an AWS Web ACL can't be named
    like a DNS zone)."""

    def _config(self, tmp_path, zone_names=None):
        from octorules.config import Config, ProviderConfig, ZoneConfig

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir(exist_ok=True)
        return Config(
            rules_dir=rules_dir,
            providers={
                "cloudflare": ProviderConfig(name="cloudflare"),
                "aws": ProviderConfig(name="aws"),
            },
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    targets=["cloudflare", "aws"],
                    zone_names=zone_names or {},
                ),
            },
        )

    def test_each_target_resolves_its_own_id(self, tmp_path):
        from octorules.config import resolve_zone_ids

        config = self._config(tmp_path, zone_names={"aws": "example-com-alb"})
        seen: dict[str, str] = {}

        def cf_resolve(name):
            seen["cloudflare"] = name
            return "cf-hex-id"

        def aws_resolve(name):
            seen["aws"] = name
            return "acl-guid"

        resolve_zone_ids(config, {"cloudflare": cf_resolve, "aws": aws_resolve}, max_workers=1)
        cfg = config.zones["example.com"]
        assert cfg.zone_ids == {"cloudflare": "cf-hex-id", "aws": "acl-guid"}
        assert cfg.zone_id == "cf-hex-id"  # primary target
        assert cfg.zone_id_for("aws") == "acl-guid"
        assert cfg.zone_id_for("cloudflare") == "cf-hex-id"
        assert cfg.zone_id_for(None) == "cf-hex-id"
        # aws resolved the overridden resource name, CF the zone name.
        assert seen == {"cloudflare": "example.com", "aws": "example-com-alb"}

    def test_secondary_target_failure_warns_and_falls_back(self, tmp_path, caplog):
        from octorules.config import resolve_zone_ids

        config = self._config(tmp_path)

        def aws_resolve(name):
            raise RuntimeError("no such ACL")

        with caplog.at_level("WARNING", logger="octorules.config"):
            resolve_zone_ids(
                config,
                {"cloudflare": lambda n: "cf-hex-id", "aws": aws_resolve},
                max_workers=1,
            )
        cfg = config.zones["example.com"]
        assert cfg.zone_id == "cf-hex-id"
        assert "aws" not in cfg.zone_ids
        assert cfg.zone_id_for("aws") == "cf-hex-id"  # fallback
        assert "falls back to the primary" in caplog.text

    def test_primary_target_failure_raises(self, tmp_path):
        import pytest

        from octorules.config import ConfigError, resolve_zone_ids

        config = self._config(tmp_path)

        def cf_resolve(name):
            raise RuntimeError("api down")

        with pytest.raises(ConfigError, match="Failed to resolve"):
            resolve_zone_ids(
                config,
                {"cloudflare": cf_resolve, "aws": lambda n: "acl-guid"},
                max_workers=1,
            )


class TestZoneNamesParsing:
    def _parse(self, zone_data):
        from octorules.config import ProviderConfig, _parse_zone

        providers = {
            "cloudflare": ProviderConfig(name="cloudflare"),
            "aws": ProviderConfig(name="aws"),
        }
        return _parse_zone("z", zone_data, set(providers), providers)

    def test_valid_zone_names(self):
        cfg = self._parse({"targets": ["cloudflare", "aws"], "zone_names": {"aws": "my-acl"}})
        assert cfg.zone_names == {"aws": "my-acl"}
        assert cfg.zone_name_for("aws") == "my-acl"
        assert cfg.zone_name_for("cloudflare") == "z"

    def test_zone_names_unknown_target_raises(self):
        import pytest

        from octorules.config import ConfigError

        with pytest.raises(ConfigError, match="not one of the zone's targets"):
            self._parse({"targets": ["cloudflare"], "zone_names": {"aws": "my-acl"}})

    def test_zone_names_non_string_value_raises(self):
        import pytest

        from octorules.config import ConfigError

        with pytest.raises(ConfigError, match="non-empty string"):
            self._parse({"targets": ["aws"], "zone_names": {"aws": 3}})

    def test_zone_names_on_template_raises(self):
        """A template expands to every discovered zone, so one
        provider-resource name would point them all at the same resource.
        It used to validate here and then be silently dropped by
        expand_templates()."""
        import pytest

        from octorules.config import ConfigError, ProviderConfig, _parse_zone

        providers = {
            "cloudflare": ProviderConfig(name="cloudflare"),
            "aws": ProviderConfig(name="aws"),
        }
        with pytest.raises(ConfigError, match="not supported on a zone template"):
            _parse_zone(
                "*",
                {"targets": ["cloudflare", "aws"], "zone_names": {"aws": "shared-acl"}},
                set(providers),
                providers,
            )

    def test_template_without_zone_names_is_fine(self):
        from octorules.config import ProviderConfig, _parse_zone

        providers = {"cloudflare": ProviderConfig(name="cloudflare")}
        cfg = _parse_zone("*", {"targets": ["cloudflare"]}, set(providers), providers)
        assert cfg.zone_names == {}


class TestScopedSectionsOfflinePaths:
    """Multi-provider files carry lists/custom_rulesets per namespace —
    lint, audit, and validate must see them."""

    def test_iter_scoped_sections(self, namespaces):
        from octorules.phases import iter_scoped_sections

        data = {
            "lists": [1],
            "alphaprov:lists": [2],
            "betaprov:lists": [3],
            "unregistered:lists": [4],
            "alphaprov:custom_rulesets": [5],
        }
        assert dict(iter_scoped_sections(data, "lists")) == {
            None: [1],
            "alphaprov": [2],
            "betaprov": [3],
        }

    def test_lint_plugin_view_unwraps_own_sections(self, namespaces):
        from octorules.linter.engine import _plugin_view

        data = {
            "alpha_custom_rules": [],
            "alphaprov:lists": [{"name": "al"}],
            "betaprov:lists": [{"name": "bl"}],
        }
        view = _plugin_view(data, "alphaprov")
        assert view["lists"] == [{"name": "al"}]
        assert "alphaprov:lists" not in view
        assert "betaprov:lists" not in view
        # Single-provider files (no scoped sections) pass through untouched.
        plain = {"lists": []}
        assert _plugin_view(plain, "alphaprov") is plain

    def test_audit_list_ip_map_aggregates_scoped_lists(self, namespaces):
        from octorules.audit import _build_list_ip_map

        data = {
            "alphaprov:lists": [
                {"name": "edge-blocked", "kind": "ip", "items": [{"ip": "198.51.100.0/24"}]}
            ],
            "betaprov:lists": [
                {"name": "origin-blocked", "kind": "ip", "items": [{"ip": "203.0.113.0/24"}]}
            ],
        }
        assert _build_list_ip_map(data) == {
            "alphaprov:edge-blocked": ["198.51.100.0/24"],
            "betaprov:origin-blocked": ["203.0.113.0/24"],
        }

    def test_audit_plain_lists_stay_unqualified(self):
        from octorules.audit import _build_list_ip_map

        data = {"lists": [{"name": "b", "kind": "ip", "items": [{"ip": "10.0.0.0/8"}]}]}
        assert _build_list_ip_map(data) == {"b": ["10.0.0.0/8"]}

    def test_lint_reports_scoped_list_errors(self, namespaces):
        """CORE008 names the namespace-scoped section of a bad list entry."""
        from octorules.commands._lint import _core_lint_zone
        from octorules.linter.engine import LintContext

        data = normalize_zone_format(
            {
                "alphaprov": {"lists": [{"name": "good", "kind": "ip", "items": []}]},
                "betaprov": {"lists": [{"name": "bad-no-kind", "items": []}]},
            },
            source="z.yaml",
        )
        ctx = LintContext(zone_name="z")
        _core_lint_zone(data, ctx)
        core008 = [r for r in ctx.results if r.rule_id == "CORE008"]
        assert len(core008) == 1
        assert "betaprov.lists" in core008[0].message
        assert "bad-no-kind" in core008[0].message


class TestAuditScopedListResolution:
    def test_rule_refs_resolve_qualified_lists_and_unreferenced_stay_flagged(self, namespaces):
        """Rules reference lists by bare name; multi-provider files store
        them namespace-qualified — refs must resolve and referenced lists
        must not reappear as unreferenced pseudo-rules."""
        from octorules.audit import RuleIPInfo, audit_zone_rules
        from octorules.extensions import (
            register_audit_extension,
            unregister_audit_extension,
        )

        def _extract(rules_data, phase_name):
            if phase_name != "alpha_custom_rules":
                return []
            return [
                RuleIPInfo(
                    zone_name="",
                    phase_name=phase_name,
                    ref="edge-rule",
                    action="block",
                    ip_ranges=[],
                    list_refs=["edge-blocked"],
                )
            ]

        register_audit_extension("test_scoped_lists", _extract)
        try:
            rules_data = {
                "alpha_custom_rules": [{"ref": "edge-rule"}],
                "alphaprov:lists": [
                    {"name": "edge-blocked", "kind": "ip", "items": [{"ip": "198.51.100.0/24"}]}
                ],
                "betaprov:lists": [
                    {"name": "origin-only", "kind": "ip", "items": [{"ip": "203.0.113.0/24"}]}
                ],
            }
            infos = audit_zone_rules(rules_data, "site.example")
        finally:
            unregister_audit_extension("test_scoped_lists")

        by_ref = {i.ref: i for i in infos}
        # The rule's bare ref resolved the qualified list's CIDRs.
        assert by_ref["edge-rule"].ip_ranges == ["198.51.100.0/24"]
        # The referenced list is NOT flagged unreferenced; the other one is.
        assert "list:alphaprov:edge-blocked" not in by_ref
        assert by_ref["list:betaprov:origin-only"].ip_ranges == ["203.0.113.0/24"]


class TestMultiClassEndToEnd:
    """Two provider classes share one nested zone file: each target plans
    with its own view and its own zone identity, and dump merges both
    classes into one nested file."""

    @pytest.fixture
    def setup(self, namespaces, tmp_path):
        from octorules.config import Config, ProviderConfig, ZoneConfig
        from octorules.phases import Phase, register_phase, unregister_phase

        register_phase(Phase("alpha_custom_rules", "alpha_custom", None))
        register_phase(Phase("beta_custom_rules", "beta_custom", None))

        class AlphaProvider:
            NAMESPACE = "alphaprov"
            account_id = None
            account_name = None

            def __init__(self):
                self.seen_scopes = []

            def get_all_phase_rules(self, scope, provider_ids=None):
                self.seen_scopes.append(scope)
                return {
                    "alpha_custom": [{"ref": "edge-rule", "expression": "true", "action": "block"}]
                }

        class BetaProvider:
            NAMESPACE = "betaprov"
            account_id = None
            account_name = None

            def __init__(self):
                self.seen_scopes = []

            def get_all_phase_rules(self, scope, provider_ids=None):
                self.seen_scopes.append(scope)
                return {
                    "beta_custom": [{"ref": "origin-rule", "expression": "true", "action": "block"}]
                }

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "site.example.yaml").write_text(
            "alphaprov:\n"
            "  custom_rules:\n"
            "    - ref: edge-rule\n"
            "      expression: 'true'\n"
            "      action: block\n"
            "betaprov:\n"
            "  custom_rules:\n"
            "    - ref: origin-rule\n"
            "      expression: 'true'\n"
            "      action: block\n"
        )
        config = Config(
            rules_dir=rules_dir,
            providers={
                "alpha": ProviderConfig(name="alpha"),
                "beta": ProviderConfig(name="beta"),
            },
            zones={
                "site.example": ZoneConfig(
                    name="site.example",
                    targets=["alpha", "beta"],
                    zone_id="alpha-id-1",
                    zone_ids={"alpha": "alpha-id-1", "beta": "beta-id-9"},
                ),
            },
        )
        try:
            yield config, AlphaProvider(), BetaProvider()
        finally:
            unregister_phase("alpha_custom_rules")
            unregister_phase("beta_custom_rules")

    def test_validator_allows_the_pair(self, setup):
        from octorules.commands._providers import _validate_multi_target

        config, alpha, beta = setup
        # Should not raise — both classes declare a NAMESPACE.
        _validate_multi_target(config, {"alpha": alpha, "beta": beta})

    def test_each_target_plans_its_own_view_and_identity(self, setup):
        from octorules.commands._plan import _plan_single_zone

        config, alpha, beta = setup
        _, zp_a, desired_a, _ = _plan_single_zone(
            config, alpha, "site.example", None, target_name="alpha"
        )
        _, zp_b, desired_b, _ = _plan_single_zone(
            config, beta, "site.example", None, target_name="beta"
        )
        # Per-target identity reached each provider.
        assert alpha.seen_scopes[0].zone_id == "alpha-id-1"
        assert beta.seen_scopes[0].zone_id == "beta-id-9"
        # Per-target views: each saw only its own sections.
        assert "alpha_custom_rules" in desired_a
        assert "beta_custom_rules" not in desired_a
        assert "beta_custom_rules" in desired_b
        assert "alpha_custom_rules" not in desired_b
        # Desired matches current on both sides — clean plans.
        assert not zp_a.has_changes
        assert not zp_b.has_changes

    def test_dump_merges_both_classes_into_one_nested_file(self, setup, tmp_path, monkeypatch):
        import yaml

        from octorules.commands import _dump
        from octorules.config import normalize_zone_format

        config, alpha, beta = setup
        monkeypatch.setattr(config, "resolve_secrets", lambda: None, raising=False)
        monkeypatch.setattr(
            _dump._providers_mod,
            "_init_providers",
            lambda cfg, zone_filter=None: {"alpha": alpha, "beta": beta},
        )
        monkeypatch.setattr(_dump._providers_mod, "write_zone_plans_cache", lambda cfg, provs: None)
        out = tmp_path / "out"
        assert _dump.cmd_dump(config, ["site.example"], str(out)) == 0
        data = yaml.safe_load((out / "site.example.yaml").read_text())
        assert "alphaprov" in data
        assert "betaprov" in data
        # Per-target scopes were used for the fetches.
        assert alpha.seen_scopes[-1].zone_id == "alpha-id-1"
        assert beta.seen_scopes[-1].zone_id == "beta-id-9"
        # The merged file round-trips through the loader.
        flat = normalize_zone_format(data, source="dumped")
        assert flat["alpha_custom_rules"][0]["ref"] == "edge-rule"
        assert flat["beta_custom_rules"][0]["ref"] == "origin-rule"


class TestNestedFormatThroughLoader:
    def test_nested_include_inside_namespace(self, namespaces, tmp_path):
        (tmp_path / "shared").mkdir()
        (tmp_path / "shared" / "settings.yaml").write_text("mode: 'on'\nlevel: 3\n")
        zone = tmp_path / "zone.yaml"
        zone.write_text(
            "alphaprov:\n"
            "  custom_rules:\n"
            "    - ref: r1\n"
            "  settings: !include 'shared/settings.yaml'\n"
        )
        data = _yaml_load(zone)
        result = normalize_zone_format(data, source=zone.name)
        assert result["alpha_custom_rules"] == [{"ref": "r1"}]
        assert result["alphaprov_settings"] == {"mode": "on", "level": 3}
