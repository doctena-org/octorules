"""Tests for the phase registration API."""

import pytest

from octorules.phases import (
    ACCOUNT_PROVIDER_IDS,
    ALL_FRIENDLY_NAMES,
    ALL_PROVIDER_IDS,
    PHASE_BY_NAME,
    PHASE_BY_PROVIDER_ID,
    PHASES,
    RENAMED_PHASES,
    ZONE_PROVIDER_IDS,
    Phase,
    get_api_fields,
    get_phase,
    register_api_fields,
    register_phase,
    register_phase_alias,
    register_phases,
    strip_api_fields,
    unregister_api_fields,
    unregister_phase,
    unregister_phase_alias,
)


@pytest.fixture(autouse=True)
def _restore_registry():
    """Snapshot and restore the phase registry around each test."""
    from octorules.phases import _api_fields, _rebuild_derived

    orig_phases = list(PHASES)
    orig_aliases = dict(RENAMED_PHASES)
    orig_api_fields = {k: set(v) for k, v in _api_fields.items()}
    yield
    PHASES[:] = orig_phases
    RENAMED_PHASES.clear()
    RENAMED_PHASES.update(orig_aliases)
    for k in _api_fields:
        _api_fields[k] = orig_api_fields.get(k, set())
    _rebuild_derived()


TEST_PHASE = Phase("test_phase", "test_provider_id", "block")
TEST_PHASE_ACCOUNT = Phase(
    "test_account_phase", "test_account_provider_id", None, zone_level=False, account_level=True
)


class TestRegisterPhase:
    def test_register_phase_appears_in_all_dicts(self):
        register_phase(TEST_PHASE)
        assert TEST_PHASE.friendly_name in PHASE_BY_NAME
        assert TEST_PHASE.provider_id in PHASE_BY_PROVIDER_ID
        assert TEST_PHASE.friendly_name in ALL_FRIENDLY_NAMES
        assert TEST_PHASE.provider_id in ALL_PROVIDER_IDS
        assert TEST_PHASE.provider_id in ZONE_PROVIDER_IDS
        assert TEST_PHASE.provider_id not in ACCOUNT_PROVIDER_IDS
        assert get_phase("test_phase") is TEST_PHASE

    def test_register_account_phase(self):
        register_phase(TEST_PHASE_ACCOUNT)
        assert TEST_PHASE_ACCOUNT.provider_id in ACCOUNT_PROVIDER_IDS
        assert TEST_PHASE_ACCOUNT.provider_id not in ZONE_PROVIDER_IDS

    def test_register_duplicate_name_raises(self):
        register_phase(TEST_PHASE)
        with pytest.raises(ValueError, match="already registered"):
            register_phase(Phase("test_phase", "different_cf", "block"))

    def test_register_duplicate_provider_id_raises(self):
        register_phase(TEST_PHASE)
        with pytest.raises(ValueError, match="already registered"):
            register_phase(Phase("different_name", "test_provider_id", "block"))

    def test_existing_phases_intact_after_registration(self):
        original_count = len(PHASES)
        register_phase(TEST_PHASE)
        assert len(PHASES) == original_count + 1
        # Existing phases still there
        assert (
            get_phase("fakeprov.redirect_rules").provider_id == "fake_http_request_dynamic_redirect"
        )
        assert (
            get_phase("fakeprov.waf_custom_rules").provider_id
            == "fake_http_request_firewall_custom"
        )

    def test_register_preserves_aliases(self):
        """waf_managed_exceptions alias should survive registration."""
        register_phase(TEST_PHASE)
        assert "waf_managed_exceptions" in PHASE_BY_NAME
        assert (
            PHASE_BY_NAME["waf_managed_exceptions"] is PHASE_BY_NAME["fakeprov.waf_managed_rules"]
        )


class TestUnregisterPhase:
    def test_unregister_phase_removes_from_all_dicts(self):
        register_phase(TEST_PHASE)
        unregister_phase("test_phase")
        assert "test_phase" not in PHASE_BY_NAME
        assert "test_provider_id" not in PHASE_BY_PROVIDER_ID
        assert "test_phase" not in ALL_FRIENDLY_NAMES
        assert "test_provider_id" not in ALL_PROVIDER_IDS
        assert "test_provider_id" not in ZONE_PROVIDER_IDS

    def test_unregister_nonexistent_raises(self):
        with pytest.raises(KeyError, match="not registered"):
            unregister_phase("nonexistent_phase")

    def test_unregister_aliased_phase_raises(self):
        """Cannot unregister a phase that has backward-compat aliases."""
        with pytest.raises(ValueError, match="backward-compat aliases"):
            unregister_phase("fakeprov.waf_managed_rules")


class TestRegisterPhases:
    def test_register_multiple(self):
        phases = [TEST_PHASE, TEST_PHASE_ACCOUNT]
        register_phases(phases)
        assert "test_phase" in PHASE_BY_NAME
        assert "test_account_phase" in PHASE_BY_NAME
        assert TEST_PHASE.provider_id in ALL_PROVIDER_IDS
        assert TEST_PHASE_ACCOUNT.provider_id in ALL_PROVIDER_IDS

    def test_atomic_on_duplicate(self):
        """If any phase in the batch conflicts, none are registered."""
        existing_name = PHASES[0].friendly_name
        phases = [TEST_PHASE, Phase(existing_name, "new_cf", "block")]
        with pytest.raises(ValueError, match="already registered"):
            register_phases(phases)
        # TEST_PHASE should NOT have been added
        assert "test_phase" not in PHASE_BY_NAME

    def test_duplicate_within_batch_raises(self):
        phases = [TEST_PHASE, Phase("test_phase", "different_cf", "block")]
        with pytest.raises(ValueError, match="Duplicate friendly_name"):
            register_phases(phases)


class TestModuleLevelImportSeesUpdates:
    def test_all_provider_ids_updated_in_place(self):
        """Modules that imported ALL_PROVIDER_IDS at module level see new phases."""
        from octorules.phases import ALL_PROVIDER_IDS as imported_ref

        register_phase(TEST_PHASE)
        assert TEST_PHASE.provider_id in imported_ref

    def test_zone_provider_ids_updated_in_place(self):
        from octorules.phases import ZONE_PROVIDER_IDS as imported_ref

        register_phase(TEST_PHASE)
        assert TEST_PHASE.provider_id in imported_ref

    def test_account_provider_id_phases_updated_in_place(self):
        from octorules.phases import ACCOUNT_PROVIDER_IDS as imported_ref

        register_phase(TEST_PHASE_ACCOUNT)
        assert TEST_PHASE_ACCOUNT.provider_id in imported_ref


class TestRegisterApiFields:
    def test_register_and_get(self):
        register_api_fields("rule", {"id", "version"})
        result = get_api_fields("rule")
        assert "id" in result
        assert "version" in result

    def test_register_accumulates(self):
        unregister_api_fields("rule")
        register_api_fields("rule", {"id"})
        register_api_fields("rule", {"version"})
        result = get_api_fields("rule")
        assert result == frozenset({"id", "version"})

    def test_get_returns_frozenset(self):
        register_api_fields("list_item", {"id"})
        result = get_api_fields("list_item")
        assert isinstance(result, frozenset)

    def test_get_empty_by_default(self):
        unregister_api_fields("rule")
        assert get_api_fields("rule") == frozenset()

    def test_unregister_clears(self):
        register_api_fields("rule", {"id", "version"})
        unregister_api_fields("rule")
        assert get_api_fields("rule") == frozenset()

    def test_register_auto_creates_category(self):
        register_api_fields("custom_entity", {"id"})
        try:
            assert get_api_fields("custom_entity") == frozenset({"id"})
        finally:
            unregister_api_fields("custom_entity")

    def test_get_unknown_category_raises(self):
        with pytest.raises(ValueError, match="Unknown API field category"):
            get_api_fields("nonexistent")

    def test_all_three_categories(self):
        register_api_fields("rule", {"id"})
        register_api_fields("list_item", {"created_on"})
        register_api_fields("page_shield_policy", {"last_updated"})
        assert "id" in get_api_fields("rule")
        assert "created_on" in get_api_fields("list_item")
        assert "last_updated" in get_api_fields("page_shield_policy")


class TestStripApiFields:
    def test_strips_registered_fields(self):
        register_api_fields("rule", {"id", "version"})
        obj = {"id": "abc", "version": "1", "expression": "true", "action": "block"}
        result = strip_api_fields(obj, "rule")
        assert result == {"expression": "true", "action": "block"}

    def test_returns_copy(self):
        register_api_fields("rule", {"id"})
        obj = {"id": "abc", "expression": "true"}
        result = strip_api_fields(obj, "rule")
        assert result is not obj

    def test_empty_api_fields(self):
        """When no API fields are registered, all keys are preserved."""
        obj = {"expression": "true", "action": "block"}
        result = strip_api_fields(obj, "rule")
        assert result == obj

    def test_unknown_category_raises(self):
        with pytest.raises(ValueError, match="Unknown API field category"):
            strip_api_fields({"a": 1}, "nonexistent")


class TestRegisterPhaseAlias:
    def test_register_alias(self):
        register_phase_alias("old_name", "fakeprov.redirect_rules")
        assert "old_name" in PHASE_BY_NAME
        assert PHASE_BY_NAME["old_name"] is PHASE_BY_NAME["fakeprov.redirect_rules"]

    def test_register_alias_appears_in_renamed_phases(self):
        register_phase_alias("old_name", "fakeprov.redirect_rules")
        assert RENAMED_PHASES["old_name"] == "fakeprov.redirect_rules"

    def test_unregister_alias(self):
        register_phase_alias("old_name", "fakeprov.redirect_rules")
        unregister_phase_alias("old_name")
        assert "old_name" not in PHASE_BY_NAME
        assert "old_name" not in RENAMED_PHASES

    def test_unregister_nonexistent_is_safe(self):
        unregister_phase_alias("nonexistent")  # no error

    def test_alias_survives_phase_registration(self):
        register_phase_alias("old_name", "fakeprov.redirect_rules")
        register_phase(TEST_PHASE)
        assert "old_name" in PHASE_BY_NAME
        assert PHASE_BY_NAME["old_name"] is PHASE_BY_NAME["fakeprov.redirect_rules"]

    def test_alias_to_nonexistent_phase_is_silently_ignored(self):
        register_phase_alias("alias", "nonexistent_phase")
        assert "alias" not in PHASE_BY_NAME
