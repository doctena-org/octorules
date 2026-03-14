"""Tests for the phase registration API."""

from __future__ import annotations

import pytest

from octorules.phases import (
    ACCOUNT_CF_PHASES,
    ALL_CF_PHASES,
    ALL_FRIENDLY_NAMES,
    PHASE_BY_CF,
    PHASE_BY_NAME,
    PHASES,
    ZONE_CF_PHASES,
    Phase,
    get_phase,
    register_phase,
    register_phases,
    unregister_phase,
)


@pytest.fixture(autouse=True)
def _restore_registry():
    """Snapshot and restore the phase registry around each test."""
    orig_phases = list(PHASES)
    orig_by_name = dict(PHASE_BY_NAME)
    orig_by_cf = dict(PHASE_BY_CF)
    orig_friendly = list(ALL_FRIENDLY_NAMES)
    orig_all_cf = list(ALL_CF_PHASES)
    orig_zone_cf = list(ZONE_CF_PHASES)
    orig_account_cf = list(ACCOUNT_CF_PHASES)
    yield
    PHASES[:] = orig_phases
    PHASE_BY_NAME.clear()
    PHASE_BY_NAME.update(orig_by_name)
    PHASE_BY_CF.clear()
    PHASE_BY_CF.update(orig_by_cf)
    ALL_FRIENDLY_NAMES[:] = orig_friendly
    ALL_CF_PHASES[:] = orig_all_cf
    ZONE_CF_PHASES[:] = orig_zone_cf
    ACCOUNT_CF_PHASES[:] = orig_account_cf


TEST_PHASE = Phase("test_phase", "test_cf_phase", "block")
TEST_PHASE_ACCOUNT = Phase(
    "test_account_phase", "test_account_cf", None, zone_level=False, account_level=True
)


class TestRegisterPhase:
    def test_register_phase_appears_in_all_dicts(self):
        register_phase(TEST_PHASE)
        assert TEST_PHASE.friendly_name in PHASE_BY_NAME
        assert TEST_PHASE.cf_phase in PHASE_BY_CF
        assert TEST_PHASE.friendly_name in ALL_FRIENDLY_NAMES
        assert TEST_PHASE.cf_phase in ALL_CF_PHASES
        assert TEST_PHASE.cf_phase in ZONE_CF_PHASES
        assert TEST_PHASE.cf_phase not in ACCOUNT_CF_PHASES
        assert get_phase("test_phase") is TEST_PHASE

    def test_register_account_phase(self):
        register_phase(TEST_PHASE_ACCOUNT)
        assert TEST_PHASE_ACCOUNT.cf_phase in ACCOUNT_CF_PHASES
        assert TEST_PHASE_ACCOUNT.cf_phase not in ZONE_CF_PHASES

    def test_register_duplicate_name_raises(self):
        register_phase(TEST_PHASE)
        with pytest.raises(ValueError, match="already registered"):
            register_phase(Phase("test_phase", "different_cf", "block"))

    def test_register_duplicate_cf_phase_raises(self):
        register_phase(TEST_PHASE)
        with pytest.raises(ValueError, match="already registered"):
            register_phase(Phase("different_name", "test_cf_phase", "block"))

    def test_existing_phases_intact_after_registration(self):
        original_count = len(PHASES)
        register_phase(TEST_PHASE)
        assert len(PHASES) == original_count + 1
        # Existing phases still there
        assert get_phase("redirect_rules").cf_phase == "http_request_dynamic_redirect"
        assert get_phase("waf_custom_rules").cf_phase == "http_request_firewall_custom"

    def test_register_preserves_aliases(self):
        """waf_managed_exceptions alias should survive registration."""
        register_phase(TEST_PHASE)
        assert "waf_managed_exceptions" in PHASE_BY_NAME
        assert PHASE_BY_NAME["waf_managed_exceptions"] is PHASE_BY_NAME["waf_managed_rules"]


class TestUnregisterPhase:
    def test_unregister_phase_removes_from_all_dicts(self):
        register_phase(TEST_PHASE)
        unregister_phase("test_phase")
        assert "test_phase" not in PHASE_BY_NAME
        assert "test_cf_phase" not in PHASE_BY_CF
        assert "test_phase" not in ALL_FRIENDLY_NAMES
        assert "test_cf_phase" not in ALL_CF_PHASES
        assert "test_cf_phase" not in ZONE_CF_PHASES

    def test_unregister_nonexistent_raises(self):
        with pytest.raises(KeyError, match="not registered"):
            unregister_phase("nonexistent_phase")

    def test_unregister_aliased_phase_raises(self):
        """Cannot unregister a phase that has backward-compat aliases."""
        with pytest.raises(ValueError, match="backward-compat aliases"):
            unregister_phase("waf_managed_rules")


class TestRegisterPhases:
    def test_register_multiple(self):
        phases = [TEST_PHASE, TEST_PHASE_ACCOUNT]
        register_phases(phases)
        assert "test_phase" in PHASE_BY_NAME
        assert "test_account_phase" in PHASE_BY_NAME
        assert TEST_PHASE.cf_phase in ALL_CF_PHASES
        assert TEST_PHASE_ACCOUNT.cf_phase in ALL_CF_PHASES

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
    def test_all_cf_phases_updated_in_place(self):
        """Modules that imported ALL_CF_PHASES at module level see new phases."""
        from octorules.phases import ALL_CF_PHASES as imported_ref

        register_phase(TEST_PHASE)
        assert TEST_PHASE.cf_phase in imported_ref

    def test_zone_cf_phases_updated_in_place(self):
        from octorules.phases import ZONE_CF_PHASES as imported_ref

        register_phase(TEST_PHASE)
        assert TEST_PHASE.cf_phase in imported_ref

    def test_account_cf_phases_updated_in_place(self):
        from octorules.phases import ACCOUNT_CF_PHASES as imported_ref

        register_phase(TEST_PHASE_ACCOUNT)
        assert TEST_PHASE_ACCOUNT.cf_phase in imported_ref
