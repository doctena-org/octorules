"""Command implementations for the octorules CLI.

Internal symbols are still imported here so that existing
``from octorules.commands import _x`` imports keep working, but ``__all__``
lists only the supported surface. A leading underscore means the name may be
renamed or removed without notice; advertising such names in ``__all__`` said
the opposite.
"""

from octorules.commands._audit import cmd_audit
from octorules.commands._dump import cmd_dump
from octorules.commands._helpers import (
    _emit_plan_outputs as _emit_plan_outputs,
)
from octorules.commands._helpers import (
    _filter_current_by_phase as _filter_current_by_phase,
)
from octorules.commands._helpers import (
    _filter_desired_by_phase as _filter_desired_by_phase,
)
from octorules.commands._helpers import (
    _format_api_error as _format_api_error,
)
from octorules.commands._helpers import (
    _get_zones as _get_zones,
)
from octorules.commands._helpers import (
    _map_ordered as _map_ordered,
)
from octorules.commands._helpers import (
    _phase_filter_to_provider_ids as _phase_filter_to_provider_ids,
)
from octorules.commands._helpers import (
    _run_staged_tasks as _run_staged_tasks,
)
from octorules.commands._helpers import (
    _TaskList as _TaskList,
)
from octorules.commands._helpers import (
    _validate_phases as _validate_phases,
)
from octorules.commands._helpers import (
    _write_output_file as _write_output_file,
)
from octorules.commands._lint import cmd_lint, cmd_lint_file
from octorules.commands._plan import (
    _cmd_plan_or_compare as _cmd_plan_or_compare,
)
from octorules.commands._plan import (
    _plan_account as _plan_account,
)
from octorules.commands._plan import (
    _plan_all_scopes as _plan_all_scopes,
)
from octorules.commands._plan import (
    _plan_single_zone as _plan_single_zone,
)
from octorules.commands._plan import (
    _plan_single_zone_safe as _plan_single_zone_safe,
)
from octorules.commands._plan import (
    _plan_zones as _plan_zones,
)
from octorules.commands._plan import (
    _PlanAllResult as _PlanAllResult,
)
from octorules.commands._plan import (
    cmd_plan,
)
from octorules.commands._providers import (
    _collect_zone_plans as _collect_zone_plans,
)
from octorules.commands._providers import (
    _discover_provider_modules as _discover_provider_modules,
)
from octorules.commands._providers import (
    _discover_zones as _discover_zones,
)
from octorules.commands._providers import (
    _ensure_provider_loaded as _ensure_provider_loaded,
)
from octorules.commands._providers import (
    _get_zone_provider as _get_zone_provider,
)
from octorules.commands._providers import (
    _get_zone_providers as _get_zone_providers,
)
from octorules.commands._providers import (
    _init_processors as _init_processors,
)
from octorules.commands._providers import (
    _init_providers as _init_providers,
)
from octorules.commands._providers import (
    _load_provider_class as _load_provider_class,
)
from octorules.commands._providers import (
    _resolve_provider_class as _resolve_provider_class,
)
from octorules.commands._providers import (
    _validate_multi_target as _validate_multi_target,
)
from octorules.commands._providers import (
    read_zone_plans_cache,
    write_zone_plans_cache,
)
from octorules.commands._sync import (
    _CHECKSUM_RE as _CHECKSUM_RE,
)
from octorules.commands._sync import (
    SyncResult,
    cmd_sync,
)
from octorules.commands._sync import (
    _apply_custom_rulesets as _apply_custom_rulesets,
)
from octorules.commands._sync import (
    _apply_lists as _apply_lists,
)
from octorules.commands._sync import (
    _apply_single_zone as _apply_single_zone,
)
from octorules.commands._sync import (
    _apply_zone_changes as _apply_zone_changes,
)
from octorules.commands._sync import (
    _check_safety_violations as _check_safety_violations,
)
from octorules.commands._sync import (
    _cmd_sync_inner as _cmd_sync_inner,
)
from octorules.commands._sync import (
    _log_safety_violations as _log_safety_violations,
)
from octorules.commands._sync import (
    _make_account_zone_config as _make_account_zone_config,
)
from octorules.commands._sync import (
    _write_audit_log as _write_audit_log,
)
from octorules.commands._versions import cmd_versions

__all__ = [
    "SyncResult",
    "cmd_audit",
    "cmd_dump",
    "cmd_lint",
    "cmd_lint_file",
    "cmd_plan",
    "cmd_sync",
    "cmd_versions",
    "read_zone_plans_cache",
    "write_zone_plans_cache",
]
