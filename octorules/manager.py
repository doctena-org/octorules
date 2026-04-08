"""High-level orchestrator for octorules operations."""

import logging
from pathlib import Path

from octorules.commands import (
    _validate_phases,
    cmd_audit,
    cmd_dump,
    cmd_lint,
    cmd_plan,
    cmd_sync,
)
from octorules.config import Config

log = logging.getLogger(__name__)


class Manager:
    """High-level orchestrator for octorules operations.

    Wraps ``Config.from_file()`` and delegates to ``cmd_*`` functions,
    providing a clean Python API for all octorules operations.

    Each command method initialises providers and processors internally
    (matching the CLI behaviour), so the Manager is stateless between
    calls — no leaked API sessions or stale provider state.

    Usage::

        with Manager("config.yaml") as mgr:
            mgr.plan()
            mgr.sync(force=True)
    """

    def __init__(self, config: Config | str | Path) -> None:
        if isinstance(config, Config):
            self.config = config
        else:
            self.config = Config.from_file(config)

    def plan(
        self,
        *,
        zones: list[str] | None = None,
        phases: list[str] | None = None,
        scope: str = "all",
        checksum: bool = False,
        exit_code: bool = False,
    ) -> int:
        """Run the plan command. Returns exit code."""
        _validate_phases(phases)
        return cmd_plan(
            self.config,
            zones,
            phase_filter=phases,
            checksum=checksum,
            exit_code=exit_code,
            scope_filter=scope,
        )

    def sync(
        self,
        *,
        zones: list[str] | None = None,
        phases: list[str] | None = None,
        scope: str = "all",
        checksum: str | None = None,
        force: bool = False,
    ) -> int:
        """Run the sync command. Returns exit code."""
        _validate_phases(phases)
        return cmd_sync(
            self.config,
            zones,
            phase_filter=phases,
            checksum=checksum,
            force=force,
            scope_filter=scope,
        )

    def dump(
        self,
        *,
        zones: list[str] | None = None,
        phases: list[str] | None = None,
        scope: str = "all",
        output_dir: str | None = None,
    ) -> int:
        """Run the dump command. Returns exit code."""
        _validate_phases(phases)
        return cmd_dump(
            self.config,
            zones,
            output_dir,
            scope_filter=scope,
            phase_filter=phases,
        )

    def lint(
        self,
        *,
        zones: list[str] | None = None,
        phases: list[str] | None = None,
        format: str = "text",
        severity: str = "info",
        rules: list[str] | None = None,
        plan: str | None = None,
        output: str | None = None,
        exit_code: bool = False,
    ) -> int:
        """Run the lint command. Returns exit code."""
        _validate_phases(phases)
        return cmd_lint(
            self.config,
            zones,
            phase_filter=phases,
            lint_format=format,
            lint_severity=severity,
            lint_rules=rules,
            lint_plan=plan,
            output_file=output,
            exit_code=exit_code,
        )

    def audit(
        self,
        *,
        zones: list[str] | None = None,
        phases: list[str] | None = None,
        checks: list[str] | None = None,
        cdn_timeout: int = 15,
        cdn_stale_days: int = 60,
        severity: str = "info",
        exit_code: bool = False,
        audit_format: str = "text",
        output_file: str | None = None,
    ) -> int:
        """Run the audit command. Returns exit code."""
        _validate_phases(phases)
        return cmd_audit(
            self.config,
            zones,
            phase_filter=phases,
            checks=checks,
            cdn_timeout=cdn_timeout,
            cdn_stale_days=cdn_stale_days,
            severity=severity,
            exit_code=exit_code,
            audit_format=audit_format,
            output_file=output_file,
        )

    def close(self) -> None:
        """No-op — included for context manager protocol compatibility."""

    def __enter__(self) -> "Manager":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
