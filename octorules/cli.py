"""CLI entry point: plan, sync, dump, validate, versions."""

import argparse
import logging
import sys

from octorules import __version__
from octorules.commands import (
    _CHECKSUM_RE,
    _apply_custom_rulesets,
    _apply_lists,
    _apply_parallel,
    _discover_provider_modules,
    _emit_plan_outputs,
    _filter_current_by_phase,
    _filter_desired_by_phase,
    _format_api_error,
    _get_zones,
    _init_providers,
    _map_ordered,
    _plan_account,
    _plan_single_zone,
    _plan_single_zone_safe,
    _plan_zones,
    _validate_phases,
    _write_output_file,
    cmd_audit,
    cmd_compare,
    cmd_dump,
    cmd_lint,
    cmd_plan,
    cmd_report,
    cmd_sync,
    cmd_validate,
    cmd_versions,
)
from octorules.config import Config, ConfigError
from octorules.provider.exceptions import (
    ProviderAuthError,
)

log = logging.getLogger(__name__)

# Re-export everything from commands so that existing imports from octorules.cli
# continue to work (e.g. ``from octorules.cli import cmd_plan``).
__all__ = [
    "_CHECKSUM_RE",
    "_apply_custom_rulesets",
    "_apply_lists",
    "_apply_parallel",
    "_discover_provider_modules",
    "_emit_plan_outputs",
    "_filter_current_by_phase",
    "_filter_desired_by_phase",
    "_format_api_error",
    "_get_zones",
    "_init_providers",
    "_map_ordered",
    "_plan_account",
    "_plan_single_zone",
    "_plan_single_zone_safe",
    "_plan_zones",
    "_validate_phases",
    "_write_output_file",
    "build_parser",
    "cmd_audit",
    "cmd_compare",
    "cmd_dump",
    "cmd_lint",
    "cmd_plan",
    "cmd_report",
    "cmd_sync",
    "cmd_validate",
    "cmd_versions",
    "main",
]


def _positive_int(value: str) -> int:
    """Argparse type that rejects non-positive integers."""
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}") from None
    if n <= 0:
        raise argparse.ArgumentTypeError(f"value must be a positive integer (got {n})")
    return n


def build_parser() -> argparse.ArgumentParser:
    # Shared parent parser: allows global flags both before and after the subcommand.
    # Uses SUPPRESS defaults so subparser values don't overwrite the main parser's.
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--config", default=argparse.SUPPRESS)
    shared.add_argument("--zone", action="append", dest="zones", default=argparse.SUPPRESS)
    shared.add_argument("--phase", action="append", dest="phases", default=argparse.SUPPRESS)
    shared.add_argument("--scope", choices=["all", "zones", "account"], default=argparse.SUPPRESS)
    shared.add_argument("--debug", action="store_true", default=argparse.SUPPRESS)
    shared.add_argument("--quiet", action="store_true", default=argparse.SUPPRESS)

    parser = argparse.ArgumentParser(
        prog="octorules",
        description="WAF rules as code — manage rules across providers declaratively",
    )
    parser.add_argument("--version", action="version", version=f"octorules {__version__}")
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config file (default: config.yaml)",
    )
    parser.add_argument(
        "--zone",
        action="append",
        dest="zones",
        help="Process only specified zone(s); can be repeated (default: all zones)",
    )

    parser.add_argument(
        "--phase",
        action="append",
        dest="phases",
        help=(
            "Only process specified phase(s); can be repeated"
            " (e.g. --phase redirect_rules --phase cache_rules)."
            " Also limits API calls to matching phases."
        ),
    )

    parser.add_argument(
        "--scope",
        choices=["all", "zones", "account"],
        default="all",
        help="Process zones only, account only, or both (default: all)",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress informational output. Only errors and the exit code are reported.",
    )

    sub = parser.add_subparsers(dest="command")

    plan_parser = sub.add_parser("plan", parents=[shared], help="Show planned changes (dry-run)")
    plan_parser.add_argument(
        "--checksum",
        action="store_true",
        help="Print a SHA-256 checksum of the plan"
        " (use with 'sync --checksum HASH' for drift protection)",
    )
    plan_parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with 2 when changes are detected (useful for CI)",
    )

    sync_parser = sub.add_parser("sync", parents=[shared], help="Apply changes to provider")
    sync_parser.add_argument(
        "--doit",
        action="store_true",
        required=True,
        help="Confirm that changes should be applied",
    )
    sync_parser.add_argument(
        "--checksum",
        metavar="HASH",
        help="Verify plan hasn't drifted since 'plan --checksum'; sync fails if state changed",
    )
    sync_parser.add_argument(
        "--force",
        action="store_true",
        help="Bypass safety threshold checks",
    )
    sync_parser.add_argument(
        "--audit-log",
        metavar="PATH",
        help="Write JSON lines audit log of sync results to PATH",
    )
    sync_parser.add_argument(
        "--format",
        dest="sync_format",
        choices=["text", "json"],
        default="text",
        help="Output format for sync results (default: text). 'json' prints structured results.",
    )

    validate_parser = sub.add_parser(
        "validate", parents=[shared], help="Validate config and rules files (offline)"
    )
    validate_parser.add_argument(
        "--output",
        dest="validate_output",
        help="Write validation results to a file",
    )
    validate_parser.add_argument(
        "--config-only",
        action="store_true",
        dest="config_only",
        help="Only validate config file structure (skip rules files)",
    )

    dump_parser = sub.add_parser("dump", parents=[shared], help="Export existing rules to YAML")
    dump_parser.add_argument(
        "--output-dir",
        help="Output directory for dumped rules (default: rules_dir from config)",
    )

    compare_parser = sub.add_parser(
        "compare", parents=[shared], help="Compare local rules against live provider state"
    )
    compare_parser.add_argument(
        "--checksum",
        action="store_true",
        help="Print a SHA-256 checksum of the comparison plan",
    )

    report_parser = sub.add_parser(
        "report", parents=[shared], help="Drift report: deployed vs YAML source of truth"
    )
    report_parser.add_argument(
        "--output-format",
        choices=["csv", "json"],
        default="csv",
        dest="report_format",
        help="Report output format (default: csv)",
    )

    lint_parser = sub.add_parser(
        "lint", parents=[shared], help="Lint rules files for errors and warnings"
    )
    lint_parser.add_argument(
        "--format",
        dest="lint_format",
        choices=["text", "json", "sarif", "summary"],
        default="text",
        help="Output format (default: text). 'summary' prints counts only.",
    )
    lint_parser.add_argument(
        "--severity",
        dest="lint_severity",
        choices=["error", "warning", "info"],
        default="info",
        help="Minimum severity to report (default: info)",
    )
    lint_parser.add_argument(
        "--rule",
        action="append",
        dest="lint_rules",
        help="Only check specific rule ID(s); can be repeated",
    )
    lint_parser.add_argument(
        "--plan",
        dest="lint_plan",
        default=None,
        help="Plan tier for entitlement checks "
        "(e.g. free/pro/business/enterprise). "
        "Defaults to 'enterprise' when omitted.",
    )
    lint_parser.add_argument(
        "--output",
        dest="lint_output",
        help="Write lint results to a file",
    )
    lint_parser.add_argument(
        "--exit-code",
        action="store_true",
        dest="lint_exit_code",
        help="Exit with 1 when errors are found, 2 when warnings are found (useful for CI)",
    )

    audit_parser = sub.add_parser(
        "audit",
        parents=[shared],
        help="Audit rules for cross-rule IP overlaps, CDN ranges, and zone drift",
    )
    audit_parser.add_argument(
        "--check",
        action="append",
        dest="audit_checks",
        help="Only run specific check(s); can be repeated"
        " (ip-overlap, ip-shadow, cdn-ranges, zone-drift)",
    )
    audit_parser.add_argument(
        "--cdn-timeout",
        type=_positive_int,
        default=15,
        dest="cdn_timeout",
        help="Timeout in seconds for CDN range API fetches (default: 15)",
    )
    audit_parser.add_argument(
        "--cdn-stale-days",
        type=_positive_int,
        default=60,
        dest="cdn_stale_days",
        help="Warn if baked-in CDN ranges are older than this many days (default: 60)",
    )
    audit_parser.add_argument(
        "--severity",
        dest="audit_severity",
        choices=["error", "warning", "info"],
        default="info",
        help="Minimum severity to report (default: info)",
    )
    audit_parser.add_argument(
        "--format",
        dest="audit_format",
        choices=["text", "json", "summary"],
        default="text",
        help="Output format (default: text). 'summary' prints counts only.",
    )
    audit_parser.add_argument(
        "--output",
        dest="audit_output",
        help="Write audit results to a file",
    )
    audit_parser.add_argument(
        "--exit-code",
        action="store_true",
        dest="audit_exit_code",
        help="Exit with 1 when errors are found, 2 when warnings are found (useful for CI)",
    )

    sub.add_parser("versions", parents=[shared], help="Show versions of octorules and dependencies")
    completion_parser = sub.add_parser(
        "completion",
        help="Print shell completion script",
    )
    completion_parser.add_argument(
        "shell",
        nargs="?",
        default="bash",
        choices=["bash", "zsh", "tcsh"],
        help="Shell type (default: bash)",
    )

    # Provide defaults for subcommand-specific attributes so getattr is never needed
    parser.set_defaults(
        checksum=False,
        force=False,
        validate_output=None,
        output_dir=None,
        report_format="csv",
        scope="all",
        lint_format="text",
        lint_severity="info",
        lint_rules=None,
        lint_plan="enterprise",
        lint_output=None,
        lint_exit_code=False,
        audit_checks=None,
        cdn_timeout=15,
        cdn_stale_days=60,
        audit_severity="info",
        audit_format="text",
        audit_output=None,
        audit_exit_code=False,
        audit_log=None,
        sync_format="text",
        config_only=False,
        shell="bash",
    )

    return parser


def _setup_logging(*, debug: bool = False, quiet: bool = False) -> None:
    """Configure the octorules logger."""
    if debug:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    else:
        level = logging.INFO
    # Configure the core logger with a handler, then set the level on all
    # octorules_* provider loggers so __name__-based loggers propagate output.
    # Discovers provider loggers from sys.modules (already imported by entry-
    # point discovery) instead of scanning installed packages — avoids the
    # ~130ms cost of importlib.metadata.packages_distributions().
    from octorules._color import ColoredFormatter, supports_color

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ColoredFormatter(use_color=supports_color(sys.stderr)))

    names = {"octorules"}
    for mod_name in sys.modules:
        if mod_name.startswith("octorules_") and "." not in mod_name:
            names.add(mod_name)

    for name in sorted(names):
        logger = logging.getLogger(name)
        logger.setLevel(level)
        if not logger.handlers:
            logger.addHandler(handler)
        else:
            for h in logger.handlers:
                h.setLevel(level)


_EXIT_MESSAGES: dict[str, dict[int, str]] = {
    "plan": {0: "success", 1: "error", 2: "changes detected"},
    "sync": {0: "success", 1: "error"},
    "compare": {0: "identical", 1: "differences detected"},
    "lint": {0: "clean", 1: "errors found", 2: "warnings only"},
    "audit": {0: "clean", 1: "errors found", 2: "warnings only"},
    "validate": {0: "valid", 1: "errors found"},
    "dump": {0: "success", 1: "error"},
    "report": {0: "success", 1: "error"},
}


def _exit(command: str, code: int, elapsed: float | None = None) -> None:
    """Print exit summary to stderr and exit."""
    msg = _EXIT_MESSAGES.get(command, {}).get(code, "")
    parts = [f"octorules {command}: exit {code}"]
    if msg:
        parts[0] += f" ({msg})"
    if elapsed is not None:
        parts.append(f"{elapsed:.1f}s")
    print(" ".join(parts), file=sys.stderr)
    sys.exit(code)


def main(argv: list[str] | None = None) -> None:
    """Main entry point."""
    import time

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    _setup_logging(debug=args.debug, quiet=args.quiet)

    from octorules._context import set_quiet

    set_quiet(args.quiet)

    # When --zone is specified without explicit --scope, skip account processing.
    if args.zones and args.scope == "all":
        args.scope = "zones"

    # Commands that don't need config
    if args.command == "versions":
        sys.exit(cmd_versions())
    if args.command == "completion":
        import shtab

        print(shtab.complete(build_parser(), args.shell))
        sys.exit(0)

    t0 = time.monotonic()
    command = args.command

    try:
        config = Config.from_file(args.config)
        phase_filter = _validate_phases(args.phases)

        if command == "plan":
            _exit(
                command,
                cmd_plan(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    checksum=args.checksum,
                    exit_code=args.exit_code,
                    scope_filter=args.scope,
                ),
                time.monotonic() - t0,
            )
        elif command == "sync":
            code = cmd_sync(
                config,
                args.zones,
                phase_filter=phase_filter,
                checksum=args.checksum,
                force=args.force,
                scope_filter=args.scope,
                audit_log=args.audit_log,
                sync_format=args.sync_format,
            )
            _exit(command, code, time.monotonic() - t0)
        elif command == "compare":
            _exit(
                command,
                cmd_compare(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    checksum=args.checksum,
                    scope_filter=args.scope,
                ),
                time.monotonic() - t0,
            )
        elif command == "report":
            _exit(
                command,
                cmd_report(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    report_format=args.report_format,
                    scope_filter=args.scope,
                ),
                time.monotonic() - t0,
            )
        elif command == "lint":
            # Import provider modules to trigger lint plugin registration,
            # without constructing provider instances (no API credentials needed).
            _discover_provider_modules()
            zone_plans: dict[str, str] = {}
            _exit(
                command,
                cmd_lint(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    lint_format=args.lint_format,
                    lint_severity=args.lint_severity,
                    lint_rules=args.lint_rules,
                    lint_plan=args.lint_plan,
                    zone_plans=zone_plans,
                    output_file=args.lint_output,
                    exit_code=args.lint_exit_code,
                ),
                time.monotonic() - t0,
            )
        elif command == "audit":
            _exit(
                command,
                cmd_audit(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    checks=args.audit_checks,
                    cdn_timeout=args.cdn_timeout,
                    cdn_stale_days=args.cdn_stale_days,
                    severity=args.audit_severity,
                    exit_code=args.audit_exit_code,
                    audit_format=args.audit_format,
                    output_file=args.audit_output,
                ),
                time.monotonic() - t0,
            )
        elif command == "validate":
            if args.config_only:
                log.info("Config valid.")
                _exit(command, 0, time.monotonic() - t0)
            _exit(
                command,
                cmd_validate(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    output_file=args.validate_output,
                ),
                time.monotonic() - t0,
            )
        elif command == "dump":
            _exit(
                command,
                cmd_dump(
                    config,
                    args.zones,
                    args.output_dir,
                    scope_filter=args.scope,
                    phase_filter=phase_filter,
                ),
                time.monotonic() - t0,
            )
    except ConfigError as e:
        log.error("Config error: %s", e)
        _exit(command, 1, time.monotonic() - t0)
    except ProviderAuthError as e:
        log.error("Authentication failed: %s", _format_api_error(e))
        _exit(command, 1, time.monotonic() - t0)
