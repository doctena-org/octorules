"""CLI entry point: plan, sync, dump, validate, versions."""

from __future__ import annotations

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
    _init_provider,
    _init_providers,
    _map_ordered,
    _plan_account,
    _plan_single_zone,
    _plan_single_zone_safe,
    _plan_zones,
    _validate_phases,
    _write_output_file,
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
    "_discover_provider_modules",
    "_apply_lists",
    "_apply_parallel",
    "_emit_plan_outputs",
    "_filter_current_by_phase",
    "_filter_desired_by_phase",
    "_format_api_error",
    "_get_zones",
    "_init_provider",
    "_init_providers",
    "_map_ordered",
    "_plan_account",
    "_plan_single_zone",
    "_plan_single_zone_safe",
    "_plan_zones",
    "_validate_phases",
    "_write_output_file",
    "build_parser",
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
        help="Only show errors",
    )

    sub = parser.add_subparsers(dest="command")

    plan_parser = sub.add_parser("plan", parents=[shared], help="Show planned changes (dry-run)")
    plan_parser.add_argument(
        "--checksum",
        action="store_true",
        help="Print a SHA-256 checksum of the plan",
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
        help="Verify plan checksum before applying",
    )
    sync_parser.add_argument(
        "--force",
        action="store_true",
        help="Bypass safety threshold checks",
    )

    validate_parser = sub.add_parser(
        "validate", parents=[shared], help="Validate config and rules files (offline)"
    )
    validate_parser.add_argument(
        "--output",
        dest="validate_output",
        help="Write validation results to a file",
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
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
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
        help="Plan tier override for entitlement checks "
        "(e.g. free/pro/business/enterprise). "
        "When omitted, auto-detected from the provider API per zone.",
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

    sub.add_parser("versions", parents=[shared], help="Show versions of octorules and dependencies")

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
    # Uses importlib.metadata to discover installed provider packages dynamically.
    from importlib.metadata import packages_distributions

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))

    names = {"octorules"}
    for pkg_name in packages_distributions():
        if pkg_name.startswith("octorules_"):
            names.add(pkg_name)

    for name in sorted(names):
        logger = logging.getLogger(name)
        logger.setLevel(level)
        if not logger.handlers:
            logger.addHandler(handler)
        else:
            for h in logger.handlers:
                h.setLevel(level)


def main(argv: list[str] | None = None) -> None:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    _setup_logging(debug=args.debug, quiet=args.quiet)

    # When --zone is specified without explicit --scope, skip account processing.
    if args.zones and args.scope == "all":
        args.scope = "zones"

    # versions doesn't need config
    if args.command == "versions":
        sys.exit(cmd_versions())

    try:
        config = Config.from_file(args.config)
        phase_filter = _validate_phases(args.phases)

        if args.command == "plan":
            sys.exit(
                cmd_plan(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    checksum=args.checksum,
                    exit_code=args.exit_code,
                    scope_filter=args.scope,
                )
            )
        elif args.command == "sync":
            sys.exit(
                cmd_sync(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    checksum=args.checksum,
                    force=args.force,
                    scope_filter=args.scope,
                )
            )
        elif args.command == "compare":
            sys.exit(
                cmd_compare(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    checksum=args.checksum,
                    scope_filter=args.scope,
                )
            )
        elif args.command == "report":
            sys.exit(
                cmd_report(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    report_format=args.report_format,
                    scope_filter=args.scope,
                )
            )
        elif args.command == "lint":
            # Import provider modules to trigger lint plugin registration,
            # without constructing provider instances (no API credentials needed).
            _discover_provider_modules()
            zone_plans: dict[str, str] = {}
            sys.exit(
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
                )
            )
        elif args.command == "validate":
            sys.exit(
                cmd_validate(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    output_file=args.validate_output,
                )
            )
        elif args.command == "dump":
            sys.exit(
                cmd_dump(
                    config,
                    args.zones,
                    args.output_dir,
                    scope_filter=args.scope,
                    phase_filter=phase_filter,
                )
            )
    except ConfigError as e:
        log.error("Config error: %s", e)
        sys.exit(1)
    except ProviderAuthError as e:
        log.error("Authentication failed: %s", _format_api_error(e))
        sys.exit(1)
