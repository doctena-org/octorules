"""CLI entry point: plan, sync, dump, lint, audit, versions."""

import argparse
import logging
import sys

from octorules import __version__
from octorules.commands import (
    _CHECKSUM_RE as _CHECKSUM_RE,
)
from octorules.commands import (
    _apply_custom_rulesets as _apply_custom_rulesets,
)
from octorules.commands import (
    _apply_lists as _apply_lists,
)
from octorules.commands import (
    _discover_provider_modules as _discover_provider_modules,
)
from octorules.commands import (
    _emit_plan_outputs as _emit_plan_outputs,
)
from octorules.commands import (
    _ensure_provider_loaded as _ensure_provider_loaded,
)
from octorules.commands import (
    _filter_current_by_phase as _filter_current_by_phase,
)
from octorules.commands import (
    _filter_desired_by_phase as _filter_desired_by_phase,
)
from octorules.commands import (
    _format_api_error as _format_api_error,
)
from octorules.commands import (
    _get_zones as _get_zones,
)
from octorules.commands import (
    _init_providers as _init_providers,
)
from octorules.commands import (
    _map_ordered as _map_ordered,
)
from octorules.commands import (
    _plan_account as _plan_account,
)
from octorules.commands import (
    _plan_single_zone as _plan_single_zone,
)
from octorules.commands import (
    _plan_single_zone_safe as _plan_single_zone_safe,
)
from octorules.commands import (
    _plan_zones as _plan_zones,
)
from octorules.commands import (
    _validate_phases as _validate_phases,
)
from octorules.commands import (
    _write_output_file as _write_output_file,
)
from octorules.commands import (
    cmd_audit,
    cmd_dump,
    cmd_lint,
    cmd_plan,
    cmd_sync,
    cmd_versions,
)
from octorules.config import Config, ConfigError
from octorules.provider.exceptions import (
    ProviderAuthError,
)

log = logging.getLogger(__name__)

# Re-export from commands so that existing imports from octorules.cli continue
# to work (e.g. ``from octorules.cli import cmd_plan``). ``__all__`` names only
# the supported surface; underscore-prefixed helpers stay importable but are not
# part of it.
__all__ = [
    "build_parser",
    "cmd_audit",
    "cmd_dump",
    "cmd_lint",
    "cmd_plan",
    "cmd_sync",
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
    shared.add_argument("--config", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    _shared_zone = shared.add_argument(
        "--zone",
        action="append",
        dest="zones",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    _shared_zone.complete = {"bash": "_octorules_zone_complete", "zsh": "_octorules_zone_complete"}
    shared.add_argument(
        "--phase", action="append", dest="phases", default=argparse.SUPPRESS, help=argparse.SUPPRESS
    )
    shared.add_argument(
        "--scope",
        choices=["all", "zones", "account"],
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    shared.add_argument(
        "--debug", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS
    )
    shared.add_argument(
        "--quiet", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS
    )
    shared.add_argument(
        "--syslog", metavar="ADDRESS", default=argparse.SUPPRESS, help=argparse.SUPPRESS
    )

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
    _main_zone = parser.add_argument(
        "--zone",
        action="append",
        dest="zones",
        help="Process only specified zone(s); can be repeated (default: all zones)",
    )
    _main_zone.complete = {"bash": "_octorules_zone_complete", "zsh": "_octorules_zone_complete"}

    parser.add_argument(
        "--phase",
        action="append",
        dest="phases",
        help=(
            "Only process specified phase(s); can be repeated"
            " (e.g. --phase cloudflare.redirect_rules"
            " --phase aws.waf_custom_rules)."
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
    parser.add_argument(
        "--syslog",
        metavar="ADDRESS",
        default=None,
        help="Send logs to syslog (host:port for UDP, or /path/to/socket)",
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

    dump_parser = sub.add_parser("dump", parents=[shared], help="Export existing rules to YAML")
    dump_parser.add_argument(
        "--output-dir",
        help="Output directory for dumped rules (default: rules_dir from config)",
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
        metavar="FILE",
        dest="lint_output",
        help="Write lint results to a file",
    )
    lint_parser.add_argument(
        "--exit-code",
        action="store_true",
        dest="lint_exit_code",
        help="Exit with 1 when errors are found, 2 when warnings are found (useful for CI)",
    )
    lint_parser.add_argument(
        "--config-only",
        action="store_true",
        dest="config_only",
        help="Only validate config file structure (skip rules files)",
    )
    lint_parser.add_argument(
        "file",
        nargs="?",
        default=None,
        help="Lint a single rules file (no config needed). When omitted, "
        "uses the config file to discover all zones.",
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
        metavar="FILE",
        dest="audit_output",
        help="Write audit results to a file",
    )
    audit_parser.add_argument(
        "--exit-code",
        action="store_true",
        dest="audit_exit_code",
        help="Exit with 1 when errors are found, 2 when warnings are found (useful for CI)",
    )

    sub.add_parser("versions", help="Show versions of octorules and dependencies")
    completion_parser = sub.add_parser(
        "completion",
        help="Print shell completion script (re-run after adding/removing zones)",
    )
    completion_parser.add_argument(
        "shell",
        nargs="?",
        default="bash",
        choices=["bash", "zsh", "tcsh"],
        help="Shell type (default: bash)",
    )

    rule_parser = sub.add_parser("rule", help="Show lint rule details")
    rule_parser.add_argument(
        "pattern",
        nargs="?",
        default=None,
        help="Rule ID or prefix to filter (e.g. CF201, CF, CORE). "
        "Omit or use --all to show all rules.",
    )
    rule_parser.add_argument(
        "--all",
        action="store_true",
        dest="rule_all",
        help="List all available lint rules",
    )
    rule_parser.add_argument(
        "--format",
        dest="rule_format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    # Provide defaults for subcommand-specific attributes so getattr is never needed
    parser.set_defaults(
        checksum=False,
        force=False,
        output_dir=None,
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
        file=None,
        syslog=None,
    )

    return parser


# Shared logging state — stored by _setup_logging, used by
# configure_provider_logging to extend to late-imported providers.
_log_handler: logging.Handler | None = None
_log_level: int = logging.INFO
_configured_names: set[str] = set()


def configure_provider_logging() -> None:
    """Configure loggers for any octorules_* packages imported since the last call.

    Called after provider modules are imported (e.g. after
    ``_init_providers`` or ``_discover_provider_modules``) to ensure
    their loggers inherit the level and handler set by ``_setup_logging``.
    """
    if _log_handler is None:
        return
    for mod_name in sys.modules:
        if (
            mod_name.startswith("octorules")
            and "." not in mod_name
            and mod_name not in _configured_names
        ):
            logger = logging.getLogger(mod_name)
            logger.setLevel(_log_level)
            if _log_handler not in logger.handlers:
                logger.addHandler(_log_handler)
            _configured_names.add(mod_name)


def _setup_logging(
    *, debug: bool = False, quiet: bool = False, syslog_address: str | None = None
) -> None:
    """Configure logging for octorules.

    Sets up a shared handler on stderr with colored output.  Only
    configures loggers for packages already in ``sys.modules`` — call
    ``configure_provider_logging()`` after importing provider modules
    to extend logging to them.
    """
    global _log_handler, _log_level

    if debug:
        _log_level = logging.DEBUG
    elif quiet:
        _log_level = logging.WARNING
    else:
        _log_level = logging.INFO

    from octorules._color import ColoredFormatter, supports_color

    if _log_handler is None:
        _log_handler = logging.StreamHandler(sys.stderr)
        _log_handler.setFormatter(ColoredFormatter(use_color=supports_color(sys.stderr)))

    # Configure all currently-known octorules loggers.
    configure_provider_logging()

    # Update levels on already-configured loggers (handles second call).
    for name in _configured_names:
        logger = logging.getLogger(name)
        logger.setLevel(_log_level)
        for h in logger.handlers:
            h.setLevel(_log_level)

    # Attach syslog handler if requested.
    if syslog_address:
        from logging.handlers import SysLogHandler

        try:
            if ":" in syslog_address and not syslog_address.startswith("/"):
                host, port_str = syslog_address.rsplit(":", 1)
                address = (host, int(port_str))
            else:
                address = syslog_address
            syslog_handler = SysLogHandler(address=address)
            syslog_handler.setFormatter(logging.Formatter("octorules: %(message)s"))
            for name in _configured_names:
                logging.getLogger(name).addHandler(syslog_handler)
        except (OSError, ValueError) as e:
            logging.getLogger("octorules").warning(
                "Failed to configure syslog (%s): %s", syslog_address, e
            )


_EXIT_MESSAGES: dict[str, dict[int, str]] = {
    "plan": {0: "success", 1: "error", 2: "changes detected"},
    "sync": {0: "success", 1: "error"},
    "lint": {0: "clean", 1: "errors found", 2: "warnings only"},
    "audit": {0: "clean", 1: "errors found", 2: "warnings only"},
    "dump": {0: "success", 1: "error"},
}


def _exit(command: str, code: int, elapsed: float | None = None) -> None:
    """Print exit summary to stderr and exit.

    Suppressed when ``--quiet`` is active, unless the command failed (code != 0).
    """
    from octorules._context import is_quiet

    if not (is_quiet() and code == 0):
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

    _setup_logging(
        debug=args.debug,
        quiet=args.quiet,
        syslog_address=getattr(args, "syslog", None),
    )

    from octorules._context import set_quiet

    set_quiet(args.quiet)

    # When --zone is specified without explicit --scope, skip account processing.
    if args.zones and args.scope == "all":
        args.scope = "zones"

    # Commands that don't need config
    if args.command == "rule":
        _discover_provider_modules()
        from octorules.commands._lint import list_rules

        pattern = getattr(args, "pattern", None)
        show_all = getattr(args, "rule_all", False)
        if not pattern and not show_all:
            log.error("Specify a rule ID/prefix, or use --all to list all rules.")
            sys.exit(1)
        filters = [pattern] if pattern else None
        sys.exit(list_rules(fmt=getattr(args, "rule_format", "text"), filters=filters))
    if args.command == "versions":
        sys.exit(cmd_versions())
    if args.command == "completion":
        import shtab

        preamble: dict[str, str] = {}
        try:
            config = Config.from_file(args.config)
            zone_str = " ".join(sorted(config.zones.keys()))
            preamble["bash"] = (
                f'_octorules_zone_complete() {{\n    compgen -W "{zone_str}" -- "$1"\n}}\n'
            )
            preamble["zsh"] = f"_octorules_zone_complete() {{\n    compadd -- {zone_str}\n}}\n"
        except (ConfigError, FileNotFoundError, OSError) as e:
            # Couldn't load config — zone completion won't have hints. Tab
            # completion still works for everything else.
            log.debug("completion: skipping zone preamble (%s)", e)
        print(shtab.complete(build_parser(), args.shell, preamble=preamble))
        sys.exit(0)
    if args.command == "lint" and args.file:
        # Single-file lint mode — no config needed
        import time

        t0 = time.monotonic()
        if args.zones:
            log.warning("--zone is ignored when linting a single file")
        _discover_provider_modules()
        from octorules.commands._lint import cmd_lint_file

        code = cmd_lint_file(
            args.file,
            lint_format=args.lint_format,
            lint_severity=args.lint_severity,
            lint_rules=args.lint_rules,
            output_file=args.lint_output,
            exit_code=args.lint_exit_code,
        )
        _exit("lint", code, time.monotonic() - t0)

    t0 = time.monotonic()
    command = args.command

    try:
        config = Config.from_file(args.config)
        # --phase is validated against the phase registry, which providers
        # populate as an import side-effect.  When --phase is given, load the
        # configured providers first so a valid phase isn't rejected against an
        # empty registry (and the error message can list the real phases).
        # ep.load() only imports the module (no provider instance, no
        # credentials) and is idempotent.  Skipped when no --phase is given so
        # we don't import providers for commands that don't need them yet.
        if args.phases:
            for prov_name in config.providers:
                _ensure_provider_loaded(prov_name)
        phase_filter = _validate_phases(args.phases)

        if getattr(args, "config_only", False):
            log.info("Config valid.")
            _exit("lint", 0, time.monotonic() - t0)

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
        elif command == "lint":
            # Load configured providers for lint plugin registration, without
            # constructing provider instances (no API credentials needed).
            # Needed even without --phase (the loop above only runs when a
            # --phase filter is given); idempotent if already loaded.
            for prov_name in config.providers:
                _ensure_provider_loaded(prov_name)
            from octorules.commands._providers import read_zone_plans_cache

            zone_plans = read_zone_plans_cache(config)
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
        log.error("Check that your API credentials are configured correctly.")
        _exit(command, 1, time.monotonic() - t0)
