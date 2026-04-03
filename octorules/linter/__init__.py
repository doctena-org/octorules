"""octorules linter — extensible rules validation via lint plugins."""

from octorules.linter.engine import LintContext, LintResult, Severity, lint_zone_file
from octorules.linter.plugin import LintPlugin, register_linter

__all__ = [
    "LintContext",
    "LintPlugin",
    "LintResult",
    "Severity",
    "lint_zone_file",
    "register_linter",
]
