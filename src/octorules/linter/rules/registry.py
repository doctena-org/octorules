"""Lint rule registry — central catalog of all rule IDs, descriptions, and severities."""

from __future__ import annotations

from dataclasses import dataclass

from octorules.linter.engine import Severity


@dataclass(frozen=True)
class RuleMeta:
    """Metadata for a lint rule."""

    rule_id: str
    category: str
    description: str
    default_severity: Severity


# Category A — Parse / Syntax Errors
A001 = RuleMeta("A001", "parse", "Expression parse error (wirefilter)", Severity.WARNING)

# Category M — Structural / Rule-Level Checks
M001 = RuleMeta("M001", "structure", "Rule is missing required 'ref' field", Severity.ERROR)
M002 = RuleMeta("M002", "structure", "Rule is missing required 'expression' field", Severity.ERROR)
M003 = RuleMeta("M003", "structure", "Duplicate ref within phase", Severity.ERROR)
M004 = RuleMeta(
    "M004", "structure", "Invalid 'ref' type (must be non-empty string)", Severity.ERROR
)
M005 = RuleMeta(
    "M005", "structure", "Invalid 'expression' type (must be non-empty string)", Severity.ERROR
)
M006 = RuleMeta("M006", "structure", "Invalid 'enabled' type (must be boolean)", Severity.ERROR)
M007 = RuleMeta("M007", "structure", "Unknown top-level phase key", Severity.WARNING)
M008 = RuleMeta("M008", "structure", "Deprecated phase name", Severity.WARNING)
M009 = RuleMeta("M009", "structure", "Description exceeds 500 characters", Severity.WARNING)
M010 = RuleMeta("M010", "structure", "Phase value is not a list", Severity.ERROR)
M011 = RuleMeta("M011", "structure", "Rule entry is not a dict", Severity.ERROR)
M012 = RuleMeta(
    "M012",
    "structure",
    "Cloudflare phase identifier used instead of friendly name",
    Severity.WARNING,
)
M013 = RuleMeta("M013", "structure", "Expression is always true (catch-all rule)", Severity.WARNING)
M014 = RuleMeta(
    "M014", "structure", "Expression is always false (rule never matches)", Severity.WARNING
)
M015 = RuleMeta("M015", "structure", "Expression exceeds 4,096 character limit", Severity.ERROR)

# Category C — Action Validation
C001 = RuleMeta("C001", "action", "Invalid action for this phase", Severity.ERROR)
C002 = RuleMeta(
    "C002", "action", "Missing required action for phase without default", Severity.ERROR
)
C003 = RuleMeta("C003", "action", "Missing required action_parameters", Severity.ERROR)
C004 = RuleMeta("C004", "action", "Unknown action_parameters key", Severity.WARNING)
C005 = RuleMeta(
    "C005", "action", "Invalid action_parameters type (must be mapping)", Severity.ERROR
)
C006 = RuleMeta("C006", "action", "Invalid status_code type or value", Severity.ERROR)
C007 = RuleMeta("C007", "action", "Missing required status_code for redirect", Severity.ERROR)
C008 = RuleMeta("C008", "action", "Conflicting static value and dynamic expression", Severity.ERROR)
C009 = RuleMeta("C009", "action", "Unnecessary action_parameters for this action", Severity.WARNING)
C010 = RuleMeta("C010", "action", "serve_error content exceeds 10KB limit", Severity.ERROR)
C011 = RuleMeta("C011", "action", "Invalid skip phases value", Severity.WARNING)
C012 = RuleMeta("C012", "action", "Invalid skip products value", Severity.WARNING)
C013 = RuleMeta("C013", "action", "Invalid compress_response algorithm", Severity.ERROR)
C014 = RuleMeta("C014", "action", "Invalid rate limit characteristic", Severity.WARNING)

# Category D — Rate Limiting Specific
D001 = RuleMeta("D001", "rate_limit", "Invalid rate limiting period", Severity.ERROR)
D002 = RuleMeta("D002", "rate_limit", "Missing rate limiting characteristics", Severity.WARNING)
D003 = RuleMeta("D003", "rate_limit", "Missing requests_per_period threshold", Severity.ERROR)
D004 = RuleMeta("D004", "rate_limit", "mitigation_timeout exceeds period", Severity.WARNING)
D005 = RuleMeta("D005", "rate_limit", "Invalid counting_expression", Severity.ERROR)
D006 = RuleMeta("D006", "rate_limit", "Invalid counting_expression content", Severity.WARNING)

# Category I — Cache Rule Specific
I001 = RuleMeta("I001", "cache", "Invalid TTL mode value", Severity.ERROR)
I002 = RuleMeta("I002", "cache", "Missing TTL with override mode", Severity.ERROR)
I003 = RuleMeta("I003", "cache", "Negative TTL value", Severity.ERROR)
I004 = RuleMeta("I004", "cache", "Conflicting bypass and eligible settings", Severity.WARNING)

# Category J — Config Rule Specific
J001 = RuleMeta("J001", "config", "Invalid security_level value", Severity.ERROR)
J002 = RuleMeta("J002", "config", "Invalid ssl value", Severity.ERROR)
J003 = RuleMeta("J003", "config", "Invalid polish value", Severity.ERROR)
J004 = RuleMeta("J004", "config", "Security warning: security_level set to 'off'", Severity.WARNING)

# Category K — Redirect Rule Specific
K001 = RuleMeta("K001", "redirect", "Invalid redirect status code", Severity.ERROR)
K002 = RuleMeta("K002", "redirect", "Missing target_url in redirect", Severity.ERROR)

# Category L — Transform Rule Specific
L002 = RuleMeta("L002", "transform", "Empty header name in transform", Severity.ERROR)
L003 = RuleMeta("L003", "transform", "Missing operation in header transform", Severity.ERROR)
L004 = RuleMeta("L004", "transform", "Invalid header transform operation", Severity.ERROR)
L005 = RuleMeta(
    "L005", "transform", "Header set/add operation missing value or expression", Severity.ERROR
)
L006 = RuleMeta(
    "L006", "transform", "Expression parse error in transform action_parameters", Severity.WARNING
)

# Category N — Origin Rule Specific
N001 = RuleMeta("N001", "origin", "Port number out of range (1-65535)", Severity.ERROR)

# Category B — Phase Restrictions
B001 = RuleMeta(
    "B001", "phase", "Response field used in request phase expression", Severity.WARNING
)
B002 = RuleMeta(
    "B002", "phase", "Request body field used in phase without body access", Severity.WARNING
)
B003 = RuleMeta(
    "B003", "phase", "Field requires a plan tier not currently configured", Severity.WARNING
)

# Category H — Plan/Entitlement Checks
H001 = RuleMeta("H001", "plan", "Regex operator not available on Free plan", Severity.WARNING)
H002 = RuleMeta("H002", "plan", "Rule count exceeds plan limit for phase", Severity.WARNING)
H003 = RuleMeta("H003", "plan", "Expression exceeds 64 regex pattern limit", Severity.WARNING)

# Category E — Function Constraint Violations
E001 = RuleMeta("E001", "function", "Unknown function in expression", Severity.WARNING)
E002 = RuleMeta("E002", "function", "Function not available in this phase", Severity.WARNING)
E003 = RuleMeta(
    "E003", "function", "regex_replace/wildcard_replace usage limit exceeded", Severity.ERROR
)
E004 = RuleMeta("E004", "function", "Invalid encode_base64 flags", Severity.WARNING)
E005 = RuleMeta("E005", "function", "Invalid url_decode options", Severity.WARNING)
E006 = RuleMeta("E006", "function", "Invalid wildcard_replace flags", Severity.WARNING)

# Category F — Type System / Semantic Checks
F001 = RuleMeta("F001", "type", "Operator-type incompatibility", Severity.ERROR)
F002 = RuleMeta("F002", "type", "Unknown field name in expression", Severity.WARNING)

# Category G — Value Constraint Warnings
G001 = RuleMeta("G001", "value", "HTTP method should be uppercase", Severity.WARNING)
G002 = RuleMeta("G002", "value", "URI path should start with /", Severity.WARNING)
G003 = RuleMeta(
    "G003", "value", "Regex anchor in literal value (use 'matches' operator?)", Severity.WARNING
)
G004 = RuleMeta("G004", "value", "Invalid country code format", Severity.WARNING)
G005 = RuleMeta("G005", "value", "Score value out of typical range", Severity.WARNING)
G006 = RuleMeta("G006", "value", "Response code out of valid range (100-599)", Severity.WARNING)
G007 = RuleMeta("G007", "value", "Header name should be lowercase", Severity.INFO)
G008 = RuleMeta("G008", "value", "File extension should not start with a dot", Severity.WARNING)
G009 = RuleMeta("G009", "value", "Duplicate value in 'in' set", Severity.WARNING)
G010 = RuleMeta("G010", "value", "Deprecated field — use replacement", Severity.WARNING)
G011 = RuleMeta("G011", "value", "Reserved/bogon IP address", Severity.WARNING)
G012 = RuleMeta("G012", "value", "Overlapping IP ranges", Severity.WARNING)
G013 = RuleMeta("G013", "value", "Invalid value for field domain", Severity.WARNING)
G014 = RuleMeta("G014", "value", "Timestamp value out of reasonable bounds", Severity.WARNING)
G015 = RuleMeta("G015", "value", "Integer range overlap in 'in' set", Severity.WARNING)
G016 = RuleMeta(
    "G016", "value", "Value incompatible with lower()/upper() transformation", Severity.WARNING
)
G017 = RuleMeta("G017", "value", "len() compared to negative value", Severity.WARNING)
G018 = RuleMeta("G018", "value", "Invalid double-asterisk in wildcard pattern", Severity.WARNING)
G019 = RuleMeta("G019", "value", "Integer range has start greater than end", Severity.ERROR)
G020 = RuleMeta("G020", "value", "split() limit outside valid range (1-128)", Severity.WARNING)
G021 = RuleMeta("G021", "value", "cidr/cidr6 bit value out of range", Severity.WARNING)
G022 = RuleMeta(
    "G022", "value", "remove_query_args() first argument is not a query field", Severity.WARNING
)
G023 = RuleMeta("G023", "value", "Invalid regex pattern in matches operator", Severity.WARNING)
G024 = RuleMeta("G024", "value", "substring() index out of bounds or inverted", Severity.WARNING)
G025 = RuleMeta("G025", "value", "lookup_json path should start with /", Severity.WARNING)

# Category O — Best Practice / Style
O001 = RuleMeta(
    "O001", "style", "Consider using 'in' operator for multiple OR values", Severity.INFO
)
O002 = RuleMeta("O002", "style", "Use normalized field instead of raw field", Severity.INFO)
O003 = RuleMeta("O003", "style", "Redundant 'not not' double negation", Severity.INFO)
O004 = RuleMeta("O004", "style", "Negated comparison can be simplified", Severity.INFO)
O005 = RuleMeta(
    "O005", "style", "Illogical condition (contradictory AND or tautological OR)", Severity.WARNING
)
O006 = RuleMeta(
    "O006", "style", "Regex pattern uses literal escapes instead of raw string", Severity.INFO
)

# Category S — Page Shield Structure
S001 = RuleMeta("S001", "page_shield", "Missing required Page Shield field", Severity.ERROR)
S002 = RuleMeta("S002", "page_shield", "Invalid Page Shield action", Severity.ERROR)
S003 = RuleMeta("S003", "page_shield", "Invalid Page Shield field type", Severity.ERROR)
S004 = RuleMeta("S004", "page_shield", "Duplicate Page Shield description", Severity.WARNING)

# Category P — Cross-Rule / Ruleset-Level
P001 = RuleMeta("P001", "cross_rule", "Duplicate expression across rules", Severity.WARNING)
P002 = RuleMeta("P002", "cross_rule", "Unreachable rule after terminating action", Severity.WARNING)
P003 = RuleMeta("P003", "cross_rule", "Unresolved list reference", Severity.WARNING)
P004 = RuleMeta("P004", "cross_rule", "Invalid managed list name", Severity.WARNING)

# Build the full registry
RULE_REGISTRY: dict[str, RuleMeta] = {}
for _name, _obj in list(globals().items()):
    if isinstance(_obj, RuleMeta):
        RULE_REGISTRY[_obj.rule_id] = _obj


def get_rule_meta(rule_id: str) -> RuleMeta | None:
    """Look up a rule's metadata by ID."""
    return RULE_REGISTRY.get(rule_id)


def all_rule_ids() -> list[str]:
    """Return all registered rule IDs, sorted."""
    return sorted(RULE_REGISTRY.keys())
