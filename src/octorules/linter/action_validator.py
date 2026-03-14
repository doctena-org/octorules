"""Action and action_parameters validation — Categories C, D, I, J, K, L, N.

Validates that actions are valid for their phase and that action_parameters
match the expected schema.

Error handling convention: structural errors (wrong type, missing required
container) early-return to skip further checks; value errors (bad enum,
missing sub-field) continue so multiple issues are reported at once.
"""

from __future__ import annotations

import re
from typing import Any

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.linter.schemas.actions import (
    ACTION_SCHEMAS,
    PHASE_PARAMETER_OVERRIDES,
    VALID_ACTIONS_BY_PHASE,
    VALID_BLOCK_RESPONSE_STATUS_CODES,
    VALID_BROWSER_TTL_MODES,
    VALID_COMPRESSION_ALGORITHMS,
    VALID_EDGE_TTL_MODES,
    VALID_POLISH_VALUES,
    VALID_RATE_LIMIT_CHARACTERISTICS,
    VALID_RATE_LIMIT_PERIODS,
    VALID_REDIRECT_STATUS_CODES,
    VALID_SECURITY_LEVELS,
    VALID_SKIP_PHASES,
    VALID_SKIP_PRODUCTS,
    VALID_SSL_VALUES,
)
from octorules.phases import Phase

RULE_IDS = frozenset(
    {
        "C001",
        "C002",
        "C003",
        "C004",
        "C005",
        "C006",
        "C007",
        "C008",
        "C009",
        "C010",
        "C011",
        "C012",
        "C013",
        "C014",
        "C015",
        "C016",
        "C017",
        "C018",
        "D001",
        "D002",
        "D003",
        "D004",
        "D005",
        "D006",
        "I001",
        "I002",
        "I003",
        "I004",
        "J001",
        "J002",
        "J003",
        "J004",
        "J005",
        "K001",
        "K002",
        "L002",
        "L003",
        "L004",
        "L005",
        "L006",
        "L007",
        "N001",
    }
)

_VALID_HEADER_OPERATIONS = frozenset({"set", "remove", "add"})


def lint_actions(rule: dict[str, Any], phase: Phase, ctx: LintContext) -> None:
    """Run all action-related lint checks on a single rule."""
    ref = rule.get("ref", "")
    action = rule.get("action")
    phase_name = phase.friendly_name

    # C002: Missing action in phase without default
    if action is None:
        if phase.default_action is None:
            ctx.add(
                LintResult(
                    rule_id="C002",
                    severity=Severity.ERROR,
                    message="Missing required 'action' (no default for this phase)",
                    phase=phase_name,
                    ref=ref,
                )
            )
            return
        # Use the phase default for parameter validation
        action = phase.default_action

    if not isinstance(action, str):
        ctx.add(
            LintResult(
                rule_id="C002",
                severity=Severity.ERROR,
                message=f"'action' must be a string (got {type(action).__name__})",
                phase=phase_name,
                ref=ref,
            )
        )
        return

    # C001: Invalid action for phase
    valid_actions = VALID_ACTIONS_BY_PHASE.get(phase_name)
    if valid_actions and action not in valid_actions:
        ctx.add(
            LintResult(
                rule_id="C001",
                severity=Severity.ERROR,
                message=(
                    f"Action {action!r} is not valid for phase {phase_name!r}."
                    f" Valid actions: {', '.join(sorted(valid_actions))}"
                ),
                phase=phase_name,
                ref=ref,
                field="action",
            )
        )
        return  # skip parameter validation for invalid action

    action_params = rule.get("action_parameters")
    schema = ACTION_SCHEMAS.get(action)

    # C003: Missing required action_parameters
    if schema and schema.requires_parameters and action_params is None:
        ctx.add(
            LintResult(
                rule_id="C003",
                severity=Severity.ERROR,
                message=f"Action {action!r} requires 'action_parameters'",
                phase=phase_name,
                ref=ref,
                field="action_parameters",
            )
        )
        return

    if action_params is None:
        return

    # C005: action_parameters type check (must be a dict/mapping)
    if not isinstance(action_params, dict):
        ctx.add(
            LintResult(
                rule_id="C005",
                severity=Severity.ERROR,
                message=(
                    f"'action_parameters' must be a mapping, got {type(action_params).__name__}"
                ),
                phase=phase_name,
                ref=ref,
                field="action_parameters",
            )
        )
        return

    # C004: Unknown action_parameters keys
    # Use phase-specific override when available (narrows the action schema).
    if schema and schema.allowed_parameter_keys:
        allowed = PHASE_PARAMETER_OVERRIDES.get(phase_name, schema.allowed_parameter_keys)
        unknown = set(action_params.keys()) - allowed
        for key in sorted(unknown):
            ctx.add(
                LintResult(
                    rule_id="C004",
                    severity=Severity.ERROR,
                    message=(
                        f"Unknown action_parameters key {key!r}"
                        f" for action {action!r} in phase {phase_name!r}"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field=f"action_parameters.{key}",
                )
            )

    # C009: action_parameters on action that doesn't need them
    if schema and not schema.requires_parameters and not schema.allowed_parameter_keys:
        if action_params:
            ctx.add(
                LintResult(
                    rule_id="C009",
                    severity=Severity.WARNING,
                    message=(f"Action {action!r} does not accept action_parameters"),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters",
                )
            )

    # Phase-specific validation
    if phase_name in ("redirect_rules", "bulk_redirect_rules"):
        _lint_redirect_params(action_params, phase_name, ref, ctx)
    elif phase_name == "cache_rules":
        _lint_cache_params(action_params, phase_name, ref, ctx)
    elif phase_name == "config_rules":
        _lint_config_params(action_params, phase_name, ref, ctx)
    elif phase_name == "rate_limiting_rules":
        _lint_rate_limit_params(action_params, phase_name, ref, ctx)
    elif phase_name == "origin_rules":
        _lint_origin_params(action_params, phase_name, ref, ctx)
    elif phase_name in ("url_rewrite_rules", "request_header_rules", "response_header_rules"):
        _lint_transform_params(action_params, phase_name, ref, ctx)
    elif phase_name == "custom_error_rules":
        _lint_serve_error_params(action_params, phase_name, ref, ctx)
    elif phase_name == "compression_rules":
        _lint_compress_response_params(action_params, phase_name, ref, ctx)

    # Action-specific validation (cross-phase)
    if action == "execute":
        _lint_execute_params(action_params, phase_name, ref, ctx)
    elif action == "skip":
        _lint_skip_params(action_params, phase_name, ref, ctx)
    elif action == "block":
        _lint_block_response_params(action_params, phase_name, ref, ctx)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _check_enum(
    value: object,
    valid: frozenset,
    *,
    rule_id: str,
    label: str,
    field_path: str,
    phase_name: str,
    ref: str,
    ctx: LintContext,
) -> bool:
    """Emit an error if *value* is not in *valid*. Returns True if valid."""
    if value in valid:
        return True
    display = repr(value) if isinstance(value, str) else str(value)
    valid_str = ", ".join(sorted(str(v) for v in valid))
    ctx.add(
        LintResult(
            rule_id=rule_id,
            severity=Severity.ERROR,
            message=f"Invalid {label} {display}. Must be one of: {valid_str}",
            phase=phase_name,
            ref=ref,
            field=field_path,
        )
    )
    return False


def _check_value_expression_conflict(
    d: dict,
    context_label: str,
    phase_name: str,
    ref: str,
    field_path: str,
    ctx: LintContext,
) -> None:
    """C008: flag when both 'value' and 'expression' are specified."""
    if "value" in d and "expression" in d:
        ctx.add(
            LintResult(
                rule_id="C008",
                severity=Severity.ERROR,
                message=(f"Cannot specify both 'value' and 'expression' in {context_label}"),
                phase=phase_name,
                ref=ref,
                field=field_path,
            )
        )


def _lint_ttl(
    ttl: dict,
    ttl_name: str,
    valid_modes: frozenset[str],
    phase_name: str,
    ref: str,
    ctx: LintContext,
) -> None:
    """Validate a TTL dict (shared for edge_ttl and browser_ttl)."""
    mode = ttl.get("mode")
    if isinstance(mode, str) and mode not in valid_modes:
        ctx.add(
            LintResult(
                rule_id="I001",
                severity=Severity.ERROR,
                message=(
                    f"Invalid {ttl_name} mode {mode!r}."
                    f" Must be one of: {', '.join(sorted(valid_modes))}"
                ),
                phase=phase_name,
                ref=ref,
                field=f"action_parameters.{ttl_name}.mode",
            )
        )
    # I002: override_origin requires default TTL
    if mode == "override_origin" and "default" not in ttl:
        ctx.add(
            LintResult(
                rule_id="I002",
                severity=Severity.ERROR,
                message=(f"{ttl_name} mode 'override_origin' requires a 'default' TTL value"),
                phase=phase_name,
                ref=ref,
                field=f"action_parameters.{ttl_name}",
            )
        )
    # I003: negative TTL
    default_val = ttl.get("default")
    if isinstance(default_val, (int, float)) and default_val < 0:
        ctx.add(
            LintResult(
                rule_id="I003",
                severity=Severity.ERROR,
                message=f"Negative {ttl_name} value: {default_val}",
                phase=phase_name,
                ref=ref,
                field=f"action_parameters.{ttl_name}.default",
            )
        )


# ---------------------------------------------------------------------------
# Phase-specific validators
# ---------------------------------------------------------------------------


def _lint_redirect_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate redirect action_parameters (K001-K003, C007, C008)."""
    from_value = params.get("from_value")
    if not isinstance(from_value, dict):
        return

    target_url = from_value.get("target_url")
    if target_url is None:
        # K002
        ctx.add(
            LintResult(
                rule_id="K002",
                severity=Severity.ERROR,
                message="Missing 'target_url' in redirect from_value",
                phase=phase_name,
                ref=ref,
                field="action_parameters.from_value.target_url",
            )
        )
        return

    if isinstance(target_url, dict):
        _check_value_expression_conflict(
            target_url,
            "redirect target_url",
            phase_name,
            ref,
            "action_parameters.from_value.target_url",
            ctx,
        )

    status_code = from_value.get("status_code")
    if status_code is None:
        # C007
        ctx.add(
            LintResult(
                rule_id="C007",
                severity=Severity.ERROR,
                message="Missing required 'status_code' in redirect from_value",
                phase=phase_name,
                ref=ref,
                field="action_parameters.from_value.status_code",
            )
        )
    elif isinstance(status_code, int):
        # K001
        _check_enum(
            status_code,
            VALID_REDIRECT_STATUS_CODES,
            rule_id="K001",
            label="redirect status code",
            field_path="action_parameters.from_value.status_code",
            phase_name=phase_name,
            ref=ref,
            ctx=ctx,
        )
    elif not isinstance(status_code, int):
        # C006: status_code must be an integer
        ctx.add(
            LintResult(
                rule_id="C006",
                severity=Severity.ERROR,
                message=(f"'status_code' must be an integer, got {type(status_code).__name__}"),
                phase=phase_name,
                ref=ref,
                field="action_parameters.from_value.status_code",
            )
        )


def _lint_cache_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate cache action_parameters (I001-I004)."""
    edge_ttl = params.get("edge_ttl")
    if isinstance(edge_ttl, dict):
        _lint_ttl(
            edge_ttl,
            "edge_ttl",
            VALID_EDGE_TTL_MODES,
            phase_name,
            ref,
            ctx,
        )

    browser_ttl = params.get("browser_ttl")
    if isinstance(browser_ttl, dict):
        _lint_ttl(
            browser_ttl,
            "browser_ttl",
            VALID_BROWSER_TTL_MODES,
            phase_name,
            ref,
            ctx,
        )

    # I004: conflicting bypass and eligible
    cache_val = params.get("cache")
    if cache_val is False:
        if edge_ttl is not None or browser_ttl is not None:
            ctx.add(
                LintResult(
                    rule_id="I004",
                    severity=Severity.WARNING,
                    message=("TTL settings have no effect when cache is disabled (cache: false)"),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters",
                )
            )


def _lint_config_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate config action_parameters (J001-J004)."""
    security_level = params.get("security_level")
    if isinstance(security_level, str):
        if not _check_enum(
            security_level,
            VALID_SECURITY_LEVELS,
            rule_id="J001",
            label="security_level",
            field_path="action_parameters.security_level",
            phase_name=phase_name,
            ref=ref,
            ctx=ctx,
        ):
            pass
        elif security_level == "off":
            ctx.add(
                LintResult(
                    rule_id="J004",
                    severity=Severity.WARNING,
                    message=("Security level set to 'off' — this disables all security features"),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.security_level",
                )
            )

    ssl = params.get("ssl")
    if isinstance(ssl, str) and not _check_enum(
        ssl,
        VALID_SSL_VALUES,
        rule_id="J002",
        label="ssl value",
        field_path="action_parameters.ssl",
        phase_name=phase_name,
        ref=ref,
        ctx=ctx,
    ):
        pass
    elif ssl == "off":
        # J005: SSL off security warning
        ctx.add(
            LintResult(
                rule_id="J005",
                severity=Severity.WARNING,
                message=(
                    "SSL set to 'off' — traffic between Cloudflare and origin will be unencrypted"
                ),
                phase=phase_name,
                ref=ref,
                field="action_parameters.ssl",
            )
        )

    polish = params.get("polish")
    if isinstance(polish, str):
        _check_enum(
            polish,
            VALID_POLISH_VALUES,
            rule_id="J003",
            label="polish value",
            field_path="action_parameters.polish",
            phase_name=phase_name,
            ref=ref,
            ctx=ctx,
        )


def _lint_rate_limit_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate rate limiting action_parameters (D001-D005)."""
    period = params.get("period")
    if isinstance(period, int):
        _check_enum(
            period,
            VALID_RATE_LIMIT_PERIODS,
            rule_id="D001",
            label="rate limiting period",
            field_path="action_parameters.period",
            phase_name=phase_name,
            ref=ref,
            ctx=ctx,
        )

    # D003: missing threshold
    if "requests_per_period" not in params and "score_per_period" not in params:
        ctx.add(
            LintResult(
                rule_id="D003",
                severity=Severity.ERROR,
                message=(
                    "Missing rate limit threshold:"
                    " needs 'requests_per_period' or 'score_per_period'"
                ),
                phase=phase_name,
                ref=ref,
                field="action_parameters",
            )
        )

    # D002: missing characteristics
    characteristics = params.get("characteristics")
    if characteristics is None:
        ctx.add(
            LintResult(
                rule_id="D002",
                severity=Severity.WARNING,
                message=("Missing 'characteristics' — rate limit will apply globally"),
                phase=phase_name,
                ref=ref,
                field="action_parameters.characteristics",
            )
        )

    # C014: validate characteristics values
    if isinstance(characteristics, list):
        for char_val in characteristics:
            if not isinstance(char_val, str):
                continue
            # Header references like "http.request.headers[\"x-api-key\"]" are valid
            if char_val.startswith("http.request.headers["):
                continue
            if char_val not in VALID_RATE_LIMIT_CHARACTERISTICS:
                ctx.add(
                    LintResult(
                        rule_id="C014",
                        severity=Severity.ERROR,
                        message=f"Unknown rate limit characteristic {char_val!r}",
                        phase=phase_name,
                        ref=ref,
                        field="action_parameters.characteristics",
                    )
                )

    # D004: mitigation_timeout > period
    mitigation_timeout = params.get("mitigation_timeout")
    if (
        isinstance(mitigation_timeout, int)
        and isinstance(period, int)
        and mitigation_timeout > period
    ):
        ctx.add(
            LintResult(
                rule_id="D004",
                severity=Severity.WARNING,
                message=(f"mitigation_timeout ({mitigation_timeout}s) exceeds period ({period}s)"),
                phase=phase_name,
                ref=ref,
                field="action_parameters.mitigation_timeout",
            )
        )

    # D005: counting_expression must be a string
    counting_expr = params.get("counting_expression")
    if counting_expr is not None and not isinstance(counting_expr, str):
        ctx.add(
            LintResult(
                rule_id="D005",
                severity=Severity.ERROR,
                message="'counting_expression' must be a string",
                phase=phase_name,
                ref=ref,
                field="action_parameters.counting_expression",
            )
        )

    # D006: lint counting_expression content
    if isinstance(counting_expr, str) and counting_expr.strip():
        from octorules.expression import normalize_expression
        from octorules.linter.expression_bridge import parse_expression

        counting_expr = normalize_expression(counting_expr)
        ce_info = parse_expression(counting_expr)
        if ce_info.parse_error:
            ctx.add(
                LintResult(
                    rule_id="D006",
                    severity=Severity.WARNING,
                    message=(f"Invalid counting_expression: {ce_info.parse_error}"),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.counting_expression",
                )
            )


def _lint_origin_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate origin rule action_parameters (N001)."""
    origin = params.get("origin")
    if isinstance(origin, dict):
        port = origin.get("port")
        if port is not None and (not isinstance(port, int) or isinstance(port, bool)):
            ctx.add(
                LintResult(
                    rule_id="N001",
                    severity=Severity.ERROR,
                    message=f"Port must be an integer, got {type(port).__name__}",
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.origin.port",
                )
            )
        elif isinstance(port, int) and (port < 1 or port > 65535):
            ctx.add(
                LintResult(
                    rule_id="N001",
                    severity=Severity.ERROR,
                    message=f"Port number {port} out of range (1-65535)",
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.origin.port",
                )
            )


def _lint_transform_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate transform action_parameters (L002-L007, C008)."""
    # Check URI transforms
    uri = params.get("uri")
    if isinstance(uri, dict):
        for component in ("path", "query"):
            comp_val = uri.get(component)
            if isinstance(comp_val, dict):
                _check_value_expression_conflict(
                    comp_val,
                    f"uri.{component} transform",
                    phase_name,
                    ref,
                    f"action_parameters.uri.{component}",
                    ctx,
                )
                # L006: Lint expression inside URI transform
                _lint_transform_expression(
                    comp_val,
                    f"action_parameters.uri.{component}",
                    phase_name,
                    ref,
                    ctx,
                )

    # Check header transforms
    headers = params.get("headers")
    if isinstance(headers, dict):
        for header_name, header_val in headers.items():
            # L002: empty header name
            if not header_name or not header_name.strip():
                ctx.add(
                    LintResult(
                        rule_id="L002",
                        severity=Severity.ERROR,
                        message="Empty header name in transform",
                        phase=phase_name,
                        ref=ref,
                        field="action_parameters.headers",
                    )
                )
            if isinstance(header_val, dict):
                # L003: missing operation
                if "operation" not in header_val:
                    ctx.add(
                        LintResult(
                            rule_id="L003",
                            severity=Severity.ERROR,
                            message=(f"Missing 'operation' for header {header_name!r} transform"),
                            phase=phase_name,
                            ref=ref,
                            field=f"action_parameters.headers.{header_name}",
                        )
                    )
                else:
                    # L004: invalid header transform operation
                    op = header_val["operation"]
                    if isinstance(op, str) and op not in _VALID_HEADER_OPERATIONS:
                        ctx.add(
                            LintResult(
                                rule_id="L004",
                                severity=Severity.ERROR,
                                message=(
                                    f"Invalid header transform operation {op!r}"
                                    f" for header {header_name!r}."
                                    " Must be one of:"
                                    f" {', '.join(sorted(_VALID_HEADER_OPERATIONS))}"
                                ),
                                phase=phase_name,
                                ref=ref,
                                field=f"action_parameters.headers.{header_name}.operation",
                            )
                        )
                    # L007: request headers don't support 'add' operation
                    elif (
                        isinstance(op, str) and op == "add" and phase_name == "request_header_rules"
                    ):
                        ctx.add(
                            LintResult(
                                rule_id="L007",
                                severity=Severity.ERROR,
                                message=(
                                    f"Request header transforms do not support 'add' operation"
                                    f" for header {header_name!r}. Use 'set' instead."
                                ),
                                phase=phase_name,
                                ref=ref,
                                field=f"action_parameters.headers.{header_name}.operation",
                            )
                        )
                    # L005: set/add missing value or expression
                    elif isinstance(op, str) and op in ("set", "add"):
                        if "value" not in header_val and "expression" not in header_val:
                            ctx.add(
                                LintResult(
                                    rule_id="L005",
                                    severity=Severity.ERROR,
                                    message=(
                                        f"Header {header_name!r} operation {op!r}"
                                        f" requires 'value' or 'expression'"
                                    ),
                                    phase=phase_name,
                                    ref=ref,
                                    field=f"action_parameters.headers.{header_name}",
                                )
                            )
                # C008: conflicting value and expression
                _check_value_expression_conflict(
                    header_val,
                    f"header {header_name!r} transform",
                    phase_name,
                    ref,
                    f"action_parameters.headers.{header_name}",
                    ctx,
                )
                # L006: Lint expression inside header transform
                _lint_transform_expression(
                    header_val,
                    f"action_parameters.headers.{header_name}",
                    phase_name,
                    ref,
                    ctx,
                )


def _lint_transform_expression(
    d: dict,
    field_path: str,
    phase_name: str,
    ref: str,
    ctx: LintContext,
) -> None:
    """L006: Lint an expression embedded in transform action_parameters.

    Transform expressions use function-call syntax (e.g. ``concat(...)``,
    ``regex_replace(...)``).  Wirefilter only understands operator form for
    some of these, so we suppress parse errors that are caused by known
    function-call patterns that Cloudflare actually accepts.
    """
    import re

    expr = d.get("expression")
    if not isinstance(expr, str) or not expr.strip():
        return

    from octorules.linter.expression_bridge import parse_expression

    info = parse_expression(expr, phase=phase_name, expect_parse_error=True)
    if info.parse_error:
        # Suppress known false positives: transform expressions routinely use
        # function-call syntax (regex_replace, wildcard_replace, concat,
        # lower, upper, starts_with, ends_with, etc.) that wirefilter rejects.
        _TRANSFORM_FUNCTIONS = (
            r"\b(?:regex_replace|wildcard_replace|concat|lower|upper|"
            r"to_string|substring|remove_bytes|url_decode|len|"
            r"starts_with|ends_with|contains|sha256|sha512|hmac|"
            r"encode_base64|decode_base64|uuidv4|split|join|"
            r"http\.request\.uri\.path|http\.request\.uri)\s*\("
        )
        if re.search(_TRANSFORM_FUNCTIONS, expr):
            return

        ctx.add(
            LintResult(
                rule_id="L006",
                severity=Severity.WARNING,
                message=(f"Expression parse error in {field_path}: {info.parse_error}"),
                phase=phase_name,
                ref=ref,
                field=f"{field_path}.expression",
            )
        )


def _lint_serve_error_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate custom error action_parameters (C006, C010)."""
    status_code = params.get("status_code")
    if status_code is not None and isinstance(status_code, int):
        if status_code < 400 or status_code > 599:
            ctx.add(
                LintResult(
                    rule_id="C006",
                    severity=Severity.ERROR,
                    message=(f"Custom error status_code {status_code} must be 400-599"),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.status_code",
                )
            )

    # C010: content size limit (~10KB)
    content = params.get("content")
    if isinstance(content, str):
        content_size = len(content.encode("utf-8"))
        if content_size > 10240:
            ctx.add(
                LintResult(
                    rule_id="C010",
                    severity=Severity.ERROR,
                    message=(
                        f"serve_error content is {content_size:,} bytes (exceeds 10,240 byte limit)"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.content",
                )
            )


_EXECUTE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")


def _lint_execute_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate execute action_parameters (C016, C017)."""
    # C016: Missing id
    ruleset_id = params.get("id")
    if ruleset_id is None:
        ctx.add(
            LintResult(
                rule_id="C016",
                severity=Severity.ERROR,
                message="Action 'execute' requires 'id' in action_parameters",
                phase=phase_name,
                ref=ref,
                field="action_parameters.id",
            )
        )
        return

    # C017: Invalid id format (must be 32-char hex)
    if isinstance(ruleset_id, str) and not _EXECUTE_ID_PATTERN.match(ruleset_id):
        ctx.add(
            LintResult(
                rule_id="C017",
                severity=Severity.WARNING,
                message=(
                    f"Execute ruleset id {ruleset_id!r} is not a valid 32-character hex string"
                ),
                phase=phase_name,
                ref=ref,
                field="action_parameters.id",
            )
        )


def _lint_skip_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate skip action_parameters (C011, C012)."""
    # C011: validate phases values
    phases = params.get("phases")
    if isinstance(phases, list):
        for phase_val in phases:
            if isinstance(phase_val, str) and phase_val not in VALID_SKIP_PHASES:
                ctx.add(
                    LintResult(
                        rule_id="C011",
                        severity=Severity.ERROR,
                        message=f"Invalid skip phase {phase_val!r}",
                        phase=phase_name,
                        ref=ref,
                        field="action_parameters.phases",
                    )
                )

    # C012: validate products values
    products = params.get("products")
    if isinstance(products, list):
        for product_val in products:
            if isinstance(product_val, str) and product_val not in VALID_SKIP_PRODUCTS:
                ctx.add(
                    LintResult(
                        rule_id="C012",
                        severity=Severity.ERROR,
                        message=f"Invalid skip product {product_val!r}",
                        phase=phase_name,
                        ref=ref,
                        field="action_parameters.products",
                    )
                )


def _lint_compress_response_params(
    params: dict, phase_name: str, ref: str, ctx: LintContext
) -> None:
    """Validate compress_response action_parameters (C013, C018)."""
    algorithms = params.get("algorithms")
    if isinstance(algorithms, list):
        _TERMINAL_ALGORITHMS = frozenset({"none", "auto"})
        for i, algo in enumerate(algorithms):
            algo_name = algo.get("name") if isinstance(algo, dict) else algo
            if isinstance(algo_name, str):
                _check_enum(
                    algo_name,
                    VALID_COMPRESSION_ALGORITHMS,
                    rule_id="C013",
                    label="compression algorithm",
                    field_path="action_parameters.algorithms",
                    phase_name=phase_name,
                    ref=ref,
                    ctx=ctx,
                )
            # C018: Terminal algorithm must be last
            if (
                isinstance(algo_name, str)
                and algo_name in _TERMINAL_ALGORITHMS
                and i < len(algorithms) - 1
            ):
                ctx.add(
                    LintResult(
                        rule_id="C018",
                        severity=Severity.WARNING,
                        message=(
                            f"Compression algorithm {algo_name!r} must be the last item"
                            " in the algorithms list"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="action_parameters.algorithms",
                    )
                )


def _lint_block_response_params(params: dict, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Validate block action response parameters (C015)."""
    response = params.get("response")
    if not isinstance(response, dict):
        return

    # C015: Invalid block response status_code (must be 400-499)
    status_code = response.get("status_code")
    if status_code is not None and isinstance(status_code, int):
        if status_code not in VALID_BLOCK_RESPONSE_STATUS_CODES:
            ctx.add(
                LintResult(
                    rule_id="C015",
                    severity=Severity.ERROR,
                    message=(f"Block response status_code {status_code} must be 400-499"),
                    phase=phase_name,
                    ref=ref,
                    field="action_parameters.response.status_code",
                )
            )

    # C015: content_type must be a string
    content_type = response.get("content_type")
    if content_type is not None and not isinstance(content_type, str):
        ctx.add(
            LintResult(
                rule_id="C015",
                severity=Severity.ERROR,
                message=(
                    f"Block response content_type must be a string,"
                    f" got {type(content_type).__name__}"
                ),
                phase=phase_name,
                ref=ref,
                field="action_parameters.response.content_type",
            )
        )

    # C015: content must be a string
    content = response.get("content")
    if content is not None and not isinstance(content, str):
        ctx.add(
            LintResult(
                rule_id="C015",
                severity=Severity.ERROR,
                message=(f"Block response content must be a string, got {type(content).__name__}"),
                phase=phase_name,
                ref=ref,
                field="action_parameters.response.content",
            )
        )
