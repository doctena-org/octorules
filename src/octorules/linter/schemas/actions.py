"""Action schemas — valid actions per phase and action_parameters schemas.

Defines which actions are valid in which phases, whether action_parameters
is required, and the expected structure of action_parameters.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ActionSchema:
    """Schema for a single action's parameters."""

    requires_parameters: bool = False
    allowed_parameter_keys: frozenset[str] = frozenset()
    required_parameter_keys: frozenset[str] = frozenset()


# --- Action schemas ---

REDIRECT_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset({"from_value", "from_list"}),
)

REWRITE_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset({"uri", "headers"}),
)

SET_CACHE_SETTINGS_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "cache",
            "edge_ttl",
            "browser_ttl",
            "serve_stale",
            "respect_strong_etags",
            "cache_key",
            "origin_error_page_passthru",
            "cache_reserve",
            "origin_cache_control",
        }
    ),
)

SET_CONFIG_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "automatic_https_rewrites",
            "autominify",
            "bic",
            "disable_apps",
            "disable_rum",
            "disable_zaraz",
            "email_obfuscation",
            "disable_railgun",
            "fonts",
            "hotlink_protection",
            "mirage",
            "opportunistic_encryption",
            "polish",
            "rocket_loader",
            "security_level",
            "server_side_excludes",
            "ssl",
            "sxg",
            "h2_prioritization",
            "cache_deception_armor",
        }
    ),
)

ROUTE_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "host_header",
            "origin",
            "sni",
        }
    ),
)

COMPRESS_RESPONSE_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset({"algorithms"}),
)

SERVE_ERROR_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "content",
            "content_type",
            "status_code",
        }
    ),
)

LOG_CUSTOM_FIELD_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "request_fields",
            "response_fields",
            "cookie_fields",
        }
    ),
)

# WAF actions
BLOCK_SCHEMA = ActionSchema(
    requires_parameters=False,
    allowed_parameter_keys=frozenset({"response"}),
)

CHALLENGE_SCHEMAS = ActionSchema(requires_parameters=False)

SKIP_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "ruleset",
            "rulesets",
            "rules",
            "phases",
            "products",
        }
    ),
)

EXECUTE_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "id",
            "matched_data",
            "overrides",
            "version",
        }
    ),
)

RATE_LIMIT_SCHEMA = ActionSchema(
    requires_parameters=True,
    allowed_parameter_keys=frozenset(
        {
            "characteristics",
            "period",
            "requests_per_period",
            "mitigation_timeout",
            "counting_expression",
            "requests_to_origin",
            "score_per_period",
            "score_response_header_name",
        }
    ),
)

LOG_SCHEMA = ActionSchema(requires_parameters=False)

# --- Valid actions per phase ---

VALID_ACTIONS_BY_PHASE: dict[str, set[str]] = {
    "redirect_rules": {"redirect"},
    "url_rewrite_rules": {"rewrite"},
    "request_header_rules": {"rewrite"},
    "response_header_rules": {"rewrite"},
    "config_rules": {"set_config"},
    "origin_rules": {"route"},
    "cache_rules": {"set_cache_settings"},
    "compression_rules": {"compress_response"},
    "custom_error_rules": {"serve_error"},
    "waf_custom_rules": {
        "block",
        "challenge",
        "js_challenge",
        "managed_challenge",
        "skip",
        "log",
        "execute",
    },
    "waf_managed_rules": {"execute", "skip", "block", "log"},
    "rate_limiting_rules": {
        "block",
        "challenge",
        "js_challenge",
        "managed_challenge",
        "log",
        "execute",
    },
    "bot_fight_rules": {"block", "challenge", "js_challenge", "managed_challenge"},
    "sensitive_data_detection": {"log"},
    "http_ddos_rules": {"block", "challenge", "log"},
    "bulk_redirect_rules": {"redirect"},
    "log_custom_fields": {"log_custom_field"},
    "url_normalization": {"none"},
    # Network-level phases
    "network_ddos_rules": {"block", "log"},
    "network_firewall_rules": {"block", "log"},
}

# --- Action → schema mapping ---

ACTION_SCHEMAS: dict[str, ActionSchema] = {
    "redirect": REDIRECT_SCHEMA,
    "rewrite": REWRITE_SCHEMA,
    "set_cache_settings": SET_CACHE_SETTINGS_SCHEMA,
    "set_config": SET_CONFIG_SCHEMA,
    "route": ROUTE_SCHEMA,
    "compress_response": COMPRESS_RESPONSE_SCHEMA,
    "serve_error": SERVE_ERROR_SCHEMA,
    "log_custom_field": LOG_CUSTOM_FIELD_SCHEMA,
    "block": BLOCK_SCHEMA,
    "challenge": CHALLENGE_SCHEMAS,
    "js_challenge": CHALLENGE_SCHEMAS,
    "managed_challenge": CHALLENGE_SCHEMAS,
    "skip": SKIP_SCHEMA,
    "execute": EXECUTE_SCHEMA,
    "log": LOG_SCHEMA,
    "none": ActionSchema(requires_parameters=False),
}

# --- Specific enum values for config rules ---

VALID_SECURITY_LEVELS = frozenset(
    {
        "off",
        "essentially_off",
        "low",
        "medium",
        "high",
        "under_attack",
    }
)

VALID_SSL_VALUES = frozenset(
    {
        "off",
        "flexible",
        "full",
        "strict",
        "origin_pull",
    }
)

VALID_POLISH_VALUES = frozenset(
    {
        "off",
        "lossless",
        "lossy",
    }
)

# --- Cache rule TTL modes ---

VALID_EDGE_TTL_MODES = frozenset(
    {
        "respect_origin",
        "override_origin",
        "bypass_by_default",
    }
)

VALID_BROWSER_TTL_MODES = frozenset(
    {
        "respect_origin",
        "override_origin",
        "bypass",
    }
)

# --- Redirect status codes ---

VALID_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})

# --- Rate limiting constants ---

VALID_RATE_LIMIT_PERIODS = frozenset({10, 60, 120, 300, 600, 3600})

# Max characteristics per plan tier
MAX_CHARACTERISTICS: dict[str, int] = {
    "free": 1,
    "pro": 1,
    "business": 2,
    "enterprise": 4,
}

# --- Compression algorithms ---

VALID_COMPRESSION_ALGORITHMS = frozenset({"gzip", "brotli", "zstd", "none", "auto"})

# --- Skip action valid values ---

VALID_SKIP_PHASES = frozenset(
    {
        "http_request_firewall_custom",
        "http_ratelimit",
        "http_request_firewall_managed",
        "http_request_sbfm",
        "http_request_transform",
        "http_request_origin",
        "http_request_cache_settings",
        "http_config_settings",
        "http_request_late_transform",
        "http_response_headers_transform",
        "http_response_firewall_managed",
        "http_response_compression",
        "http_log_custom_fields",
    }
)

VALID_SKIP_PRODUCTS = frozenset(
    {
        "bic",
        "hot",
        "rateLimit",
        "securityLevel",
        "uaBlock",
        "waf",
        "zoneLockdown",
    }
)

# --- Block action response status codes (400-499) ---

VALID_BLOCK_RESPONSE_STATUS_CODES = frozenset(range(400, 500))

# --- Rate limit valid characteristics ---

VALID_RATE_LIMIT_CHARACTERISTICS = frozenset(
    {
        "cf.colo.id",
        "cf.unique_visitor_id",
        "ip.src",
        "ip.geoip.country",
        "ip.geoip.asnum",
        "ip.src.country",
        "ip.src.asnum",
    }
)
