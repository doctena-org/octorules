"""Field registry — Cloudflare wirefilter field definitions.

Each field has a name, type, and set of phases where it's available.
Used for expression analysis: type checking, phase restrictions, value validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FieldType(Enum):
    """Wirefilter field types."""

    STRING = "String"
    INT = "Int"
    BOOL = "Bool"
    IP = "IP"
    BYTES = "Bytes"
    MAP_STRING_STRING = "Map<String, String>"
    MAP_STRING_INT = "Map<String, Int>"
    ARRAY_STRING = "Array<String>"
    ARRAY_INT = "Array<Int>"
    MAP_ARRAY_STRING = "Map<Array<String>>"
    MAP_ARRAY_INT = "Map<Array<Int>>"
    ARRAY_ARRAY_STRING = "Array<Array<String>>"


@dataclass(frozen=True)
class FieldDef:
    """Definition of a Cloudflare wirefilter field."""

    name: str
    field_type: FieldType
    # Phases where this field is available (empty = all phases)
    phases: frozenset[str] = frozenset()
    # Whether this is a response-only field
    is_response: bool = False
    # Whether this field requires a specific plan tier
    requires_plan: str = ""  # empty = all plans


# --- Core HTTP request fields ---
_REQUEST_PHASES = frozenset()  # available in all phases

FIELDS: dict[str, FieldDef] = {}


def _f(name: str, ftype: FieldType, **kwargs: object) -> FieldDef:
    fd = FieldDef(name=name, field_type=ftype, **kwargs)  # type: ignore[arg-type]
    FIELDS[name] = fd
    return fd


# --- BEGIN GENERATED FIELDS --- #
_f("cf.api_gateway.auth_id_present", FieldType.BOOL, requires_plan="enterprise")
_f("cf.api_gateway.fallthrough_detected", FieldType.BOOL)
_f("cf.api_gateway.request_violates_schema", FieldType.BOOL)
_f("cf.bot_management.corporate_proxy", FieldType.BOOL, requires_plan="enterprise")
_f("cf.bot_management.detection_ids", FieldType.ARRAY_INT, requires_plan="enterprise")
_f("cf.bot_management.ja3_hash", FieldType.STRING, requires_plan="enterprise")
_f("cf.bot_management.ja4", FieldType.STRING, requires_plan="enterprise")
_f("cf.bot_management.js_detection.passed", FieldType.BOOL, requires_plan="enterprise")
_f("cf.bot_management.score", FieldType.INT, requires_plan="enterprise")
_f("cf.bot_management.static_resource", FieldType.BOOL, requires_plan="enterprise")
_f("cf.bot_management.verified_bot", FieldType.BOOL, requires_plan="enterprise")
_f("cf.client.bot", FieldType.BOOL)
_f("cf.edge.client_tcp", FieldType.BOOL)
_f("cf.edge.server_ip", FieldType.IP)
_f("cf.edge.server_port", FieldType.INT)
_f("cf.hostname.metadata", FieldType.STRING)
_f("cf.llm.prompt.detected", FieldType.BOOL, requires_plan="enterprise")
_f("cf.llm.prompt.injection_score", FieldType.INT, requires_plan="enterprise")
_f("cf.llm.prompt.pii_categories", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("cf.llm.prompt.pii_detected", FieldType.BOOL, requires_plan="enterprise")
_f("cf.llm.prompt.unsafe_topic_categories", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("cf.llm.prompt.unsafe_topic_detected", FieldType.BOOL, requires_plan="enterprise")
_f("cf.random_seed", FieldType.BYTES)
_f("cf.ray_id", FieldType.STRING)
_f("cf.response.1xxx_code", FieldType.INT, is_response=True)
_f("cf.response.error_type", FieldType.STRING, is_response=True)
_f("cf.threat_score", FieldType.INT)
_f("cf.timings.client_tcp_rtt_msec", FieldType.INT)
_f("cf.timings.edge_msec", FieldType.INT)
_f("cf.timings.origin_ttfb_msec", FieldType.INT)
_f("cf.tls_cipher", FieldType.STRING)
_f("cf.tls_ciphers_sha1", FieldType.STRING)
_f("cf.tls_client_auth.cert_fingerprint_sha1", FieldType.STRING)
_f("cf.tls_client_auth.cert_fingerprint_sha256", FieldType.STRING)
_f("cf.tls_client_auth.cert_issuer_dn", FieldType.STRING)
_f("cf.tls_client_auth.cert_issuer_dn_legacy", FieldType.STRING)
_f("cf.tls_client_auth.cert_issuer_dn_rfc2253", FieldType.STRING)
_f("cf.tls_client_auth.cert_issuer_serial", FieldType.STRING)
_f("cf.tls_client_auth.cert_issuer_ski", FieldType.STRING)
_f("cf.tls_client_auth.cert_not_after", FieldType.STRING)
_f("cf.tls_client_auth.cert_not_before", FieldType.STRING)
_f("cf.tls_client_auth.cert_presented", FieldType.BOOL)
_f("cf.tls_client_auth.cert_revoked", FieldType.BOOL)
_f("cf.tls_client_auth.cert_serial", FieldType.STRING)
_f("cf.tls_client_auth.cert_ski", FieldType.STRING)
_f("cf.tls_client_auth.cert_subject_dn", FieldType.STRING)
_f("cf.tls_client_auth.cert_subject_dn_legacy", FieldType.STRING)
_f("cf.tls_client_auth.cert_subject_dn_rfc2253", FieldType.STRING)
_f("cf.tls_client_auth.cert_verified", FieldType.BOOL)
_f("cf.tls_client_extensions_sha1", FieldType.STRING)
_f("cf.tls_client_extensions_sha1_le", FieldType.STRING)
_f("cf.tls_client_hello_length", FieldType.INT)
_f("cf.tls_client_random", FieldType.STRING)
_f("cf.tls_version", FieldType.STRING)
_f("cf.verified_bot_category", FieldType.STRING)
_f("cf.waf.auth_detected", FieldType.BOOL, requires_plan="enterprise")
_f("cf.waf.content_scan.has_failed", FieldType.BOOL, requires_plan="enterprise")
_f("cf.waf.content_scan.has_malicious_obj", FieldType.BOOL, requires_plan="enterprise")
_f("cf.waf.content_scan.has_obj", FieldType.BOOL, requires_plan="enterprise")
_f("cf.waf.content_scan.num_malicious_obj", FieldType.INT, requires_plan="enterprise")
_f("cf.waf.content_scan.num_obj", FieldType.INT, requires_plan="enterprise")
_f("cf.waf.content_scan.obj_results", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("cf.waf.content_scan.obj_sizes", FieldType.ARRAY_INT, requires_plan="enterprise")
_f("cf.waf.content_scan.obj_types", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("cf.waf.credential_check.password_leaked", FieldType.BOOL)
_f("cf.waf.credential_check.username_and_password_leaked", FieldType.BOOL, requires_plan="pro")
_f("cf.waf.credential_check.username_leaked", FieldType.BOOL, requires_plan="enterprise")
_f("cf.waf.credential_check.username_password_similar", FieldType.BOOL, requires_plan="enterprise")
_f("cf.waf.score", FieldType.INT, requires_plan="enterprise")
_f("cf.waf.score.class", FieldType.STRING, requires_plan="business")
_f("cf.waf.score.rce", FieldType.INT, requires_plan="enterprise")
_f("cf.waf.score.sqli", FieldType.INT, requires_plan="enterprise")
_f("cf.waf.score.xss", FieldType.INT, requires_plan="enterprise")
_f("cf.worker.upstream_zone", FieldType.STRING)
_f("http.cookie", FieldType.STRING)
_f("http.host", FieldType.STRING)
_f("http.referer", FieldType.STRING)
_f("http.request.accepted_languages", FieldType.ARRAY_STRING)
_f("http.request.body.form", FieldType.MAP_ARRAY_STRING, requires_plan="enterprise")
_f("http.request.body.form.names", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("http.request.body.form.values", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("http.request.body.mime", FieldType.STRING)
_f("http.request.body.multipart", FieldType.MAP_ARRAY_STRING, requires_plan="enterprise")
_f(
    "http.request.body.multipart.content_dispositions",
    FieldType.ARRAY_ARRAY_STRING,
    requires_plan="enterprise",
)
_f(
    "http.request.body.multipart.content_transfer_encodings",
    FieldType.ARRAY_ARRAY_STRING,
    requires_plan="enterprise",
)
_f(
    "http.request.body.multipart.content_types",
    FieldType.ARRAY_ARRAY_STRING,
    requires_plan="enterprise",
)
_f(
    "http.request.body.multipart.filenames",
    FieldType.ARRAY_ARRAY_STRING,
    requires_plan="enterprise",
)
_f("http.request.body.multipart.names", FieldType.ARRAY_ARRAY_STRING, requires_plan="enterprise")
_f("http.request.body.multipart.values", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("http.request.body.raw", FieldType.STRING, requires_plan="enterprise")
_f("http.request.body.size", FieldType.INT, requires_plan="enterprise")
_f("http.request.body.truncated", FieldType.BOOL, requires_plan="enterprise")
_f("http.request.cookies", FieldType.MAP_ARRAY_STRING, requires_plan="pro")
_f("http.request.full_uri", FieldType.STRING)
_f("http.request.headers", FieldType.MAP_ARRAY_STRING)
_f("http.request.headers.names", FieldType.ARRAY_STRING)
_f("http.request.headers.truncated", FieldType.BOOL)
_f("http.request.headers.values", FieldType.ARRAY_STRING)
_f("http.request.jwt.claims.aud", FieldType.MAP_ARRAY_STRING, requires_plan="enterprise")
_f("http.request.jwt.claims.aud.names", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("http.request.jwt.claims.aud.values", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("http.request.jwt.claims.iat.sec", FieldType.MAP_ARRAY_INT, requires_plan="enterprise")
_f("http.request.jwt.claims.iat.sec.names", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("http.request.jwt.claims.iat.sec.values", FieldType.ARRAY_INT, requires_plan="enterprise")
_f("http.request.jwt.claims.iss", FieldType.MAP_ARRAY_STRING, requires_plan="enterprise")
_f("http.request.jwt.claims.iss.names", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("http.request.jwt.claims.iss.values", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("http.request.jwt.claims.jti", FieldType.MAP_ARRAY_STRING, requires_plan="enterprise")
_f("http.request.jwt.claims.jti.names", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("http.request.jwt.claims.jti.values", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("http.request.jwt.claims.nbf.sec", FieldType.MAP_ARRAY_INT, requires_plan="enterprise")
_f("http.request.jwt.claims.nbf.sec.names", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("http.request.jwt.claims.nbf.sec.values", FieldType.ARRAY_INT, requires_plan="enterprise")
_f("http.request.jwt.claims.sub", FieldType.MAP_ARRAY_STRING, requires_plan="enterprise")
_f("http.request.jwt.claims.sub.names", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("http.request.jwt.claims.sub.values", FieldType.ARRAY_STRING, requires_plan="enterprise")
_f("http.request.method", FieldType.STRING)
_f("http.request.timestamp.msec", FieldType.INT)
_f("http.request.timestamp.sec", FieldType.INT)
_f("http.request.uri", FieldType.STRING)
_f("http.request.uri.args", FieldType.MAP_ARRAY_STRING)
_f("http.request.uri.args.names", FieldType.ARRAY_STRING)
_f("http.request.uri.args.values", FieldType.ARRAY_STRING)
_f("http.request.uri.path.extension", FieldType.STRING)
_f("http.request.uri.query", FieldType.STRING)
_f("http.request.version", FieldType.STRING)
_f("http.response.code", FieldType.INT, is_response=True)
_f("http.response.content_type.media_type", FieldType.STRING, is_response=True)
_f("http.response.headers", FieldType.MAP_ARRAY_STRING, is_response=True)
_f("http.response.headers.names", FieldType.ARRAY_STRING, is_response=True)
_f("http.response.headers.truncated", FieldType.BOOL, is_response=True)
_f("http.response.headers.values", FieldType.ARRAY_STRING, is_response=True)
_f("http.user_agent", FieldType.STRING)
_f("http.x_forwarded_for", FieldType.STRING)
_f("ip.src", FieldType.IP)
_f("ip.src.asnum", FieldType.INT)
_f("ip.src.city", FieldType.STRING)
_f("ip.src.continent", FieldType.STRING)
_f("ip.src.country", FieldType.STRING)
_f("ip.src.is_in_european_union", FieldType.BOOL, requires_plan="business")
_f("ip.src.lat", FieldType.STRING)
_f("ip.src.lon", FieldType.STRING)
_f("ip.src.metro_code", FieldType.STRING)
_f("ip.src.postal_code", FieldType.STRING)
_f("ip.src.region", FieldType.STRING)
_f("ip.src.region_code", FieldType.STRING)
_f("ip.src.subdivision_1_iso_code", FieldType.STRING, requires_plan="business")
_f("ip.src.subdivision_2_iso_code", FieldType.STRING, requires_plan="business")
_f("ip.src.timezone.name", FieldType.STRING)
_f("raw.http.request.full_uri", FieldType.STRING)
_f("raw.http.request.uri", FieldType.STRING)
_f("raw.http.request.uri.args", FieldType.MAP_ARRAY_STRING)
_f("raw.http.request.uri.args.names", FieldType.ARRAY_STRING)
_f("raw.http.request.uri.args.values", FieldType.ARRAY_STRING)
_f("raw.http.request.uri.path", FieldType.STRING)
_f("raw.http.request.uri.path.extension", FieldType.STRING)
_f("raw.http.request.uri.query", FieldType.STRING)
_f("raw.http.response.headers", FieldType.MAP_ARRAY_STRING, is_response=True)
_f("raw.http.response.headers.names", FieldType.ARRAY_STRING, is_response=True)
_f("raw.http.response.headers.values", FieldType.ARRAY_STRING, is_response=True)
_f("ssl", FieldType.BOOL)
# --- END GENERATED FIELDS --- #

# Scheme-specific: http.request.uri.path is a field in default scheme,
# a function in transform phases. Not in generated block.
_f("http.request.uri.path", FieldType.STRING)

# Deprecated fields — still registered so the linter can flag them with G010.
_f("ip.geoip.asnum", FieldType.INT)
_f("ip.geoip.continent", FieldType.STRING)
_f("ip.geoip.country", FieldType.STRING)
_f("ip.geoip.subdivision_1_iso_code", FieldType.STRING)
_f("ip.geoip.subdivision_2_iso_code", FieldType.STRING)
_f("ip.geoip.is_in_european_union", FieldType.BOOL)

# Account-level zone fields (not in CF docs YAML)
_f("cf.zone.name", FieldType.STRING)
_f("cf.zone.plan", FieldType.STRING)


# --- Response-only phases ---
# Phases where response fields are available
RESPONSE_PHASES = frozenset(
    {
        "response_header_rules",
        "compression_rules",
        "sensitive_data_detection",
        "custom_error_rules",
        "log_custom_fields",
    }
)

# Phases where request body fields are available
BODY_PHASES = frozenset(
    {
        "waf_custom_rules",
        "waf_managed_rules",
        "rate_limiting_rules",
        "custom_error_rules",
    }
)


def get_field(name: str) -> FieldDef | None:
    """Look up a field definition by name."""
    return FIELDS.get(name)


def is_response_field(name: str) -> bool:
    """Check if a field is response-only."""
    fd = FIELDS.get(name)
    return fd.is_response if fd else False


def is_body_field(name: str) -> bool:
    """Check if a field is a request body field."""
    return name.startswith("http.request.body.")
