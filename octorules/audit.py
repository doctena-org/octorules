"""Audit checks for cross-rule, cross-zone IP analysis.

Provides four checks:

- **ip-overlap**: Cross-rule IP range overlaps within a zone.
- **ip-shadow**: Rules shadowed by broader rules in earlier phases.
- **cdn-ranges**: Rules matching known CDN provider IP ranges.
- **zone-drift**: Same CIDR treated differently across zones.
"""

from __future__ import annotations

import ipaddress
import json as _json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

log = logging.getLogger(__name__)

# All available audit check names.
ALL_CHECKS: frozenset[str] = frozenset({"ip-overlap", "ip-shadow", "cdn-ranges", "zone-drift"})


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class RuleIPInfo:
    """IP ranges extracted from a single rule by a provider audit extension."""

    zone_name: str
    phase_name: str
    ref: str
    action: str
    ip_ranges: list[str]
    """IPv4/IPv6 CIDRs (e.g. ``["203.0.113.0/24", "2001:db8::/32"]``)."""
    list_refs: list[str] = field(default_factory=list)
    """List names referenced by this rule (e.g. ``["blocked_ips"]``).
    Resolved to IPs by :func:`audit_zone_rules` using the ``lists`` section."""


class FindingSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class AuditFinding:
    """A single audit finding."""

    check: str
    severity: FindingSeverity
    message: str
    zone_name: str = ""
    phase_name: str = ""
    ref: str = ""


# ---------------------------------------------------------------------------
# CDN range fetching
# ---------------------------------------------------------------------------


def _fetch_json(url: str, timeout: int = 15) -> Any:
    """Fetch JSON from a URL. Returns parsed data or None on failure."""
    import json

    req = Request(url, headers={"User-Agent": "octorules-audit/1.0"})
    try:
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return json.loads(resp.read())
    except Exception as e:
        log.warning("Failed to fetch %s: %s", url, e)
        return None


def _parse_cloudflare_ips(data: dict) -> list[str]:
    """Extract CIDRs from Cloudflare /client/v4/ips response."""
    if not isinstance(data, dict):
        return []
    result = data.get("result", {})
    if not isinstance(result, dict):
        return []
    cidrs: list[str] = []
    for key in ("ipv4_cidrs", "ipv6_cidrs"):
        val = result.get(key)
        if isinstance(val, list):
            cidrs.extend(str(c) for c in val)
    return cidrs


def _parse_aws_cloudfront_ips(data: dict) -> list[str]:
    """Extract CloudFront CIDRs from AWS ip-ranges.json."""
    if not isinstance(data, dict):
        return []
    cidrs: list[str] = []
    for prefix in data.get("prefixes", []):
        if isinstance(prefix, dict) and prefix.get("service") == "CLOUDFRONT":
            ip = prefix.get("ip_prefix")
            if ip:
                cidrs.append(str(ip))
    for prefix in data.get("ipv6_prefixes", []):
        if isinstance(prefix, dict) and prefix.get("service") == "CLOUDFRONT":
            ip = prefix.get("ipv6_prefix")
            if ip:
                cidrs.append(str(ip))
    return cidrs


def _parse_google_cloud_ips(data: dict) -> list[str]:
    """Extract CIDRs from Google Cloud ip-ranges JSON."""
    if not isinstance(data, dict):
        return []
    cidrs: list[str] = []
    for prefix in data.get("prefixes", []):
        if isinstance(prefix, dict):
            for key in ("ipv4Prefix", "ipv6Prefix"):
                ip = prefix.get(key)
                if ip:
                    cidrs.append(str(ip))
    return cidrs


@dataclass
class CdnRangeResult:
    """CDN IP ranges with source metadata for staleness detection."""

    ranges: dict[str, list[str]]
    source: str  # "api" or "baked-in"
    generated_at: datetime | None = None  # None for API (always fresh)

    def is_stale(self, max_age_days: int = 60) -> bool:
        """Return True if the data is older than *max_age_days*."""
        if self.generated_at is None:
            return False  # API data is always fresh
        return datetime.now(timezone.utc) - self.generated_at > timedelta(days=max_age_days)


_CDN_DATA_DIR = Path(__file__).resolve().parent / "data" / "cdn_ranges"

_CDN_FILES = [
    ("cloudflare.json", "Cloudflare"),
    ("aws_cloudfront.json", "AWS CloudFront"),
    ("google_cloud.json", "Google Cloud"),
]


def _load_baked_in_ranges() -> CdnRangeResult:
    """Load baked-in CDN IP ranges from package data files.

    Returns a :class:`CdnRangeResult` with ``source="baked-in"`` and the
    oldest ``_generated_at`` timestamp as the staleness anchor.
    """
    ranges: dict[str, list[str]] = {}
    oldest: datetime | None = None

    for filename, provider in _CDN_FILES:
        path = _CDN_DATA_DIR / filename
        if not path.exists():
            log.debug("Baked-in CDN file not found: %s", path)
            continue
        try:
            with open(path, encoding="utf-8") as f:
                data = _json.load(f)
        except (OSError, _json.JSONDecodeError) as e:
            log.warning("Failed to load baked-in CDN file %s: %s", path, e)
            continue

        cidrs = data.get("cidrs", [])
        if isinstance(cidrs, list) and cidrs:
            ranges[provider] = [str(c) for c in cidrs]

        generated_at_str = data.get("_generated_at", "")
        if generated_at_str:
            try:
                ts = datetime.fromisoformat(generated_at_str.replace("Z", "+00:00"))
                if oldest is None or ts < oldest:
                    oldest = ts
            except ValueError:
                pass

    return CdnRangeResult(ranges=ranges, source="baked-in", generated_at=oldest)


def fetch_cdn_ranges(timeout: int = 15) -> CdnRangeResult:
    """Fetch CDN IP ranges from public APIs, falling back to baked-in data.

    Tries all three CDN APIs.  If any succeed, returns a ``CdnRangeResult``
    with ``source="api"``.  If all fail, falls back to the baked-in JSON
    files shipped with the package.
    """
    sources = [
        ("Cloudflare", "https://api.cloudflare.com/client/v4/ips", _parse_cloudflare_ips),
        (
            "AWS CloudFront",
            "https://ip-ranges.amazonaws.com/ip-ranges.json",
            _parse_aws_cloudfront_ips,
        ),
        ("Google Cloud", "https://www.gstatic.com/ipranges/cloud.json", _parse_google_cloud_ips),
    ]
    result: dict[str, list[str]] = {}
    for label, url, parser in sources:
        data = _fetch_json(url, timeout=timeout)
        if data is None:
            continue
        cidrs = parser(data)
        if cidrs:
            result[label] = cidrs
            log.debug("Fetched %d CIDRs from %s", len(cidrs), label)

    if result:
        return CdnRangeResult(ranges=result, source="api")

    # All API fetches failed — fall back to baked-in data.
    log.warning("CDN API fetch failed, falling back to baked-in ranges")
    return _load_baked_in_ranges()


# ---------------------------------------------------------------------------
# Check implementations
# ---------------------------------------------------------------------------


def _to_network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Parse a CIDR string, returning None on failure."""
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


def check_ip_overlap(rule_ips: list[RuleIPInfo]) -> list[AuditFinding]:
    """Cross-rule IP range overlap detection within a zone.

    Compares IPs across *different* rules (intra-rule overlaps are
    already caught by per-provider linters).
    """
    findings: list[AuditFinding] = []

    # Build list of (rule_ref, phase, cidr_str, network) tuples
    entries: list[tuple[str, str, str, str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for info in rule_ips:
        for cidr in info.ip_ranges:
            net = _to_network(cidr)
            if net is not None:
                entries.append((info.ref, info.phase_name, info.zone_name, cidr, net))

    for i, (ref_a, phase_a, zone_a, cidr_a, net_a) in enumerate(entries):
        for ref_b, phase_b, zone_b, cidr_b, net_b in entries[i + 1 :]:
            if ref_a == ref_b and phase_a == phase_b:
                continue  # Skip intra-rule comparison
            if net_a.version != net_b.version:
                continue
            if not net_a.overlaps(net_b):
                continue
            # Determine narrower/broader for message
            if net_a.prefixlen >= net_b.prefixlen:
                narrower, broader = cidr_a, cidr_b
            else:
                narrower, broader = cidr_b, cidr_a
            findings.append(
                AuditFinding(
                    check="ip-overlap",
                    severity=FindingSeverity.WARNING,
                    message=(
                        f"Overlapping IP ranges: {narrower} (in {ref_a}/{phase_a})"
                        f" overlaps {broader} (in {ref_b}/{phase_b})"
                    ),
                    zone_name=zone_a,
                    phase_name=phase_a,
                    ref=ref_a,
                )
            )
    return findings


def check_ip_shadow(rule_ips: list[RuleIPInfo], phase_order: list[str]) -> list[AuditFinding]:
    """Detect rules shadowed by broader rules in earlier phases.

    A rule is "shadowed" when *all* its IPs are contained within IPs of
    a rule in an earlier phase with a blocking action (block/deny/challenge).
    """
    findings: list[AuditFinding] = []
    phase_rank = {p: i for i, p in enumerate(phase_order)}

    # Group by zone
    by_zone: dict[str, list[RuleIPInfo]] = {}
    for info in rule_ips:
        by_zone.setdefault(info.zone_name, []).append(info)

    blocking_actions = frozenset(
        {"block", "managed_challenge", "js_challenge", "challenge", "deny", "Block"}
    )

    for zone_name, infos in by_zone.items():
        # For each rule, check if all its IPs are covered by an earlier-phase blocking rule
        for info in infos:
            if not info.ip_ranges:
                continue
            info_rank = phase_rank.get(info.phase_name)
            if info_rank is None:
                continue

            info_nets = [_to_network(c) for c in info.ip_ranges]
            info_nets = [n for n in info_nets if n is not None]
            if not info_nets:
                continue

            for other in infos:
                if other is info:
                    continue
                if not other.ip_ranges:
                    continue
                other_rank = phase_rank.get(other.phase_name)
                if other_rank is None or other_rank >= info_rank:
                    continue  # Not an earlier phase

                # Check if action is blocking
                action_lower = (other.action or "").lower()
                # Handle Google deny(NNN) format
                if action_lower.startswith("deny"):
                    is_blocking = True
                else:
                    is_blocking = action_lower in blocking_actions

                if not is_blocking:
                    continue

                other_nets = [_to_network(c) for c in other.ip_ranges]
                other_nets = [n for n in other_nets if n is not None]
                if not other_nets:
                    continue

                # Check if every IP in info is covered by some IP in other
                all_shadowed = True
                for info_net in info_nets:
                    covered = False
                    for other_net in other_nets:
                        if info_net.version != other_net.version:
                            continue
                        if info_net.subnet_of(other_net):
                            covered = True
                            break
                    if not covered:
                        all_shadowed = False
                        break

                if all_shadowed:
                    findings.append(
                        AuditFinding(
                            check="ip-shadow",
                            severity=FindingSeverity.WARNING,
                            message=(
                                f"Rule {info.ref} ({info.phase_name}) is shadowed by"
                                f" {other.ref} ({other.phase_name}, action={other.action}):"
                                f" all IPs are covered by the earlier rule"
                            ),
                            zone_name=zone_name,
                            phase_name=info.phase_name,
                            ref=info.ref,
                        )
                    )
                    break  # One shadow finding per rule is enough

    return findings


def check_cdn_ranges(
    rule_ips: list[RuleIPInfo],
    cdn_ranges: dict[str, list[str]],
) -> list[AuditFinding]:
    """Check if any rule IPs match known CDN provider IP ranges."""
    findings: list[AuditFinding] = []

    # Pre-parse CDN networks
    cdn_nets: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}
    for provider, cidrs in cdn_ranges.items():
        nets = []
        for cidr in cidrs:
            net = _to_network(cidr)
            if net is not None:
                nets.append(net)
        if nets:
            cdn_nets[provider] = nets

    if not cdn_nets:
        return findings

    for info in rule_ips:
        for cidr in info.ip_ranges:
            net = _to_network(cidr)
            if net is None:
                continue
            for provider, nets in cdn_nets.items():
                for cdn_net in nets:
                    if net.version != cdn_net.version:
                        continue
                    if net.overlaps(cdn_net):
                        findings.append(
                            AuditFinding(
                                check="cdn-ranges",
                                severity=FindingSeverity.WARNING,
                                message=(
                                    f"{cidr} (in {info.ref}/{info.phase_name})"
                                    f" overlaps {provider} range {cdn_net}"
                                ),
                                zone_name=info.zone_name,
                                phase_name=info.phase_name,
                                ref=info.ref,
                            )
                        )
                        break  # One finding per (rule_cidr, cdn_provider) pair
    return findings


def check_zone_drift(rule_ips: list[RuleIPInfo]) -> list[AuditFinding]:
    """Detect CIDRs treated differently across zones.

    Groups rules by normalized CIDR, then flags cases where the same
    CIDR appears in different zones with different actions.
    """
    findings: list[AuditFinding] = []

    # Group: normalized_cidr -> list of (zone, phase, ref, action)
    # Skip list pseudo-rules — they have no action, so comparing them
    # against rules would produce false drift findings.
    cidr_usage: dict[str, list[tuple[str, str, str, str]]] = {}
    for info in rule_ips:
        if info.phase_name == "lists":
            continue
        for cidr in info.ip_ranges:
            net = _to_network(cidr)
            if net is None:
                continue
            key = str(net)  # Normalized form
            cidr_usage.setdefault(key, []).append(
                (info.zone_name, info.phase_name, info.ref, info.action)
            )

    for cidr, usages in sorted(cidr_usage.items()):
        # Only care about multi-zone CIDRs
        zones = {u[0] for u in usages}
        if len(zones) <= 1:
            continue

        # Check if actions differ
        actions_by_zone: dict[str, set[str]] = {}
        for zone, phase, ref, action in usages:
            actions_by_zone.setdefault(zone, set()).add(action.lower())

        unique_action_sets = {frozenset(a) for a in actions_by_zone.values()}
        if len(unique_action_sets) <= 1:
            continue  # Same actions everywhere

        zone_details = []
        for zone, phase, ref, action in usages:
            zone_details.append(f"{zone}/{ref}={action or '(none)'}")

        findings.append(
            AuditFinding(
                check="zone-drift",
                severity=FindingSeverity.WARNING,
                message=(
                    f"CIDR {cidr} has different actions across zones: {', '.join(zone_details)}"
                ),
                zone_name=usages[0][0],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def format_findings(findings: list[AuditFinding]) -> str:
    """Format findings as human-readable text."""
    if not findings:
        return ""

    lines: list[str] = []
    by_check: dict[str, list[AuditFinding]] = {}
    for f in findings:
        by_check.setdefault(f.check, []).append(f)

    for check in ("ip-overlap", "ip-shadow", "cdn-ranges", "zone-drift"):
        check_findings = by_check.get(check, [])
        if not check_findings:
            continue
        lines.append(f"\n[{check}] {len(check_findings)} finding(s):")
        for f in check_findings:
            prefix = f"  [{f.severity.value.upper()}]"
            if f.zone_name:
                prefix += f" {f.zone_name}"
            lines.append(f"{prefix} {f.message}")

    return "\n".join(lines)


def _build_list_ip_map(rules_data: dict) -> dict[str, list[str]]:
    """Build a map from list name to IP CIDRs from the ``lists`` section."""
    lists_section = rules_data.get("lists")
    if not isinstance(lists_section, list):
        return {}

    ip_map: dict[str, list[str]] = {}
    for lst in lists_section:
        if not isinstance(lst, dict):
            continue
        kind = lst.get("kind", "")
        if kind != "ip":
            continue
        name = lst.get("name", "")
        if not isinstance(name, str) or not name:
            continue
        items = lst.get("items", [])
        if not isinstance(items, list):
            continue
        cidrs: list[str] = []
        for item in items:
            if isinstance(item, dict):
                ip = item.get("ip")
                if isinstance(ip, str):
                    cidrs.append(ip)
        if cidrs:
            ip_map[name] = cidrs
    return ip_map


def _extract_unreferenced_list_ips(
    ip_map: dict[str, list[str]],
    referenced: set[str],
) -> list[RuleIPInfo]:
    """Create pseudo-rules for IP lists not referenced by any rule.

    Lists already resolved into a rule's ``ip_ranges`` via ``list_refs``
    are excluded to avoid double-counting.
    """
    results: list[RuleIPInfo] = []
    for name, cidrs in ip_map.items():
        if name in referenced:
            continue
        results.append(
            RuleIPInfo(
                zone_name="",
                phase_name="lists",
                ref=f"list:{name}",
                action="",
                ip_ranges=cidrs,
            )
        )
    return results


def audit_zone_rules(
    rules_data: dict,
    zone_name: str,
) -> list[RuleIPInfo]:
    """Extract IP info from a zone's rules using registered audit extensions.

    Iterates over all phases present in *rules_data* and calls registered
    audit extension extractors for each.  Then resolves ``list_refs``
    populated by provider extractors into actual IPs from the ``lists``
    section.  Unreferenced IP lists are included as standalone pseudo-rules.
    """
    from octorules.extensions import call_audit_extensions

    all_infos: list[RuleIPInfo] = []
    for phase_name in rules_data:
        infos = call_audit_extensions(rules_data, phase_name)
        all_infos.extend(infos)

    # Resolve list_refs → IPs from the lists section
    ip_map = _build_list_ip_map(rules_data)
    referenced_lists: set[str] = set()
    for info in all_infos:
        if info.list_refs:
            for list_name in info.list_refs:
                cidrs = ip_map.get(list_name)
                if cidrs:
                    info.ip_ranges.extend(cidrs)
                    referenced_lists.add(list_name)

    # Include unreferenced lists as standalone pseudo-rules
    all_infos.extend(_extract_unreferenced_list_ips(ip_map, referenced_lists))

    # Stamp zone_name onto results (extractors don't know the zone)
    for info in all_infos:
        info.zone_name = zone_name

    # Drop entries with no resolved IPs (e.g. unresolvable managed list refs)
    return [info for info in all_infos if info.ip_ranges]


def run_audit(
    all_rule_ips: list[RuleIPInfo],
    phase_order: list[str],
    *,
    checks: frozenset[str] | None = None,
    cdn_timeout: int = 15,
    cdn_stale_days: int = 60,
) -> list[AuditFinding]:
    """Run selected audit checks on collected IP data.

    Args:
        all_rule_ips: IP info from all zones.
        phase_order: Ordered list of phase friendly names.
        checks: Which checks to run (default: all).
        cdn_timeout: Timeout for CDN range fetching.
        cdn_stale_days: Warn if baked-in CDN data is older than this many days.
    """
    if checks is None:
        checks = ALL_CHECKS

    findings: list[AuditFinding] = []

    if "ip-overlap" in checks:
        # Run per-zone
        by_zone: dict[str, list[RuleIPInfo]] = {}
        for info in all_rule_ips:
            by_zone.setdefault(info.zone_name, []).append(info)
        for zone_ips in by_zone.values():
            findings.extend(check_ip_overlap(zone_ips))

    if "ip-shadow" in checks:
        findings.extend(check_ip_shadow(all_rule_ips, phase_order))

    if "cdn-ranges" in checks:
        cdn_result = fetch_cdn_ranges(timeout=cdn_timeout)
        if cdn_result.ranges:
            findings.extend(check_cdn_ranges(all_rule_ips, cdn_result.ranges))
            if cdn_result.is_stale(cdn_stale_days):
                age = (datetime.now(timezone.utc) - cdn_result.generated_at).days
                findings.append(
                    AuditFinding(
                        check="cdn-ranges",
                        severity=FindingSeverity.WARNING,
                        message=(
                            f"Using baked-in CDN ranges ({age} days old,"
                            f" threshold: {cdn_stale_days} days)."
                            " Run 'scripts/sync_cdn_ranges.py' to refresh."
                        ),
                    )
                )
        else:
            log.warning("No CDN IP ranges available (API fetch failed, no baked-in data)")

    if "zone-drift" in checks:
        findings.extend(check_zone_drift(all_rule_ips))

    return findings
