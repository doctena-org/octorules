"""Audit checks for cross-rule, cross-zone IP analysis.

Provides four checks:

- **ip-overlap**: Cross-rule IP range overlaps within a zone.
- **ip-shadow**: Rules shadowed by broader rules in earlier phases.
- **cdn-ranges**: Rules matching known CDN provider IP ranges.
- **zone-drift**: Same CIDR treated differently across zones.
"""

import ipaddress
import json as _json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from octorules import USER_AGENT
from octorules._cdn_sources import (
    _AZURE_DETAILS_URL,
    _AZURE_JSON_URL_RE,
    _BUNNY_URLS,
    _parse_aws_cloudfront_ips,
    _parse_azure_front_door_ips,
    _parse_bunny_ips,
    _parse_cloudflare_ips,
    _parse_google_cloud_ips,
)

log = logging.getLogger(__name__)

# All available audit check names.
ALL_CHECKS: frozenset[str] = frozenset({"ip-overlap", "ip-shadow", "cdn-ranges", "zone-drift"})

# Severity ordering (lower rank = higher severity).
_SEVERITY_RANK: dict["FindingSeverity", int] = {}  # populated after enum definition
# ---------------------------------------------------------------------------
# Suppression parser
# ---------------------------------------------------------------------------

# Matches: # octorules:accept=zone-drift
# Also:    # octorules: accept = ip-overlap, cdn-ranges
# Case-sensitive: check names must be lowercase (ip-overlap, not IP-Overlap).
_AUDIT_ACCEPT_RE = re.compile(
    r"#\s*octorules:\s*accept\s*=\s*([a-z][a-z0-9-]*(?:\s*,\s*[a-z][a-z0-9-]*)*)"
)


def parse_audit_acceptances(file_path: str | Path) -> set[str]:
    """Parse ``# octorules:accept=<check>`` directives from a YAML file.

    Returns a set of accepted check names (e.g. ``{"zone-drift"}``).
    Unknown check names are logged as warnings and silently dropped.
    """
    accepted: set[str] = set()
    try:
        text = Path(file_path).read_text()
    except OSError:
        return accepted

    for m in _AUDIT_ACCEPT_RE.finditer(text):
        names = {n.strip() for n in m.group(1).split(",")}
        unknown = names - ALL_CHECKS
        for u in sorted(unknown):
            log.warning("Unknown audit check %r in acceptance directive (%s)", u, file_path)
        accepted.update(names - unknown)

    return accepted


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


# Populate after enum definition (lower rank = higher severity).
_SEVERITY_RANK.update(
    {
        FindingSeverity.ERROR: 1,
        FindingSeverity.WARNING: 2,
        FindingSeverity.INFO: 3,
    }
)


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
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                log.warning("HTTP %d from %s", resp.status, url)
                return None
            return _json.loads(resp.read())
    except (_json.JSONDecodeError, OSError, TimeoutError) as e:
        log.warning("Failed to fetch %s: %s", url, e)
        return None


def _fetch_text(url: str, timeout: int = 15) -> str | None:
    """Fetch plain text from a URL. Returns decoded body or None on failure."""
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                log.warning("HTTP %d from %s", resp.status, url)
                return None
            return resp.read().decode("utf-8", errors="replace")
    except (OSError, TimeoutError) as e:
        log.warning("Failed to fetch %s: %s", url, e)
        return None


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
    ("bunny.json", "Bunny"),
    ("azure_front_door.json", "Azure Front Door"),
]


def _fetch_bunny_text(timeout: int = 15) -> str | None:
    """Fetch and concatenate Bunny IPv4 + IPv6 edge server lists."""
    parts: list[str] = []
    for url in _BUNNY_URLS:
        body = _fetch_text(url, timeout=timeout)
        if body:
            parts.append(body)
    return "\n".join(parts) if parts else None


def _fetch_azure_service_tags(timeout: int = 15) -> Any:
    """Scrape the Azure Download Center page and fetch the current ServiceTags JSON."""
    html = _fetch_text(_AZURE_DETAILS_URL, timeout=timeout)
    if not html:
        return None
    m = _AZURE_JSON_URL_RE.search(html)
    if not m:
        log.warning(
            "Azure details page: no ServiceTags_Public JSON URL found (page layout changed?)"
        )
        return None
    return _fetch_json(m.group(0), timeout=timeout)


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


def fetch_cdn_ranges(timeout: int = 15, cdn_stale_days: int = 60) -> CdnRangeResult:
    """Return CDN IP ranges, using baked-in data when fresh.

    Strategy:
    1. Load baked-in ranges from package data files.
    2. If they are fresh (younger than *cdn_stale_days*), return immediately
       — no network calls needed.
    3. If stale (or missing), fetch from the CDN APIs concurrently.
    4. If all API fetches fail, fall back to stale baked-in data anyway.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    baked = _load_baked_in_ranges()
    if baked.ranges and not baked.is_stale(cdn_stale_days):
        log.debug("Using fresh baked-in CDN ranges (%s)", baked.source)
        return baked

    # Baked-in data is stale or missing — fetch from APIs concurrently.
    log.debug("Baked-in CDN ranges are stale, fetching from APIs")

    def _cf_fetch(to: int) -> Any:
        return _fetch_json("https://api.cloudflare.com/client/v4/ips", timeout=to)

    def _aws_fetch(to: int) -> Any:
        return _fetch_json("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=to)

    def _google_fetch(to: int) -> Any:
        return _fetch_json("https://www.gstatic.com/ipranges/cloud.json", timeout=to)

    # (label, fetcher(timeout) -> data, parser(data) -> list[str])
    sources = [
        ("Cloudflare", _cf_fetch, _parse_cloudflare_ips),
        ("AWS CloudFront", _aws_fetch, _parse_aws_cloudfront_ips),
        ("Google Cloud", _google_fetch, _parse_google_cloud_ips),
        ("Bunny", _fetch_bunny_text, _parse_bunny_ips),
        ("Azure Front Door", _fetch_azure_service_tags, _parse_azure_front_door_ips),
    ]

    result: dict[str, list[str]] = {}

    def _fetch_one(source_tuple: tuple) -> tuple[str, list[str]] | None:
        label, fetcher, parser = source_tuple
        data = fetcher(timeout)
        if data is None:
            return None
        cidrs = parser(data)
        if cidrs:
            log.debug("Fetched %d CIDRs from %s", len(cidrs), label)
            return (label, cidrs)
        return None

    with ThreadPoolExecutor(max_workers=len(sources)) as executor:
        futures = {executor.submit(_fetch_one, s): s for s in sources}
        for future in as_completed(futures):
            pair = future.result()
            if pair is not None:
                result[pair[0]] = pair[1]

    if result:
        return CdnRangeResult(ranges=result, source="api")

    # All API fetches failed — fall back to stale baked-in data.
    if baked.ranges:
        log.warning("CDN API fetch failed, falling back to stale baked-in ranges")
        return baked

    log.warning("No CDN IP ranges available (API fetch failed, no baked-in data)")
    return CdnRangeResult(ranges={}, source="baked-in")


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

    Uses a sweep-line algorithm: entries are sorted by network address
    (ascending) then prefix length (ascending = broadest first).  A stack
    of "active" networks is maintained; each new entry is checked against
    the stack top.  If the new entry falls within the active network and
    belongs to a different rule, it's an overlap.  Complexity is
    O(n log n) instead of O(n²).
    """
    findings: list[AuditFinding] = []

    # Build and sort entries per address family.
    Entry = tuple[
        int,  # network_address (as int, for sorting)
        int,  # prefix_length
        int,  # broadcast_address (as int, for containment check)
        str,  # ref
        str,  # phase_name
        str,  # zone_name
        str,  # cidr_str
        ipaddress.IPv4Network | ipaddress.IPv6Network,  # net
    ]

    entries_v4: list[Entry] = []
    entries_v6: list[Entry] = []
    for info in rule_ips:
        for cidr in info.ip_ranges:
            net = _to_network(cidr)
            if net is None:
                continue
            entry = (
                int(net.network_address),
                net.prefixlen,
                int(net.broadcast_address),
                info.ref,
                info.phase_name,
                info.zone_name,
                cidr,
                net,
            )
            if net.version == 4:
                entries_v4.append(entry)
            else:
                entries_v6.append(entry)

    def _sweep(entries: list[Entry]) -> None:
        # Sort by network address ascending, then prefix length ascending
        # (broadest first when same network address — e.g. /8 before /16).
        entries.sort(key=lambda e: (e[0], e[1]))

        # Stack of active (broadcast_int, ref, phase, zone, cidr, net).
        # An entry is "active" while the sweep position is within its range.
        _Net = ipaddress.IPv4Network | ipaddress.IPv6Network
        stack: list[tuple[int, str, str, str, str, _Net]] = []

        for net_addr, _prefixlen, bcast, ref, phase, zone, cidr_str, net in entries:
            # Pop expired entries from the stack (their broadcast < current network address).
            while stack and stack[-1][0] < net_addr:
                stack.pop()

            # Check remaining stack entries for overlap (they all contain this entry).
            for _s_bcast, s_ref, s_phase, _s_zone, s_cidr, _s_net in stack:
                # Skip intra-rule comparison.
                if ref == s_ref and phase == s_phase:
                    continue
                # The stack entry contains this entry (broader contains narrower).
                narrower = cidr_str
                broader = s_cidr
                findings.append(
                    AuditFinding(
                        check="ip-overlap",
                        severity=FindingSeverity.WARNING,
                        message=(
                            f"Overlapping IP ranges: {narrower} (in {ref}/{phase})"
                            f" overlaps {broader} (in {s_ref}/{s_phase})"
                        ),
                        zone_name=zone,
                        phase_name=phase,
                        ref=ref,
                    )
                )

            stack.append((bcast, ref, phase, zone, cidr_str, net))

    _sweep(entries_v4)
    _sweep(entries_v6)
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
        {"block", "managed_challenge", "js_challenge", "challenge", "deny"}
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
    """Check if any rule IPs match known CDN provider IP ranges.

    Uses a sorted-interval approach: CDN ranges are sorted by start
    address, then each rule CIDR is checked via binary search against
    candidate CDN ranges.  Complexity is O((n + m) log m) instead of
    O(n * m).
    """
    import bisect

    findings: list[AuditFinding] = []

    # Pre-parse CDN networks into (start_int, end_int, provider, net) sorted by start.
    CdnEntry = tuple[int, int, str, ipaddress.IPv4Network | ipaddress.IPv6Network]
    cdn_v4: list[CdnEntry] = []
    cdn_v6: list[CdnEntry] = []
    for provider, cidrs in cdn_ranges.items():
        for cidr in cidrs:
            net = _to_network(cidr)
            if net is None:
                continue
            entry = (int(net.network_address), int(net.broadcast_address), provider, net)
            if net.version == 4:
                cdn_v4.append(entry)
            else:
                cdn_v6.append(entry)

    cdn_v4.sort()
    cdn_v6.sort()
    # Extract start addresses for bisect.
    cdn_v4_starts = [e[0] for e in cdn_v4]
    cdn_v6_starts = [e[0] for e in cdn_v6]

    if not cdn_v4 and not cdn_v6:
        return findings

    def _check_against(
        net: ipaddress.IPv4Network | ipaddress.IPv6Network,
        cdn_list: list[CdnEntry],
        cdn_starts: list[int],
    ) -> tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network] | None:
        """Find the first CDN range that overlaps *net*, or None."""
        addr_start = int(net.network_address)
        addr_end = int(net.broadcast_address)

        # Find CDN ranges whose start <= addr_end (candidates for overlap).
        idx = bisect.bisect_right(cdn_starts, addr_end)
        # Check candidates in reverse (closest start first).
        for i in range(idx - 1, -1, -1):
            cdn_start, cdn_end, cdn_provider, cdn_net = cdn_list[i]
            # Overlap: ranges intersect if start_a <= end_b AND start_b <= end_a.
            if cdn_start <= addr_end and addr_start <= cdn_end:
                return (cdn_provider, cdn_net)
            # NOTE: we cannot break early here.  CDN ranges are sorted by
            # start address, but a broader prefix (e.g. /8) at a lower
            # index can have a *higher* end than a narrower prefix at a
            # higher index, so we must check every candidate.
        return None

    for info in rule_ips:
        for cidr in info.ip_ranges:
            net = _to_network(cidr)
            if net is None:
                continue
            cdn_list = cdn_v4 if net.version == 4 else cdn_v6
            cdn_starts = cdn_v4_starts if net.version == 4 else cdn_v6_starts
            match = _check_against(net, cdn_list, cdn_starts)
            if match is not None:
                cdn_provider, cdn_net = match
                findings.append(
                    AuditFinding(
                        check="cdn-ranges",
                        severity=FindingSeverity.WARNING,
                        message=(
                            f"{cidr} (in {info.ref}/{info.phase_name})"
                            f" overlaps {cdn_provider} range {cdn_net}"
                        ),
                        zone_name=info.zone_name,
                        phase_name=info.phase_name,
                        ref=info.ref,
                    )
                )
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

        # Check if actions differ (case-insensitive comparison; display uses
        # original casing from each provider for clarity).
        actions_by_zone: dict[str, set[str]] = {}
        for zone, _phase, _ref, action in usages:
            actions_by_zone.setdefault(zone, set()).add(action.lower())

        unique_action_sets = {frozenset(a) for a in actions_by_zone.values()}
        if len(unique_action_sets) <= 1:
            continue  # Same actions everywhere

        zone_details = []
        for zone, _phase, ref, action in usages:
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
_FINDING_SEVERITY_PEN_METHOD = {
    FindingSeverity.ERROR: "error",
    FindingSeverity.WARNING: "warning",
    FindingSeverity.INFO: "info",
}


def _filter_findings_by_severity(
    findings: list[AuditFinding], min_severity: FindingSeverity
) -> list[AuditFinding]:
    """Return only the findings at or above *min_severity*."""
    max_rank = _SEVERITY_RANK[min_severity]
    return [f for f in findings if _SEVERITY_RANK[f.severity] <= max_rank]


def format_findings(
    findings: list[AuditFinding],
    *,
    min_severity: FindingSeverity = FindingSeverity.INFO,
    use_color: bool = False,
) -> str:
    """Format findings as human-readable text.

    *min_severity* filters which findings are displayed (lower severity
    findings are omitted).  The caller is responsible for using the
    unfiltered list for exit-code decisions.
    """
    from octorules._color import Pen

    p = Pen(use_color)
    filtered = _filter_findings_by_severity(findings, min_severity)
    if not filtered:
        return ""

    lines: list[str] = []
    by_check: dict[str, list[AuditFinding]] = {}
    for f in filtered:
        by_check.setdefault(f.check, []).append(f)

    for check in ("ip-overlap", "ip-shadow", "cdn-ranges", "zone-drift"):
        check_findings = by_check.get(check, [])
        if not check_findings:
            continue
        lines.append(p.header(f"\n[{check}] {len(check_findings)} finding(s):"))
        for f in check_findings:
            # Use lowercase "warning:" instead of "[WARNING]" to avoid
            # GitHub Actions interpreting bracketed severity as annotations
            # (which mangles the output into "Warning: G]").
            method = _FINDING_SEVERITY_PEN_METHOD[f.severity]
            sev_label = getattr(p, method)(f"{f.severity.value}:")
            prefix = f"  {sev_label}"
            if f.zone_name:
                prefix += f" {f.zone_name}"
            lines.append(f"{prefix} {f.message}")

    return "\n".join(lines)


def format_findings_json(
    findings: list[AuditFinding],
    *,
    min_severity: FindingSeverity = FindingSeverity.INFO,
) -> str:
    """Format findings as JSON."""
    filtered = _filter_findings_by_severity(findings, min_severity)
    data = [
        {
            "check": f.check,
            "severity": f.severity.value,
            "message": f.message,
            "zone_name": f.zone_name,
            "phase_name": f.phase_name,
            "ref": f.ref,
        }
        for f in filtered
    ]
    return _json.dumps(data, indent=2) + "\n"


def format_findings_summary(
    findings: list[AuditFinding],
    *,
    min_severity: FindingSeverity = FindingSeverity.INFO,
    **_kwargs,
) -> str:
    """Format findings as a one-line summary (counts only)."""
    filtered = _filter_findings_by_severity(findings, min_severity)
    by_check: dict[str, int] = {}
    for f in filtered:
        by_check[f.check] = by_check.get(f.check, 0) + 1
    if not by_check:
        return ""
    parts = [f"{check}: {count}" for check, count in sorted(by_check.items())]
    return ", ".join(parts) + "\n"


AUDIT_FORMATTERS: dict[str, Any] = {
    "text": format_findings,
    "json": format_findings_json,
    "summary": format_findings_summary,
}


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
        infos, failed = call_audit_extensions(rules_data, phase_name)
        all_infos.extend(infos)
        for ext_name in failed:
            log.warning(
                "Audit extension %r failed for phase %r in zone %r — results may be incomplete",
                ext_name,
                phase_name,
                zone_name,
            )

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
        cdn_result = fetch_cdn_ranges(timeout=cdn_timeout, cdn_stale_days=cdn_stale_days)
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
