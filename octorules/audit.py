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
from collections.abc import Callable
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
    _GOOGLE_CLOUD_URL,
    _GOOGLE_GOOG_URL,
    _parse_aws_cloudfront_ips,
    _parse_azure_front_door_ips,
    _parse_bunny_ips,
    _parse_cloudflare_ips,
    _parse_google_cloud_ips,
    google_front_end_cidrs,
)
from octorules.phases import display_phase_name

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

# Anchor lines a directive can attach to (shellcheck-style positional model,
# mirroring octorules' lint suppressions). ``name:`` is recognised only inside
# ``!include``d list files, where it anchors as ``list:<name>`` to match the
# audit's ``list:<name>`` finding refs.
_ACCEPT_REF_RE = re.compile(r"^\s*-\s*ref:\s*(\S+)")
_ACCEPT_DESC_RE = re.compile(r"^\s*(?:-\s*)?description:\s*(?:\"(.+?)\"|'(.+?)'|(.+?))\s*$")
_ACCEPT_NAME_RE = re.compile(r"^\s*name:\s*(\S+)")
_INCLUDE_RE = re.compile(r"!include\s+['\"]?([^'\"\s]+)")


def _scan_acceptances(
    text: str,
    result: dict[str, set[str]],
    *,
    name_anchor: bool,
    file_path: str | Path,
) -> None:
    """Scan one file's text for accept directives, attaching each to the
    rule anchor (``ref:``/``description:``, or ``name:`` when *name_anchor*)
    that follows it. Directives before any anchor are file-wide (``"*"``).
    """
    pending: set[str] = set()
    seen_first_anchor = False

    for line in text.splitlines():
        m_dir = _AUDIT_ACCEPT_RE.search(line)
        if m_dir:
            names = {n.strip() for n in m_dir.group(1).split(",")}
            unknown = names - ALL_CHECKS
            for u in sorted(unknown):
                log.warning("Unknown audit check %r in acceptance directive (%s)", u, file_path)
            pending.update(names - unknown)
            continue  # a directive line is never itself an anchor

        anchor: str | None = None
        m_ref = _ACCEPT_REF_RE.match(line)
        if m_ref:
            anchor = m_ref.group(1)
        elif name_anchor and (m_name := _ACCEPT_NAME_RE.match(line)):
            anchor = f"list:{m_name.group(1)}"
        else:
            m_desc = _ACCEPT_DESC_RE.match(line)
            if m_desc:
                anchor = m_desc.group(1) or m_desc.group(2) or m_desc.group(3)

        if anchor is not None:
            seen_first_anchor = True
            if pending:
                result.setdefault(anchor, set()).update(pending)
                pending.clear()
        elif line.strip() and not line.strip().startswith("#"):
            # Non-comment, non-anchor content line. Pending directives before
            # any anchor are file-level; after an anchor they're discarded to
            # avoid attaching to the wrong rule.
            if pending and not seen_first_anchor:
                result.setdefault("*", set()).update(pending)
                pending.clear()
            elif pending and seen_first_anchor:
                pending.clear()

    if pending and not seen_first_anchor:
        result.setdefault("*", set()).update(pending)


def parse_audit_acceptances(file_path: str | Path) -> dict[str, set[str]]:
    """Parse ``# octorules:accept=<check>`` directives, shellcheck-style.

    A directive attaches to the rule anchor that follows it — a ``ref:`` or
    ``description:`` line — and scopes the acceptance to that rule's findings.
    Directives placed before any anchor (e.g. at the top of the file) are
    file-wide and keyed under ``"*"``. Returns a dict mapping anchor (or
    ``"*"``) to the set of accepted check names.

    ``!include``d files are followed so a directive can be scoped to a list
    by placing it above the list's ``name:`` in the list's own file; there a
    ``name: foo`` line anchors as ``list:foo`` to match the audit's
    ``list:<name>`` finding refs. Unknown check names are logged and dropped.
    """
    result: dict[str, set[str]] = {}
    try:
        text = Path(file_path).read_text()
    except OSError:
        return result

    _scan_acceptances(text, result, name_anchor=False, file_path=file_path)

    base = Path(file_path).parent
    for inc in _INCLUDE_RE.findall(text):
        inc_path = (base / inc).resolve()
        if not inc_path.is_file():
            continue
        try:
            inc_text = inc_path.read_text()
        except OSError:
            continue
        _scan_acceptances(inc_text, result, name_anchor=True, file_path=inc_path)

    return result


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
    suppressible: bool = True
    """When False, no ``# octorules:accept=`` directive may silence this
    finding (e.g. overlapping your own active provider's edge ranges)."""


# ---------------------------------------------------------------------------
# CDN range fetching
# ---------------------------------------------------------------------------
def _fetch_url(url: str, timeout: int, parse: Callable[[bytes], Any]) -> Any:
    """Fetch *url* and run *parse* on the body. Returns None on failure."""
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                log.warning("HTTP %d from %s", resp.status, url)
                return None
            return parse(resp.read())
    except (_json.JSONDecodeError, OSError, TimeoutError) as e:
        log.warning("Failed to fetch %s: %s", url, e)
        return None


def _fetch_json(url: str, timeout: int = 15) -> Any:
    """Fetch JSON from a URL. Returns parsed data or None on failure."""
    return _fetch_url(url, timeout, _json.loads)


def _fetch_text(url: str, timeout: int = 15) -> str | None:
    """Fetch plain text from a URL. Returns decoded body or None on failure."""
    return _fetch_url(url, timeout, lambda body: body.decode("utf-8", errors="replace"))


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
    ("google_front_end.json", "Google Front End"),
]

# Maps a provider namespace (a key in ``config.providers``) to its CDN display
# name in ``_CDN_FILES``. An overlap with the edge ranges of a provider you are
# ACTIVELY fronting on is always a mistake — those addresses only ever carry
# your own edge traffic, never an attacker (who appears as their real IP at the
# edge) — so :func:`check_cdn_ranges` raises it to a non-suppressible ERROR
# instead of an accept-able warning.
#
# Every provider whose bundled ``_CDN_FILES`` data is a *shared edge* range set
# belongs here — those ranges front all of the provider's customers and are
# never a legitimate block target. Note ``google`` maps to "Google Front End"
# (the ``goog.json - cloud.json`` edge), NOT "Google Cloud": the latter is the
# rentable GCP compute space, where blocking a specific attacker host is valid,
# so it stays an accept-able ``cdn-ranges`` warning.
_OWN_EDGE_CDN_NAMES: dict[str, str] = {
    "cloudflare": "Cloudflare",
    "aws": "AWS CloudFront",
    "azure": "Azure Front Door",
    "bunny": "Bunny",
    "google": "Google Front End",
}


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
        return _fetch_json(_GOOGLE_CLOUD_URL, timeout=to)

    def _google_front_end_fetch(to: int) -> Any:
        # GFE needs both lists; return the pre-computed difference (identity parser).
        goog = _fetch_json(_GOOGLE_GOOG_URL, timeout=to)
        cloud = _fetch_json(_GOOGLE_CLOUD_URL, timeout=to)
        if goog is None or cloud is None:
            return None
        return google_front_end_cidrs(goog, cloud)

    # (label, fetcher(timeout) -> data, parser(data) -> list[str])
    sources = [
        ("Cloudflare", _cf_fetch, _parse_cloudflare_ips),
        ("AWS CloudFront", _aws_fetch, _parse_aws_cloudfront_ips),
        ("Google Cloud", _google_fetch, _parse_google_cloud_ips),
        ("Bunny", _fetch_bunny_text, _parse_bunny_ips),
        ("Azure Front Door", _fetch_azure_service_tags, _parse_azure_front_door_ips),
        ("Google Front End", _google_front_end_fetch, lambda cidrs: cidrs),
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
            label = futures[future][0]
            try:
                pair = future.result()
            except Exception as e:
                log.warning("CDN fetch failed for %s: %s", label, e)
                continue
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


_BLOCKING_ACTIONS = frozenset({"block", "managed_challenge", "js_challenge", "challenge", "deny"})


def _is_blocking_action(action: str | None) -> bool:
    """Return True if *action* is a blocking action.

    Handles Google's ``deny(NNN)`` format (treated as ``deny``) alongside
    the canonical Cloudflare / AWS / Azure action vocabulary.
    """
    a = (action or "").lower()
    if a.startswith("deny"):
        return True
    return a in _BLOCKING_ACTIONS


def check_ip_shadow(rule_ips: list[RuleIPInfo], phase_order: list[str]) -> list[AuditFinding]:
    """Detect rules shadowed by broader rules in earlier phases.

    A rule is "shadowed" when *all* its IPs are contained within IPs of
    a single rule in an earlier phase with a blocking action
    (block/deny/challenge).

    Per zone, builds a prefix-keyed index of all blocking rules' CIDRs
    keyed by ``(prefix_len, network_address, version)``. For each
    candidate, supernet lookup is at most 33 dict lookups for IPv4 (129
    for IPv6) regardless of the zone's rule count, replacing the
    earlier O(N²·M²) pair-by-pair comparison.
    """
    findings: list[AuditFinding] = []
    phase_rank = {p: i for i, p in enumerate(phase_order)}

    by_zone: dict[str, list[RuleIPInfo]] = {}
    for info in rule_ips:
        by_zone.setdefault(info.zone_name, []).append(info)

    for zone_name, infos in by_zone.items():
        # Parse every rule's CIDRs once. Position-indexed so we can refer
        # to a rule by its position in `infos` (stable + cheap to hash).
        parsed: list[list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
        for info in infos:
            nets = [n for n in (_to_network(c) for c in info.ip_ranges) if n is not None]
            parsed.append(nets)

        # Index blocking rules' CIDRs by (prefix_len, network_int, version).
        # Each entry is (rule_position, phase_rank). Reverse the values list
        # at the end so identically-keyed entries iterate in insertion order
        # (the iteration walks supernets from /0 upward, and within a single
        # supernet bucket we want the earliest-inserted rule first).
        index: dict[tuple[int, int, int], list[tuple[int, int]]] = {}
        for pos, info in enumerate(infos):
            rank = phase_rank.get(info.phase_name)
            if rank is None or not _is_blocking_action(info.action):
                continue
            for net in parsed[pos]:
                key = (net.prefixlen, int(net.network_address), net.version)
                index.setdefault(key, []).append((pos, rank))

        # Per-rule shadow lookup.
        for pos, info in enumerate(infos):
            info_rank = phase_rank.get(info.phase_name)
            if info_rank is None:
                continue
            info_nets = parsed[pos]
            if not info_nets:
                continue

            # For each CIDR of `info`, collect candidate rules that contain it
            # AND are in an earlier phase. The intersection across all CIDRs
            # is the set of rules that shadow `info`.
            per_net_covers: list[set[int]] = []
            for info_net in info_nets:
                covers: set[int] = set()
                ip_int = int(info_net.network_address)
                version = info_net.version
                bitlen = 32 if version == 4 else 128
                for plen in range(info_net.prefixlen + 1):
                    if plen == 0:
                        net_int = 0
                    else:
                        shift = bitlen - plen
                        net_int = (ip_int >> shift) << shift
                    for cand_pos, cand_rank in index.get((plen, net_int, version), ()):
                        if cand_pos != pos and cand_rank < info_rank:
                            covers.add(cand_pos)
                per_net_covers.append(covers)

            shadowers = set.intersection(*per_net_covers) if per_net_covers else set()
            if not shadowers:
                continue

            # Pick the first-encountered shadowing rule (lowest position) for
            # deterministic output that matches the original iteration order.
            shadower = infos[min(shadowers)]
            findings.append(
                AuditFinding(
                    check="ip-shadow",
                    severity=FindingSeverity.WARNING,
                    message=(
                        f"Rule {info.ref} ({display_phase_name(info.phase_name)})"
                        f" is shadowed by {shadower.ref}"
                        f" ({display_phase_name(shadower.phase_name)},"
                        f" action={shadower.action}):"
                        f" all IPs are covered by the earlier rule"
                    ),
                    zone_name=zone_name,
                    phase_name=info.phase_name,
                    ref=info.ref,
                )
            )

    return findings


def check_cdn_ranges(
    rule_ips: list[RuleIPInfo],
    cdn_ranges: dict[str, list[str]],
    active_cdn_providers: set[str] | None = None,
) -> list[AuditFinding]:
    """Check if any rule IPs match known CDN provider IP ranges.

    Uses a sorted-interval approach: CDN ranges are sorted by start
    address, then each rule CIDR is checked via binary search against
    candidate CDN ranges.  Complexity is O((n + m) log m) instead of
    O(n * m).

    *active_cdn_providers* is the set of CDN display names this config
    actively fronts on (see ``_OWN_EDGE_CDN_NAMES``). An overlap with one
    of those is an "own-edge" mistake: it is emitted as a non-suppressible
    ERROR rather than an accept-able WARNING.
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
                if active_cdn_providers and cdn_provider in active_cdn_providers:
                    # Own-edge overlap: a range of a provider this config
                    # actively fronts on. Always wrong, and never silenceable.
                    findings.append(
                        AuditFinding(
                            check="cdn-ranges",
                            severity=FindingSeverity.ERROR,
                            message=(
                                f"{cidr} (in"
                                f" {info.ref}/{display_phase_name(info.phase_name)})"
                                f" is inside"
                                f" {cdn_provider}'s own edge range {cdn_net}, but"
                                f" {cdn_provider} is an active provider for this config."
                                " Blocklisting your own edge only ever matches your own"
                                " edge/Worker/WARP traffic, never an attacker — remove it."
                            ),
                            zone_name=info.zone_name,
                            phase_name=info.phase_name,
                            ref=info.ref,
                            suppressible=False,
                        )
                    )
                else:
                    findings.append(
                        AuditFinding(
                            check="cdn-ranges",
                            severity=FindingSeverity.WARNING,
                            message=(
                                f"{cidr} (in {info.ref}/{display_phase_name(info.phase_name)})"
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
            "phase_name": display_phase_name(f.phase_name),
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
    """Build a map from list name to IP CIDRs from the ``lists`` sections.

    Multi-provider files carry lists per namespace — audit aggregates
    every provider's lists (cross-layer IP checks want all of them),
    qualifying names with the namespace to keep them distinct.
    """
    from octorules.phases import iter_scoped_sections

    ip_map: dict[str, list[str]] = {}
    for ns, lists_section in iter_scoped_sections(rules_data, "lists"):
        if not isinstance(lists_section, list):
            continue
        _collect_list_ips(lists_section, ip_map, prefix=f"{ns}:" if ns else "")
    return ip_map


def _collect_list_ips(lists_section: list, ip_map: dict[str, list[str]], *, prefix: str) -> None:
    """Collect IP-kind list CIDRs from one ``lists`` section into *ip_map*."""
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
            ip_map[prefix + name] = cidrs


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
    # Multi-provider files qualify list names with their namespace
    # ("cloudflare:blocked-ips") while rules reference the bare name —
    # index by bare name so refs resolve either way.  A bare name shared
    # by several namespaces resolves to all of them (conservative for
    # the overlap checks; audit can't attribute a rule to a namespace).
    by_bare: dict[str, list[str]] = {}
    for full_name in ip_map:
        bare = full_name.partition(":")[2] or full_name
        by_bare.setdefault(bare, []).append(full_name)
    referenced_lists: set[str] = set()
    for info in all_infos:
        if info.list_refs:
            for list_name in info.list_refs:
                for key in by_bare.get(list_name, ()):
                    info.ip_ranges.extend(ip_map[key])
                    referenced_lists.add(key)

    # Include unreferenced lists as standalone pseudo-rules
    all_infos.extend(_extract_unreferenced_list_ips(ip_map, referenced_lists))

    # Stamp zone_name onto results (extractors don't know the zone)
    for info in all_infos:
        info.zone_name = zone_name

    # Drop entries with no resolved IPs (e.g. unresolvable managed list refs)
    return [info for info in all_infos if info.ip_ranges]


def apply_audit_acceptances(
    findings: list[AuditFinding],
    accepted_by_zone: dict[str, dict[str, set[str]]],
) -> tuple[list[AuditFinding], int]:
    """Drop findings whose zone accepts their check — file-wide (``"*"``) or for
    the finding's specific rule anchor (``ref``).

    Non-suppressible findings (``suppressible=False``, e.g. own-edge overlaps)
    are NEVER dropped, even when their check is accepted. Returns
    ``(kept_findings, suppressed_count)``.
    """
    from octorules.phases import PROVIDER_NAMESPACES

    if not accepted_by_zone:
        return findings, 0
    kept: list[AuditFinding] = []
    suppressed = 0
    for f in findings:
        acc = accepted_by_zone.get(f.zone_name, {}) if f.zone_name else {}
        refs = {f.ref}
        # Multi-provider files qualify list pseudo-rule refs with their
        # namespace ("list:cloudflare:blocked-ips") while acceptance
        # directives anchor on the bare spelling ("list:blocked-ips") —
        # accept either, mirroring the by_bare resolution for list_refs.
        if f.ref.startswith("list:") and f.ref.count(":") >= 2:
            _, ns, bare = f.ref.split(":", 2)
            if ns in PROVIDER_NAMESPACES:
                refs.add(f"list:{bare}")
        accepted_here = f.check in acc.get("*", set()) or any(
            f.check in acc.get(r, set()) for r in refs
        )
        if f.suppressible and accepted_here:
            suppressed += 1
        else:
            kept.append(f)
    return kept, suppressed


def run_audit(
    all_rule_ips: list[RuleIPInfo],
    phase_order: list[str],
    *,
    checks: frozenset[str] | None = None,
    cdn_timeout: int = 15,
    cdn_stale_days: int = 60,
    active_cdn_providers: set[str] | None = None,
) -> list[AuditFinding]:
    """Run selected audit checks on collected IP data.

    Args:
        all_rule_ips: IP info from all zones.
        phase_order: Ordered list of phase friendly names.
        checks: Which checks to run (default: all).
        cdn_timeout: Timeout for CDN range fetching.
        cdn_stale_days: Warn if baked-in CDN data is older than this many days.
        active_cdn_providers: CDN display names this config fronts on; an
            overlap with one is a non-suppressible own-edge ERROR.
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
            findings.extend(check_cdn_ranges(all_rule_ips, cdn_result.ranges, active_cdn_providers))
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
