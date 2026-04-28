"""CDN provider source descriptors and CIDR-extraction parsers.

Single source of truth for the per-provider knowledge needed to fetch and
parse public CDN IP ranges. Two consumers:

- ``octorules.audit`` uses these parsers at runtime (with graceful
  ``None``-on-failure fetchers) for the ``cdn-ranges`` audit check.
- ``scripts/sync_cdn_ranges.py`` (maintainer tool, not installed) uses
  the same parsers with raise-on-failure fetchers to bake the JSON
  files shipped in ``octorules/data/cdn_ranges/``.

Each parser is a pure function: ``data -> list[str]``. Failure modes are
``log.warning`` + return ``[]`` so callers can decide whether to skip
the provider, fall back to baked-in data, or abort.
"""

import ipaddress
import logging
import re

log = logging.getLogger(__name__)

# Bunny publishes IPv4 and IPv6 edge-server lists on separate plain-text endpoints.
_BUNNY_URLS: tuple[str, ...] = (
    "https://api.bunny.net/system/edgeserverlist/plain",
    "https://api.bunny.net/system/edgeserverlist/IPv6/plain",
)

# Azure publishes its service tag JSON on a rotating URL reachable only via the
# Microsoft Download Center details page. We scrape the page for the current
# ServiceTags_Public_YYYYMMDD.json link, then fetch the JSON.
_AZURE_DETAILS_URL = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
_AZURE_JSON_URL_RE = re.compile(
    r"https://download\.microsoft\.com/download/[^\"'\s]+/ServiceTags_Public_\d+\.json"
)
# Front Door is the only Azure-side service with globally-published ingress/egress
# IPs relevant to a WAF rule. Application Gateway is customer-deployed inside a
# VNet and has no global range to bake in.
_AZURE_FRONT_DOOR_TAGS: frozenset[str] = frozenset(
    {"AzureFrontDoor.Frontend", "AzureFrontDoor.Backend"}
)


def _parse_cloudflare_ips(data: dict) -> list[str]:
    """Extract CIDRs from Cloudflare /client/v4/ips response."""
    if not isinstance(data, dict):
        log.warning("Cloudflare IP response: expected dict, got %s", type(data).__name__)
        return []
    result = data.get("result", {})
    if not isinstance(result, dict):
        log.warning("Cloudflare IP response: 'result' is %s, expected dict", type(result).__name__)
        return []
    cidrs: list[str] = []
    for key in ("ipv4_cidrs", "ipv6_cidrs"):
        val = result.get(key)
        if isinstance(val, list):
            cidrs.extend(str(c) for c in val)
    if not cidrs:
        log.warning("Cloudflare IP response: no CIDRs found in 'result' (keys: %s)", list(result))
    return cidrs


def _parse_aws_cloudfront_ips(data: dict) -> list[str]:
    """Extract CloudFront CIDRs from AWS ip-ranges.json."""
    if not isinstance(data, dict):
        log.warning("AWS IP response: expected dict, got %s", type(data).__name__)
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
    if not cidrs:
        log.warning("AWS IP response: no CloudFront CIDRs found")
    return cidrs


def _parse_google_cloud_ips(data: dict) -> list[str]:
    """Extract CIDRs from Google Cloud ip-ranges JSON."""
    if not isinstance(data, dict):
        log.warning("Google Cloud IP response: expected dict, got %s", type(data).__name__)
        return []
    cidrs: list[str] = []
    for prefix in data.get("prefixes", []):
        if isinstance(prefix, dict):
            for key in ("ipv4Prefix", "ipv6Prefix"):
                ip = prefix.get(key)
                if ip:
                    cidrs.append(str(ip))
    if not cidrs:
        log.warning("Google Cloud IP response: no CIDRs found in 'prefixes'")
    return cidrs


def _parse_bunny_ips(data: str) -> list[str]:
    """Extract CIDRs from Bunny edge server plain-text lists.

    Bunny publishes its edge IPs as newline-separated bare addresses
    (one per line, no CIDR suffix). IPv4 and IPv6 are served from
    separate endpoints and concatenated upstream before parsing.
    Each address is wrapped as ``/32`` (IPv4) or ``/128`` (IPv6).
    """
    if not isinstance(data, str):
        log.warning("Bunny IP response: expected str, got %s", type(data).__name__)
        return []
    cidrs: list[str] = []
    for line in data.splitlines():
        ip = line.strip()
        if not ip:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        cidrs.append(f"{ip}/32" if isinstance(addr, ipaddress.IPv4Address) else f"{ip}/128")
    if not cidrs:
        log.warning("Bunny IP response: no IPs parsed")
    return cidrs


def _parse_azure_front_door_ips(data: dict) -> list[str]:
    """Extract Azure Front Door CIDRs from the ServiceTags_Public JSON."""
    if not isinstance(data, dict):
        log.warning("Azure IP response: expected dict, got %s", type(data).__name__)
        return []
    cidrs: list[str] = []
    for entry in data.get("values", []):
        if not isinstance(entry, dict) or entry.get("name") not in _AZURE_FRONT_DOOR_TAGS:
            continue
        props = entry.get("properties")
        if not isinstance(props, dict):
            continue
        for p in props.get("addressPrefixes", []):
            if isinstance(p, str):
                cidrs.append(p)
    if not cidrs:
        log.warning("Azure IP response: no Front Door prefixes found")
    return cidrs
