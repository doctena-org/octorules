#!/usr/bin/env python3
"""Fetch CDN IP ranges and write per-provider JSON files.

Maintainer tool — not installed with the package. Run manually or from CI
to refresh the baked-in CDN IP ranges shipped with octorules.

Source-of-truth split: URL constants and CIDR-extraction parsers live in
``octorules._cdn_sources``. The runtime audit (``octorules.audit``) and
this maintainer script both consume from that module — neither owns the
parsing layer. This script adds only the maintainer-only concerns:
raise-on-error HTTP wrappers (so failures are loud) and per-provider
version-metadata extraction (so file diffs are stable across runs).

Usage:
    python scripts/sync_cdn_ranges.py              # Fetch and write
    python scripts/sync_cdn_ranges.py --check      # Exit 1 if data is stale
    python scripts/sync_cdn_ranges.py --check 30   # Custom staleness in days
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
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

_DATA_DIR = Path(__file__).resolve().parent.parent / "octorules" / "data" / "cdn_ranges"

# (filename, provider label, source descriptor, format)
# - "json"        — descriptor is a single URL, parser receives dict
# - "text"        — descriptor is a tuple of URLs whose bodies are concatenated,
#                   parser receives str
# - "azure-scrape"— descriptor is the details-page URL; the script scrapes it
#                   for the current JSON URL and fetches that. Parser receives dict.
_SOURCES: list[tuple[str, str, object, str]] = [
    ("cloudflare.json", "Cloudflare", "https://api.cloudflare.com/client/v4/ips", "json"),
    (
        "aws_cloudfront.json",
        "AWS CloudFront",
        "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "json",
    ),
    ("google_cloud.json", "Google Cloud", "https://www.gstatic.com/ipranges/cloud.json", "json"),
    ("bunny.json", "Bunny", _BUNNY_URLS, "text"),
    ("azure_front_door.json", "Azure Front Door", _AZURE_DETAILS_URL, "azure-scrape"),
]


# Maintainer-script HTTP: raise on any failure so the run aborts loudly.
# (Runtime audit uses the audit.py variants which log+return None for graceful
# degradation. Different contracts; keep separate.)
def _fetch_json(url: str) -> dict:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _fetch_text(url: str) -> str:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _fetch_azure_service_tags(details_url: str) -> dict:
    """Scrape the Azure download page for the current ServiceTags_Public URL, then fetch it."""
    html = _fetch_text(details_url)
    m = _AZURE_JSON_URL_RE.search(html)
    if not m:
        raise RuntimeError(f"Azure details page layout changed: no JSON URL found in {details_url}")
    return _fetch_json(m.group(0))


# Per-provider version-metadata extractors. These exist only in the sync
# script: the runtime audit doesn't care about provenance because the API
# response itself is authoritative. Baked-in JSON files need it for diff
# stability and staleness reporting.
def _cf_version(data: dict) -> dict:
    etag = data.get("result", {}).get("etag")
    return {"etag": etag} if etag else {}


def _aws_version(data: dict) -> dict:
    return {key: str(data[key]) for key in ("createDate", "syncToken") if data.get(key)}


def _google_version(data: dict) -> dict:
    return {key: str(data[key]) for key in ("creationTime", "syncToken") if data.get(key)}


def _bunny_version(_data: str) -> dict:
    return {}


def _azure_version(data: dict) -> dict:
    version: dict = {}
    if data.get("changeNumber") is not None:
        version["changeNumber"] = data["changeNumber"]
    if data.get("cloud"):
        version["cloud"] = data["cloud"]
    return version


# (cidr_parser, version_extractor)
_HANDLERS: dict[str, tuple] = {
    "Cloudflare": (_parse_cloudflare_ips, _cf_version),
    "AWS CloudFront": (_parse_aws_cloudfront_ips, _aws_version),
    "Google Cloud": (_parse_google_cloud_ips, _google_version),
    "Bunny": (_parse_bunny_ips, _bunny_version),
    "Azure Front Door": (_parse_azure_front_door_ips, _azure_version),
}


def sync() -> bool:
    """Fetch all CDN ranges and write per-provider JSON files. Returns True on success."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    ok = True

    for filename, provider, src, fmt in _SOURCES:
        print(f"Fetching {provider} from {src}...")
        try:
            if fmt == "text":
                urls = (src,) if isinstance(src, str) else tuple(src)
                data = "\n".join(_fetch_text(u) for u in urls)
            elif fmt == "azure-scrape":
                data = _fetch_azure_service_tags(src)  # type: ignore[arg-type]
            else:
                data = _fetch_json(src)  # type: ignore[arg-type]
        except Exception as e:
            print(f"  ERROR: {e}", file=sys.stderr)
            ok = False
            continue

        parser, version_fn = _HANDLERS[provider]
        cidrs = sorted(parser(data))
        version = version_fn(data)
        print(f"  {len(cidrs)} CIDRs, version={version}")

        out = {
            "_generated_at": now,
            "_generator": "scripts/sync_cdn_ranges.py",
            "provider": provider,
            "version": version,
            "cidrs": cidrs,
        }

        path = _DATA_DIR / filename
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
            f.write("\n")
        print(f"  Wrote {path}")

    return ok


def check(max_age_days: int = 60) -> bool:
    """Check if baked-in data is stale. Returns True if fresh."""
    now = datetime.now(timezone.utc)
    ok = True

    for filename, provider, _src, _fmt in _SOURCES:
        path = _DATA_DIR / filename
        if not path.exists():
            print(f"MISSING: {path}", file=sys.stderr)
            ok = False
            continue

        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"INVALID: {path}: {e}", file=sys.stderr)
            ok = False
            continue

        generated_at_str = data.get("_generated_at", "")
        if not generated_at_str:
            print(f"INVALID: {path} has no _generated_at", file=sys.stderr)
            ok = False
            continue

        generated_at = datetime.fromisoformat(generated_at_str.replace("Z", "+00:00"))
        age = now - generated_at
        if age > timedelta(days=max_age_days):
            print(
                f"STALE: {provider} data is {age.days} days old (threshold: {max_age_days} days)",
                file=sys.stderr,
            )
            ok = False
        else:
            cidrs = data.get("cidrs", [])
            print(f"  {provider}: {len(cidrs)} CIDRs, {age.days} days old — OK")

    return ok


def main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1] == "--check":
        max_age = int(sys.argv[2]) if len(sys.argv) >= 3 else 60
        if not check(max_age):
            sys.exit(1)
    else:
        if not sync():
            sys.exit(1)


if __name__ == "__main__":
    main()
