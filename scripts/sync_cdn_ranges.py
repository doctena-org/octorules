#!/usr/bin/env python3
"""Fetch CDN IP ranges and write per-provider JSON files.

Maintainer tool — not installed with the package. Run manually or from CI
to refresh the baked-in CDN IP ranges shipped with octorules.

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

_DATA_DIR = Path(__file__).resolve().parent.parent / "octorules" / "data" / "cdn_ranges"

_SOURCES: list[tuple[str, str, str]] = [
    # (filename, provider label, url)
    ("cloudflare.json", "Cloudflare", "https://api.cloudflare.com/client/v4/ips"),
    ("aws_cloudfront.json", "AWS CloudFront", "https://ip-ranges.amazonaws.com/ip-ranges.json"),
    ("google_cloud.json", "Google Cloud", "https://www.gstatic.com/ipranges/cloud.json"),
]


def _fetch_json(url: str) -> dict:
    req = Request(url, headers={"User-Agent": "octorules-sync/1.0"})
    with urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _parse_cloudflare(data: dict) -> tuple[list[str], dict]:
    result = data.get("result", {})
    cidrs: list[str] = []
    for key in ("ipv4_cidrs", "ipv6_cidrs"):
        val = result.get(key)
        if isinstance(val, list):
            cidrs.extend(str(c) for c in val)
    version = {}
    etag = result.get("etag")
    if etag:
        version["etag"] = etag
    return sorted(cidrs), version


def _parse_aws_cloudfront(data: dict) -> tuple[list[str], dict]:
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
    version = {}
    for key in ("createDate", "syncToken"):
        val = data.get(key)
        if val:
            version[key] = str(val)
    return sorted(cidrs), version


def _parse_google_cloud(data: dict) -> tuple[list[str], dict]:
    cidrs: list[str] = []
    for prefix in data.get("prefixes", []):
        if isinstance(prefix, dict):
            for key in ("ipv4Prefix", "ipv6Prefix"):
                ip = prefix.get(key)
                if ip:
                    cidrs.append(str(ip))
    version = {}
    for key in ("creationTime", "syncToken"):
        val = data.get(key)
        if val:
            version[key] = str(val)
    return sorted(cidrs), version


_PARSERS = {
    "Cloudflare": _parse_cloudflare,
    "AWS CloudFront": _parse_aws_cloudfront,
    "Google Cloud": _parse_google_cloud,
}


def sync() -> bool:
    """Fetch all CDN ranges and write per-provider JSON files. Returns True on success."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    ok = True

    for filename, provider, url in _SOURCES:
        print(f"Fetching {provider} from {url}...")
        try:
            data = _fetch_json(url)
        except Exception as e:
            print(f"  ERROR: {e}", file=sys.stderr)
            ok = False
            continue

        cidrs, version = _PARSERS[provider](data)
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

    for filename, provider, _url in _SOURCES:
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
