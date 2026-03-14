"""Cloudflare SDK wrapper for phase rulesets.

Public API (re-exported for backward compatibility):
    CloudflareProvider, BaseProvider, Scope, PhaseRulesResult
"""

from __future__ import annotations

import json as _json
import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

import cloudflare
import httpx
from cloudflare import DefaultHttpxClient

from octorules.config import ConfigError
from octorules.phases import (
    ACCOUNT_CF_PHASES,
    ALL_CF_PHASES,
    LIST_ITEM_API_FIELDS,
    PAGE_SHIELD_POLICY_API_FIELDS,
    ZONE_CF_PHASES,
)
from octorules.provider.base import BaseProvider, PhaseRulesResult, Scope
from octorules.provider.exceptions import (
    APIConnectionError,
    APIError,
    AuthenticationError,
    BadRequestError,
    NotFoundError,
    PermissionDeniedError,
)


def _zone_phase_set() -> set[str]:
    return set(ZONE_CF_PHASES)


def _account_phase_set() -> set[str]:
    return set(ACCOUNT_CF_PHASES)


log = logging.getLogger("octorules")

_KNOWN_PLANS = {"free", "pro", "business", "enterprise"}


def _normalize_plan_name(raw: str) -> str:
    """Normalize a Cloudflare API plan name to an octorules tier.

    The API returns names like "Free Website", "Pro Website",
    "Business Website", "Enterprise Website" or just "Free", etc.
    """
    lower = raw.lower()
    for plan in _KNOWN_PLANS:
        if plan in lower:
            return plan
    return lower


def _fmt_scope(scope: Scope) -> str:
    """Format scope for log messages."""
    if scope.label:
        kw = scope.api_kwargs
        key = next(iter(kw))
        return f"{scope.label} ({key}={kw[key]})"
    kw = scope.api_kwargs
    key = next(iter(kw))
    return f"{key}={kw[key]}"


def _fetch_parallel(
    items: list,
    *,
    submit_fn: Callable,
    key_fn: Callable,
    result_fn: Callable,
    label: str,
    scope_label: str,
    max_workers: int,
) -> tuple[dict, list]:
    """Run *submit_fn* for each item in parallel, collecting results.

    Args:
        items: Items to iterate over.
        submit_fn: ``submit_fn(executor, item)`` → ``Future``.
        key_fn: ``key_fn(item)`` → hashable key for log messages and
            the ``failed`` list.
        result_fn: ``result_fn(item, future_result)`` → ``(key, value)`` pair
            to insert into the result dict, or *None* to skip.  Receives the
            original *item*, not the key.
        label: Human label for log messages (e.g. "phase", "custom ruleset").
        scope_label: Pre-formatted scope string for log messages.
        max_workers: Max concurrent workers.

    Returns:
        ``(results_dict, failed_keys)`` — results for successful fetches and
        keys of items that failed with transient errors.  Auth/permission
        errors propagate immediately.
    """
    workers = min(max_workers, len(items))
    results: dict = {}
    failed: list = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_item: dict = {}
        for item in items:
            f = submit_fn(executor, item)
            future_to_item[f] = item
        for future in as_completed(future_to_item):
            item = future_to_item[future]
            key = key_fn(item)
            try:
                value = future.result()
            except (AuthenticationError, PermissionDeniedError):
                for f in future_to_item:
                    f.cancel()
                raise
            except (APIError, APIConnectionError) as e:
                log.warning("Failed to fetch %s %s for %s: %s", label, key, scope_label, e)
                failed.append(key)
                continue
            pair = result_fn(item, value)
            if pair is not None:
                results[pair[0]] = pair[1]
    return results, failed


class CloudflareProvider:
    """Wraps the Cloudflare Python SDK for ruleset phase operations."""

    def __init__(
        self,
        token: str,
        *,
        max_retries: int = 2,
        timeout: float | None = None,
        max_workers: int = 1,
        client: cloudflare.Cloudflare | None = None,
    ):
        if client is not None:
            self._client = client
        else:
            kwargs: dict = {"api_token": token, "max_retries": max_retries}
            if timeout is not None:
                kwargs["timeout"] = timeout
            # Scale connection pool to match concurrency
            if max_workers > 1:
                pool_size = max_workers * len(ALL_CF_PHASES)
                kwargs["http_client"] = DefaultHttpxClient(
                    limits=httpx.Limits(
                        max_connections=max(100, pool_size),
                        max_keepalive_connections=max(20, max_workers * 4),
                    ),
                )
            self._client = cloudflare.Cloudflare(**kwargs)
        self._max_workers = max_workers
        self._lock = threading.Lock()
        self._account_id: str | None = None
        self._account_name: str | None = None
        self._zone_plans: dict[str, str] = {}

    @property
    def max_workers(self) -> int:
        """Maximum concurrent workers for parallel operations."""
        return self._max_workers

    @property
    def account_id(self) -> str | None:
        return self._account_id

    @property
    def account_name(self) -> str | None:
        return self._account_name

    @property
    def zone_plans(self) -> dict[str, str]:
        """Zone name → normalized plan tier, populated during resolve_zone_id."""
        return self._zone_plans

    def resolve_zone_id(self, zone_name: str) -> str:
        """Resolve a zone name to its Cloudflare zone ID.

        Raises ConfigError if zero or more than one zone matches.
        Also stashes account info from the first successful resolution.

        Called concurrently from ThreadPoolExecutor. Shared state writes
        are protected by ``_lock``.
        """
        result = self._client.zones.list(name=zone_name)
        matches = [z for z in result if z.name == zone_name]
        if len(matches) == 0:
            raise ConfigError(f"No zone found for {zone_name!r}")
        if len(matches) > 1:
            raise ConfigError(f"Multiple zones found for {zone_name!r}")
        zone = matches[0]
        with self._lock:
            if getattr(zone, "account", None) and not self._account_id:
                self._account_id = zone.account.id
                self._account_name = zone.account.name
            if getattr(zone, "plan", None) and getattr(zone.plan, "name", None):
                self._zone_plans[zone_name] = _normalize_plan_name(zone.plan.name)
        return zone.id

    def get_phase_rules(self, scope: Scope, cf_phase: str) -> list[dict]:
        """Fetch rules for a single phase. Returns empty list if no ruleset exists."""
        log.debug("GET rulesets/phases/%s %s", cf_phase, _fmt_scope(scope))
        try:
            ruleset = self._client.rulesets.phases.get(
                cf_phase,
                **scope.api_kwargs,
            )
            rules = ruleset.rules or []
            return [_rule_to_dict(r) for r in rules]
        except NotFoundError:
            return []
        except BadRequestError:
            # Cloudflare returns 400 for phases the zone/account doesn't
            # support (e.g. SBFM without the entitlement).  Treat the same
            # as "no ruleset" so callers aren't surprised.
            log.debug(
                "Skipping phase %s for %s (not supported on this plan)",
                cf_phase,
                _fmt_scope(scope),
            )
            return []
        except PermissionDeniedError:
            # Token lacks permission for this specific phase (e.g. ddos_l7,
            # http_log_custom_fields).  Skip rather than aborting the entire
            # operation — the caller can still process other phases.
            log.debug(
                "Skipping phase %s for %s (token lacks permission)",
                cf_phase,
                _fmt_scope(scope),
            )
            return []

    def put_phase_rules(self, scope: Scope, cf_phase: str, rules: list[dict]) -> int:
        """Atomically replace all rules in a phase.

        Returns the number of rules in the response (for verification).
        """
        sl = _fmt_scope(scope)
        log.debug("PUT rulesets/phases/%s %s rules=%d", cf_phase, sl, len(rules))
        result = self._client.rulesets.phases.update(
            cf_phase,
            **scope.api_kwargs,
            rules=rules,
        )
        response_rules = result.rules or []
        response_count = len(response_rules)
        if response_count != len(rules):
            log.warning(
                "PUT %s %s: sent %d rule(s) but response contains %d",
                cf_phase,
                sl,
                len(rules),
                response_count,
            )
        return response_count

    def get_all_phase_rules(
        self, scope: Scope, *, cf_phases: list[str] | None = None
    ) -> PhaseRulesResult:
        """Fetch rules for supported phases in parallel. Returns cf_phase → rules mapping.

        AuthenticationError and PermissionDeniedError propagate immediately
        (permanent errors). Transient errors (rate limit, server error,
        connection) are logged and the phase is recorded in ``result.failed_phases``.

        For account scopes, automatically restricts to account-compatible phases.

        Args:
            scope: The Scope (zone or account) to fetch rules for.
            cf_phases: Optional list of CF phase identifiers to fetch.
                       Defaults to all supported phases.
        """
        phases_to_fetch = cf_phases if cf_phases is not None else ALL_CF_PHASES
        if scope.is_account:
            account_set = _account_phase_set()
            phases_to_fetch = [p for p in phases_to_fetch if p in account_set]
        else:
            zone_set = _zone_phase_set()
            phases_to_fetch = [p for p in phases_to_fetch if p in zone_set]
        sl = _fmt_scope(scope)
        log.debug("Fetching %d phase(s) for %s", len(phases_to_fetch), sl)

        if not phases_to_fetch:
            return PhaseRulesResult({}, failed_phases=[])

        def _result_fn(phase, rules):
            return (phase, rules) if rules else None

        rules, failed = _fetch_parallel(
            phases_to_fetch,
            submit_fn=lambda ex, p: ex.submit(self.get_phase_rules, scope, p),
            key_fn=lambda p: p,
            result_fn=_result_fn,
            label="phase",
            scope_label=sl,
            max_workers=self._max_workers,
        )
        return PhaseRulesResult(rules, failed_phases=failed)

    def list_custom_rulesets(self, scope: Scope) -> list[dict]:
        """List custom rulesets (kind == 'custom') for a scope.

        Returns list of {id, name, phase, description} dicts.
        """
        sl = _fmt_scope(scope)
        log.debug("LIST rulesets (custom) %s", sl)
        result = self._client.rulesets.list(**scope.api_kwargs)
        custom = []
        for rs in result:
            rs_dict = _ruleset_to_dict(rs)
            if rs_dict.get("kind") != "custom":
                continue
            custom.append(
                {
                    "id": rs_dict["id"],
                    "name": rs_dict.get("name", ""),
                    "phase": rs_dict.get("phase", ""),
                    "description": rs_dict.get("description", ""),
                }
            )
        return custom

    def get_custom_ruleset(self, scope: Scope, ruleset_id: str) -> list[dict]:
        """Fetch rules inside a single custom ruleset. Returns list of rule dicts."""
        sl = _fmt_scope(scope)
        log.debug("GET rulesets/%s %s", ruleset_id, sl)
        ruleset = self._client.rulesets.get(ruleset_id, **scope.api_kwargs)
        rules = ruleset.rules or []
        return [_rule_to_dict(r) for r in rules]

    def put_custom_ruleset(self, scope: Scope, ruleset_id: str, rules: list[dict]) -> int:
        """Replace all rules in a custom ruleset. Returns rule count from response."""
        sl = _fmt_scope(scope)
        log.debug("PUT rulesets/%s %s rules=%d", ruleset_id, sl, len(rules))
        result = self._client.rulesets.update(ruleset_id, **scope.api_kwargs, rules=rules)
        response_rules = result.rules or []
        response_count = len(response_rules)
        if response_count != len(rules):
            log.warning(
                "PUT ruleset %s %s: sent %d rule(s) but response contains %d",
                ruleset_id,
                sl,
                len(rules),
                response_count,
            )
        return response_count

    def get_all_custom_rulesets(
        self, scope: Scope, *, ruleset_ids: list[str] | None = None
    ) -> dict[str, dict]:
        """Fetch all custom rulesets in parallel.

        Returns {ruleset_id: {"name": ..., "phase": ..., "rules": [...]}}.
        If ruleset_ids is None, discovers via list_custom_rulesets.
        """
        if ruleset_ids is None:
            rulesets_meta = self.list_custom_rulesets(scope)
        else:
            rulesets_meta = [{"id": rid, "name": "", "phase": ""} for rid in ruleset_ids]

        if not rulesets_meta:
            return {}

        sl = _fmt_scope(scope)
        log.debug("Fetching %d custom ruleset(s) for %s", len(rulesets_meta), sl)

        def _result_fn(rs, rules):
            return (
                rs["id"],
                {"name": rs.get("name", ""), "phase": rs.get("phase", ""), "rules": rules},
            )

        results, _ = _fetch_parallel(
            rulesets_meta,
            submit_fn=lambda ex, rs: ex.submit(self.get_custom_ruleset, scope, rs["id"]),
            key_fn=lambda rs: rs["id"],
            result_fn=_result_fn,
            label="custom ruleset",
            scope_label=sl,
            max_workers=self._max_workers,
        )
        return results

    # --- Lists API ---

    def list_lists(self, scope: Scope) -> list[dict]:
        """List all account-level lists.

        Returns list of {id, name, kind, description} dicts.
        """
        sl = _fmt_scope(scope)
        log.debug("LIST rules/lists %s", sl)
        result = self._client.rules.lists.list(**scope.api_kwargs)
        lists = []
        for item in result:
            d = _ruleset_to_dict(item)
            lists.append(
                {
                    "id": d.get("id", ""),
                    "name": d.get("name", ""),
                    "kind": d.get("kind", ""),
                    "description": d.get("description", ""),
                }
            )
        return lists

    def create_list(self, scope: Scope, name: str, kind: str, description: str = "") -> dict:
        """Create a new list. Returns created list metadata dict."""
        sl = _fmt_scope(scope)
        log.debug("CREATE rules/lists %s name=%s kind=%s", sl, name, kind)
        result = self._client.rules.lists.create(
            **scope.api_kwargs, kind=kind, name=name, description=description
        )
        return _ruleset_to_dict(result)

    def delete_list(self, scope: Scope, list_id: str) -> None:
        """Delete a list by ID."""
        sl = _fmt_scope(scope)
        log.debug("DELETE rules/lists/%s %s", list_id, sl)
        self._client.rules.lists.delete(list_id, **scope.api_kwargs)

    def update_list_description(self, scope: Scope, list_id: str, description: str) -> None:
        """Update list metadata (description)."""
        sl = _fmt_scope(scope)
        log.debug("UPDATE rules/lists/%s %s description=%r", list_id, sl, description)
        self._client.rules.lists.update(list_id, **scope.api_kwargs, description=description)

    def get_list_items(self, scope: Scope, list_id: str, *, _page_retries: int = 2) -> list[dict]:
        """Fetch all items in a list, handling cursor-based pagination.

        Strips LIST_ITEM_API_FIELDS from each item.
        Uses raw responses to extract pagination cursors, since the SDK
        returns a plain list without cursor metadata.

        Each page is retried up to *_page_retries* times on transient errors
        (``APIError``, ``APIConnectionError``).  ``AuthenticationError`` and
        ``PermissionDeniedError`` propagate immediately.
        """
        sl = _fmt_scope(scope)
        log.debug("GET rules/lists/%s/items %s", list_id, sl)
        all_items: list[dict] = []
        cursor: str | None = None
        while True:
            kwargs: dict = {**scope.api_kwargs, "per_page": 500}
            if cursor:
                kwargs["cursor"] = cursor
            last_exc: APIError | APIConnectionError | None = None
            for attempt in range(_page_retries + 1):
                try:
                    raw = self._client.rules.lists.items.with_raw_response.list(list_id, **kwargs)
                    body = _json.loads(raw.http_response.text)
                    last_exc = None
                    break
                except (AuthenticationError, PermissionDeniedError):
                    raise
                except _json.JSONDecodeError as e:
                    raise ValueError(
                        f"Invalid JSON in list items response for {list_id}: {e}"
                    ) from e
                except (APIError, APIConnectionError) as e:
                    last_exc = e
                    if attempt < _page_retries:
                        delay = (attempt + 1) * 1.0
                        log.warning(
                            "Retrying page fetch for list %s (%s, attempt %d/%d): %s",
                            list_id,
                            sl,
                            attempt + 1,
                            _page_retries + 1,
                            e,
                        )
                        time.sleep(delay)
            if last_exc is not None:
                raise last_exc
            for item in body.get("result", []):
                cleaned = {k: v for k, v in item.items() if k not in LIST_ITEM_API_FIELDS}
                all_items.append(cleaned)
            # Extract next cursor from result_info
            cursor = None
            result_info = body.get("result_info")
            if result_info:
                cursors = result_info.get("cursors")
                if cursors:
                    cursor = cursors.get("after") or None
            if not cursor:
                break
        return all_items

    def put_list_items(self, scope: Scope, list_id: str, items: list[dict]) -> str:
        """Replace all items in a list (async). Returns operation_id.

        Unlike ``put_phase_rules``, no count-check is performed here because
        this is an async bulk operation — the actual items are applied
        server-side and validated during ``poll_bulk_operation``.
        """
        sl = _fmt_scope(scope)
        log.debug("PUT rules/lists/%s/items %s items=%d", list_id, sl, len(items))
        result = self._client.rules.lists.items.update(list_id, **scope.api_kwargs, body=items)
        d = _ruleset_to_dict(result)
        return d.get("operation_id", "")

    def poll_bulk_operation(
        self, scope: Scope, operation_id: str, *, timeout: float = 120.0
    ) -> str:
        """Poll a bulk operation until completion.

        Uses graduated backoff: 1s → 2s → 3s → 5s (capped).
        Returns "completed". Raises APIError on "failed", TimeoutError on timeout.
        """
        sl = _fmt_scope(scope)
        log.debug("POLL bulk_operations/%s %s", operation_id, sl)
        _BACKOFF = (1.0, 2.0, 3.0, 5.0)
        start = time.monotonic()
        poll_count = 0
        while True:
            result = self._client.rules.lists.bulk_operations.get(operation_id, **scope.api_kwargs)
            d = _ruleset_to_dict(result)
            status = d.get("status", "")
            if status == "completed":
                return "completed"
            if status == "failed":
                error = d.get("error", "unknown error")
                raise APIError(
                    f"Bulk operation {operation_id} failed: {error}",
                    request=None,
                    body=None,
                )
            elapsed = time.monotonic() - start
            if elapsed >= timeout:
                raise TimeoutError(
                    f"Bulk operation {operation_id} timed out after {timeout}s (status={status})"
                )
            interval = _BACKOFF[min(poll_count, len(_BACKOFF) - 1)]
            time.sleep(interval)
            poll_count += 1

    def get_all_lists(
        self, scope: Scope, *, list_names: list[str] | None = None
    ) -> dict[str, dict]:
        """Fetch all lists and their items in parallel.

        Returns {list_name: {"id": ..., "kind": ..., "description": ..., "items": [...]}}.
        If list_names is provided, filters to those names only.
        """
        all_meta = self.list_lists(scope)
        if list_names is not None:
            name_set = set(list_names)
            all_meta = [m for m in all_meta if m["name"] in name_set]

        if not all_meta:
            return {}

        sl = _fmt_scope(scope)
        log.debug("Fetching items for %d list(s) for %s", len(all_meta), sl)

        def _result_fn(meta, items):
            return (
                meta["name"],
                {
                    "id": meta["id"],
                    "kind": meta["kind"],
                    "description": meta["description"],
                    "items": items,
                },
            )

        results, _ = _fetch_parallel(
            all_meta,
            submit_fn=lambda ex, m: ex.submit(self.get_list_items, scope, m["id"]),
            key_fn=lambda m: m["name"],
            result_fn=_result_fn,
            label="list",
            scope_label=sl,
            max_workers=self._max_workers,
        )
        return results

    # --- Page Shield Policies API ---

    def list_page_shield_policies(self, scope: Scope) -> list[dict]:
        """List all Page Shield policies for a zone.

        Returns list of {id, description, action, expression, enabled, value} dicts.
        """
        sl = _fmt_scope(scope)
        log.debug("LIST page_shield/policies %s", sl)
        result = self._client.page_shield.policies.list(zone_id=scope.zone_id)
        policies = []
        for item in result:
            d = _ruleset_to_dict(item)
            policies.append(
                {
                    "id": d.get("id", ""),
                    "description": d.get("description", ""),
                    "action": d.get("action", ""),
                    "expression": d.get("expression", ""),
                    "enabled": d.get("enabled", False),
                    "value": d.get("value", ""),
                }
            )
        return policies

    def create_page_shield_policy(
        self,
        scope: Scope,
        *,
        description: str,
        action: str,
        expression: str,
        enabled: bool,
        value: str,
    ) -> dict:
        """Create a new Page Shield policy. Returns created policy dict."""
        sl = _fmt_scope(scope)
        log.debug("CREATE page_shield/policies %s description=%r", sl, description)
        result = self._client.page_shield.policies.create(
            zone_id=scope.zone_id,
            description=description,
            action=action,
            expression=expression,
            enabled=enabled,
            value=value,
        )
        return _ruleset_to_dict(result)

    def update_page_shield_policy(
        self,
        scope: Scope,
        policy_id: str,
        *,
        description: str,
        action: str,
        expression: str,
        enabled: bool,
        value: str,
    ) -> dict:
        """Update an existing Page Shield policy. Returns updated policy dict."""
        sl = _fmt_scope(scope)
        log.debug("UPDATE page_shield/policies/%s %s", policy_id, sl)
        result = self._client.page_shield.policies.update(
            policy_id,
            zone_id=scope.zone_id,
            description=description,
            action=action,
            expression=expression,
            enabled=enabled,
            value=value,
        )
        return _ruleset_to_dict(result)

    def delete_page_shield_policy(self, scope: Scope, policy_id: str) -> None:
        """Delete a Page Shield policy by ID."""
        sl = _fmt_scope(scope)
        log.debug("DELETE page_shield/policies/%s %s", policy_id, sl)
        self._client.page_shield.policies.delete(policy_id, zone_id=scope.zone_id)

    def get_all_page_shield_policies(self, scope: Scope) -> list[dict]:
        """Fetch all Page Shield policies, stripping API-only fields.

        Returns list of {description, action, expression, enabled, value} dicts.
        """
        policies = self.list_page_shield_policies(scope)
        return [
            {k: v for k, v in p.items() if k not in PAGE_SHIELD_POLICY_API_FIELDS} for p in policies
        ]


def _ruleset_to_dict(ruleset) -> dict:
    """Convert a Cloudflare SDK ruleset object to a plain dict."""
    if isinstance(ruleset, dict):
        return ruleset
    if hasattr(ruleset, "model_dump"):
        return ruleset.model_dump(exclude_none=True)
    if hasattr(ruleset, "to_dict"):
        return ruleset.to_dict()
    try:
        return dict(ruleset)
    except (TypeError, ValueError):
        log.warning(
            "Failed to convert ruleset to dict (type=%s), returning empty",
            type(ruleset).__name__,
        )
        return {}


def _rule_to_dict(rule) -> dict:
    """Convert a Cloudflare SDK rule object to a plain dict."""
    if isinstance(rule, dict):
        return rule
    # The cloudflare SDK returns Pydantic-like model objects
    if hasattr(rule, "model_dump"):
        return rule.model_dump(exclude_none=True)
    if hasattr(rule, "to_dict"):
        return rule.to_dict()
    try:
        return dict(rule)
    except (TypeError, ValueError) as e:
        raise TypeError(f"Cannot convert rule of type {type(rule).__name__} to dict: {e}") from e


__all__ = [
    "BaseProvider",
    "CloudflareProvider",
    "PhaseRulesResult",
    "Scope",
]
