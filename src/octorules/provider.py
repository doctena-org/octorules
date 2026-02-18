"""Cloudflare SDK wrapper for phase rulesets."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import cloudflare
from cloudflare import (
    APIConnectionError,
    APIError,
    AuthenticationError,
    NotFoundError,
    PermissionDeniedError,
)

from octorules.config import ConfigError
from octorules.phases import ACCOUNT_CF_PHASES, ALL_CF_PHASES

_ACCOUNT_PHASE_SET: frozenset[str] = frozenset(ACCOUNT_CF_PHASES)

log = logging.getLogger("octorules")


@dataclass
class Scope:
    zone_id: str | None = None
    account_id: str | None = None
    label: str = ""

    @property
    def api_kwargs(self) -> dict[str, str]:
        if self.account_id:
            return {"account_id": self.account_id}
        if self.zone_id:
            return {"zone_id": self.zone_id}
        raise ValueError("Scope must have either zone_id or account_id")

    @property
    def is_account(self) -> bool:
        return self.account_id is not None


def _fmt_scope(scope: Scope) -> str:
    """Format scope for log messages."""
    if scope.label:
        kw = scope.api_kwargs
        key = next(iter(kw))
        return f"{scope.label} ({key}={kw[key]})"
    kw = scope.api_kwargs
    key = next(iter(kw))
    return f"{key}={kw[key]}"


class PhaseRulesResult(dict):
    """Dict mapping cf_phase → rules, with tracking of phases that failed to fetch.

    Behaves as a normal dict everywhere, but carries a ``failed_phases`` list so
    callers can distinguish "phase has no rules" from "phase fetch failed".
    """

    failed_phases: list[str]

    def __init__(self, data=None, *, failed_phases: list[str] | None = None):
        super().__init__(data or {})
        self.failed_phases = failed_phases or []


class CloudflareProvider:
    """Wraps the Cloudflare Python SDK for ruleset phase operations."""

    def __init__(
        self,
        token: str,
        *,
        max_retries: int = 2,
        timeout: float | None = None,
        client: cloudflare.Cloudflare | None = None,
    ):
        if client is not None:
            self._client = client
        else:
            kwargs: dict = {"api_token": token, "max_retries": max_retries}
            if timeout is not None:
                kwargs["timeout"] = timeout
            self._client = cloudflare.Cloudflare(**kwargs)
        self._account_id: str | None = None
        self._account_name: str | None = None

    @property
    def account_id(self) -> str | None:
        return self._account_id

    @property
    def account_name(self) -> str | None:
        return self._account_name

    def resolve_zone_id(self, zone_name: str) -> str:
        """Resolve a zone name to its Cloudflare zone ID.

        Raises ConfigError if zero or more than one zone matches.
        Also stashes account info from the first successful resolution.
        """
        result = self._client.zones.list(name=zone_name)
        matches = [z for z in result if z.name == zone_name]
        if len(matches) == 0:
            raise ConfigError(f"No zone found for {zone_name!r}")
        if len(matches) > 1:
            raise ConfigError(f"Multiple zones found for {zone_name!r}")
        zone = matches[0]
        if getattr(zone, "account", None) and not self._account_id:
            self._account_id = zone.account.id
            self._account_name = zone.account.name
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
            phases_to_fetch = [p for p in phases_to_fetch if p in _ACCOUNT_PHASE_SET]
        sl = _fmt_scope(scope)
        log.debug("Fetching %d phase(s) for %s", len(phases_to_fetch), sl)
        rules: dict[str, list[dict]] = {}
        failed: list[str] = []

        if not phases_to_fetch:
            return PhaseRulesResult(rules, failed_phases=failed)

        with ThreadPoolExecutor(max_workers=min(4, len(phases_to_fetch))) as executor:
            futures = {executor.submit(self.get_phase_rules, scope, p): p for p in phases_to_fetch}
            for future in as_completed(futures):
                cf_phase = futures[future]
                try:
                    phase_rules = future.result()
                except (AuthenticationError, PermissionDeniedError):
                    # Cancel remaining futures before propagating
                    for f in futures:
                        f.cancel()
                    raise
                except (APIError, APIConnectionError) as e:
                    log.warning("Failed to fetch phase %s for %s: %s", cf_phase, sl, e)
                    failed.append(cf_phase)
                    continue
                if phase_rules:
                    rules[cf_phase] = phase_rules
        return PhaseRulesResult(rules, failed_phases=failed)


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
