"""Cloudflare SDK wrapper for phase rulesets."""

from __future__ import annotations

import logging

import cloudflare
from cloudflare import (
    APIConnectionError,
    APIError,
    AuthenticationError,
    NotFoundError,
    PermissionDeniedError,
)

from octorules.config import ConfigError
from octorules.phases import ALL_CF_PHASES

log = logging.getLogger("octorules")


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

    def resolve_zone_id(self, zone_name: str) -> str:
        """Resolve a zone name to its Cloudflare zone ID.

        Raises ConfigError if zero or more than one zone matches.
        """
        result = self._client.zones.list(name=zone_name)
        matches = [z for z in result if z.name == zone_name]
        if len(matches) == 0:
            raise ConfigError(f"No zone found for {zone_name!r}")
        if len(matches) > 1:
            raise ConfigError(f"Multiple zones found for {zone_name!r}")
        return matches[0].id

    def get_phase_rules(self, zone_id: str, cf_phase: str) -> list[dict]:
        """Fetch rules for a single phase. Returns empty list if no ruleset exists."""
        log.debug("GET rulesets/phases/%s zone=%s", cf_phase, zone_id)
        try:
            ruleset = self._client.rulesets.phases.get(
                cf_phase,
                zone_id=zone_id,
            )
            rules = ruleset.rules or []
            return [_rule_to_dict(r) for r in rules]
        except NotFoundError:
            return []

    def put_phase_rules(self, zone_id: str, cf_phase: str, rules: list[dict]) -> int:
        """Atomically replace all rules in a phase.

        Returns the number of rules in the response (for verification).
        """
        log.debug("PUT rulesets/phases/%s zone=%s rules=%d", cf_phase, zone_id, len(rules))
        result = self._client.rulesets.phases.update(
            cf_phase,
            zone_id=zone_id,
            rules=rules,
        )
        response_rules = result.rules or []
        response_count = len(response_rules)
        if response_count != len(rules):
            log.warning(
                "PUT %s zone=%s: sent %d rule(s) but response contains %d",
                cf_phase,
                zone_id,
                len(rules),
                response_count,
            )
        return response_count

    def get_all_phase_rules(
        self, zone_id: str, *, cf_phases: list[str] | None = None
    ) -> PhaseRulesResult:
        """Fetch rules for supported phases. Returns cf_phase → rules mapping.

        AuthenticationError and PermissionDeniedError propagate immediately
        (permanent errors). Transient errors (rate limit, server error,
        connection) are logged and the phase is recorded in ``result.failed_phases``.

        Args:
            zone_id: The Cloudflare zone ID.
            cf_phases: Optional list of CF phase identifiers to fetch.
                       Defaults to all supported phases.
        """
        phases_to_fetch = cf_phases if cf_phases is not None else ALL_CF_PHASES
        log.debug("Fetching %d phase(s) for zone=%s", len(phases_to_fetch), zone_id)
        rules: dict[str, list[dict]] = {}
        failed: list[str] = []
        for cf_phase in phases_to_fetch:
            try:
                phase_rules = self.get_phase_rules(zone_id, cf_phase)
            except (AuthenticationError, PermissionDeniedError):
                raise
            except (APIError, APIConnectionError) as e:
                log.warning("Failed to fetch phase %s for zone=%s: %s", cf_phase, zone_id, e)
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
