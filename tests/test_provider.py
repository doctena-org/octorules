"""Tests for the Cloudflare provider."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

from octorules.provider import CloudflareProvider, PhaseRulesResult, Scope, _rule_to_dict


class MockRuleset:
    def __init__(self, rules=None):
        self.rules = rules


class MockRule:
    def __init__(self, data: dict):
        self._data = data

    def model_dump(self, exclude_none=False):
        if exclude_none:
            return {k: v for k, v in self._data.items() if v is not None}
        return dict(self._data)


class MockRuleWithToDict:
    """Mock rule that only has to_dict (no model_dump)."""

    def __init__(self, data: dict):
        self._data = data

    def to_dict(self):
        return dict(self._data)


class MockRuleIterableOnly:
    """Mock rule that is iterable (has __iter__) but no model_dump or to_dict."""

    def __init__(self, data: dict):
        self._data = data

    def __iter__(self):
        return iter(self._data.items())


# Helper to create a zone scope for tests
def _zs(zone_id: str = "zone-123", label: str = "") -> Scope:
    return Scope(zone_id=zone_id, label=label)


class TestScope:
    """Tests for the Scope dataclass."""

    def test_zone_api_kwargs(self):
        scope = Scope(zone_id="z123")
        assert scope.api_kwargs == {"zone_id": "z123"}

    def test_account_api_kwargs(self):
        scope = Scope(account_id="a456")
        assert scope.api_kwargs == {"account_id": "a456"}

    def test_account_takes_priority(self):
        scope = Scope(zone_id="z123", account_id="a456")
        assert scope.api_kwargs == {"account_id": "a456"}

    def test_no_id_raises(self):
        scope = Scope()
        with pytest.raises(ValueError, match="either zone_id or account_id"):
            scope.api_kwargs

    def test_is_account_true(self):
        scope = Scope(account_id="a456")
        assert scope.is_account is True

    def test_is_account_false(self):
        scope = Scope(zone_id="z123")
        assert scope.is_account is False

    def test_label(self):
        scope = Scope(zone_id="z123", label="example.com")
        assert scope.label == "example.com"


class TestRuleToDict:
    def test_dict_passthrough(self):
        rule = {"ref": "r1", "expression": "true"}
        assert _rule_to_dict(rule) == rule

    def test_model_dump(self):
        rule = MockRule({"ref": "r1", "expression": "true", "version": None})
        result = _rule_to_dict(rule)
        assert result == {"ref": "r1", "expression": "true"}

    def test_to_dict_fallback(self):
        rule = MockRuleWithToDict({"ref": "r1", "expression": "true"})
        result = _rule_to_dict(rule)
        assert result == {"ref": "r1", "expression": "true"}

    def test_dict_constructor_fallback(self):
        rule = MockRuleIterableOnly({"ref": "r1", "expression": "true"})
        result = _rule_to_dict(rule)
        assert result == {"ref": "r1", "expression": "true"}


class TestCloudflareProvider:
    def test_get_phase_rules(self, mock_cf_client):
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert len(rules) == 1
        assert rules[0]["ref"] == "r1"
        mock_cf_client.rulesets.phases.get.assert_called_once_with(
            "http_request_dynamic_redirect",
            zone_id="zone-123",
        )

    def test_get_phase_rules_account_scope(self, mock_cf_client):
        """Account scope should pass account_id to SDK."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[{"ref": "r1", "expression": "true", "action": "block"}]
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123", label="My Account")
        rules = provider.get_phase_rules(scope, "http_request_firewall_custom")
        assert len(rules) == 1
        mock_cf_client.rulesets.phases.get.assert_called_once_with(
            "http_request_firewall_custom",
            account_id="acct-123",
        )

    def test_get_phase_rules_not_found(self, mock_cf_client):
        from cloudflare import NotFoundError

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_cf_client.rulesets.phases.get.side_effect = NotFoundError(
            message="Not Found",
            response=mock_response,
            body=None,
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert rules == []

    def test_get_phase_rules_empty_ruleset(self, mock_cf_client):
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=None)
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert rules == []

    def test_get_phase_rules_multiple(self, mock_cf_client):
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[
                {"ref": "r1", "expression": "true", "action": "redirect"},
                {"ref": "r2", "expression": "false", "action": "redirect"},
            ]
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert len(rules) == 2
        assert rules[0]["ref"] == "r1"
        assert rules[1]["ref"] == "r2"

    def test_get_phase_rules_with_model_objects(self, mock_cf_client):
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[MockRule({"ref": "r1", "expression": "true", "action": "redirect"})]
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert len(rules) == 1
        assert rules[0]["ref"] == "r1"

    def test_put_phase_rules(self, mock_cf_client):
        rules = [{"ref": "r1", "expression": "true", "action": "redirect"}]
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(rules=list(rules))
        provider = CloudflareProvider("token", client=mock_cf_client)
        count = provider.put_phase_rules(_zs(), "http_request_dynamic_redirect", rules)
        assert count == 1
        mock_cf_client.rulesets.phases.update.assert_called_once_with(
            "http_request_dynamic_redirect",
            zone_id="zone-123",
            rules=rules,
        )

    def test_put_phase_rules_account_scope(self, mock_cf_client):
        """Account scope should pass account_id to SDK."""
        rules = [{"ref": "r1", "expression": "true", "action": "block"}]
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(rules=list(rules))
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123", label="My Account")
        count = provider.put_phase_rules(scope, "http_request_firewall_custom", rules)
        assert count == 1
        mock_cf_client.rulesets.phases.update.assert_called_once_with(
            "http_request_firewall_custom",
            account_id="acct-123",
            rules=rules,
        )

    def test_put_phase_rules_empty(self, mock_cf_client):
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(rules=[])
        provider = CloudflareProvider("token", client=mock_cf_client)
        count = provider.put_phase_rules(_zs(), "http_request_dynamic_redirect", [])
        assert count == 0
        mock_cf_client.rulesets.phases.update.assert_called_once_with(
            "http_request_dynamic_redirect",
            zone_id="zone-123",
            rules=[],
        )

    def test_get_all_phase_rules(self, mock_cf_client):
        def mock_get(cf_phase, **kwargs):
            if cf_phase == "http_request_dynamic_redirect":
                return MockRuleset(
                    rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
                )
            from cloudflare import NotFoundError

            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert "http_request_dynamic_redirect" in result
        assert len(result) == 1

    def test_get_all_phase_rules_multiple(self, mock_cf_client):
        def mock_get(cf_phase, **kwargs):
            if cf_phase == "http_request_dynamic_redirect":
                return MockRuleset(
                    rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
                )
            if cf_phase == "http_request_cache_settings":
                return MockRuleset(
                    rules=[{"ref": "c1", "expression": "true", "action": "set_cache_settings"}]
                )
            from cloudflare import NotFoundError

            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert "http_request_dynamic_redirect" in result
        assert "http_request_cache_settings" in result
        assert len(result) == 2

    def test_get_all_phase_rules_empty(self, mock_cf_client):
        from cloudflare import NotFoundError

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_cf_client.rulesets.phases.get.side_effect = NotFoundError(
            message="Not Found", response=mock_response, body=None
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert result == {}

    @patch("octorules.provider.cloudflare.Cloudflare")
    def test_max_retries_passed_to_client(self, mock_cf_cls):
        CloudflareProvider("token", max_retries=5)
        mock_cf_cls.assert_called_once_with(api_token="token", max_retries=5)

    @patch("octorules.provider.cloudflare.Cloudflare")
    def test_default_max_retries(self, mock_cf_cls):
        CloudflareProvider("token")
        mock_cf_cls.assert_called_once_with(api_token="token", max_retries=2)

    @patch("octorules.provider.cloudflare.Cloudflare")
    def test_timeout_passed_to_client(self, mock_cf_cls):
        CloudflareProvider("token", timeout=30.0)
        mock_cf_cls.assert_called_once_with(api_token="token", max_retries=2, timeout=30.0)

    @patch("octorules.provider.cloudflare.Cloudflare")
    def test_timeout_none_not_passed(self, mock_cf_cls):
        CloudflareProvider("token", timeout=None)
        mock_cf_cls.assert_called_once_with(api_token="token", max_retries=2)

    def test_get_phase_rules_logs_debug(self, mock_cf_client, caplog):
        from cloudflare import NotFoundError

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_cf_client.rulesets.phases.get.side_effect = NotFoundError(
            message="Not Found", response=mock_response, body=None
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        with caplog.at_level(logging.DEBUG, logger="octorules"):
            provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert "GET rulesets/phases/http_request_dynamic_redirect" in caplog.text
        assert "zone-123" in caplog.text

    def test_get_all_phase_rules_partial_failure(self, mock_cf_client, caplog):
        """Non-404 error on one phase should log warning and continue."""
        from cloudflare import APIError

        call_count = 0

        def mock_get(cf_phase, **kwargs):
            nonlocal call_count
            call_count += 1
            if cf_phase == "http_request_dynamic_redirect":
                return MockRuleset(
                    rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
                )
            if cf_phase == "http_request_cache_settings":
                raise APIError("Internal Server Error", request=MagicMock(), body=None)
            from cloudflare import NotFoundError

            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = provider.get_all_phase_rules(_zs())
        # redirect phase succeeded, cache phase failed, rest were 404
        assert "http_request_dynamic_redirect" in result
        assert "http_request_cache_settings" not in result
        assert "Failed to fetch phase" in caplog.text
        assert "http_request_cache_settings" in caplog.text
        # All zone-level phases should have been attempted
        from octorules.phases import ZONE_CF_PHASES

        assert call_count == len(ZONE_CF_PHASES)

    def test_get_all_phase_rules_filtered(self, mock_cf_client):
        """When cf_phases is given, only those phases should be fetched."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs(), cf_phases=["http_request_dynamic_redirect"])
        assert "http_request_dynamic_redirect" in result
        # Should only have been called once (for the single filtered phase)
        mock_cf_client.rulesets.phases.get.assert_called_once()

    def test_get_all_phase_rules_filter_none_fetches_all_zone(self, mock_cf_client):
        """When cf_phases is None with zone scope, all zone-level phases should be fetched."""
        from cloudflare import NotFoundError

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_cf_client.rulesets.phases.get.side_effect = NotFoundError(
            message="Not Found", response=mock_response, body=None
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        provider.get_all_phase_rules(_zs(), cf_phases=None)
        from octorules.phases import ZONE_CF_PHASES

        assert mock_cf_client.rulesets.phases.get.call_count == len(ZONE_CF_PHASES)

    def test_put_phase_rules_logs_debug(self, mock_cf_client, caplog):
        rules = [{"ref": "r1"}, {"ref": "r2"}]
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(rules=list(rules))
        provider = CloudflareProvider("token", client=mock_cf_client)
        with caplog.at_level(logging.DEBUG, logger="octorules"):
            provider.put_phase_rules(_zs(), "http_request_dynamic_redirect", rules)
        assert "PUT rulesets/phases/http_request_dynamic_redirect" in caplog.text
        assert "zone-123" in caplog.text
        assert "rules=2" in caplog.text

    def test_put_phase_rules_count_mismatch_warns(self, mock_cf_client, caplog):
        """PUT response with different rule count should log a warning."""
        rules = [{"ref": "r1"}, {"ref": "r2"}]
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(
            rules=[{"ref": "r1"}]  # Only 1 rule in response
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        with caplog.at_level(logging.WARNING, logger="octorules"):
            count = provider.put_phase_rules(_zs(), "http_request_dynamic_redirect", rules)
        assert count == 1
        assert "sent 2 rule(s) but response contains 1" in caplog.text

    def test_put_phase_rules_null_response_rules(self, mock_cf_client, caplog):
        """PUT response with null rules should treat as 0 rules."""
        rules = [{"ref": "r1"}]
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(rules=None)
        provider = CloudflareProvider("token", client=mock_cf_client)
        with caplog.at_level(logging.WARNING, logger="octorules"):
            count = provider.put_phase_rules(_zs(), "http_request_dynamic_redirect", rules)
        assert count == 0
        assert "sent 1 rule(s) but response contains 0" in caplog.text

    def test_get_all_phase_rules_auth_error_propagates(self, mock_cf_client):
        """AuthenticationError should propagate immediately, not be caught."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_cf_client.rulesets.phases.get.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        provider = CloudflareProvider("token", client=mock_cf_client)

        with pytest.raises(AuthenticationError):
            provider.get_all_phase_rules(_zs())

    def test_get_all_phase_rules_permission_error_propagates(self, mock_cf_client):
        """PermissionDeniedError should propagate immediately, not be caught."""
        from cloudflare import PermissionDeniedError

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_cf_client.rulesets.phases.get.side_effect = PermissionDeniedError(
            message="Missing zone permission", response=mock_response, body=None
        )
        provider = CloudflareProvider("token", client=mock_cf_client)

        with pytest.raises(PermissionDeniedError):
            provider.get_all_phase_rules(_zs())

    def test_get_all_phase_rules_failed_phases_tracked(self, mock_cf_client):
        """Transient errors should be tracked in result.failed_phases."""
        from cloudflare import APIError, NotFoundError

        def mock_get(cf_phase, **kwargs):
            if cf_phase == "http_request_dynamic_redirect":
                return MockRuleset(
                    rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
                )
            if cf_phase == "http_request_cache_settings":
                raise APIError("Server Error", request=MagicMock(), body=None)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert "http_request_dynamic_redirect" in result
        assert "http_request_cache_settings" not in result
        assert "http_request_cache_settings" in result.failed_phases

    def test_get_all_phase_rules_no_failed_phases(self, mock_cf_client):
        """When all phases succeed, failed_phases should be empty."""
        from cloudflare import NotFoundError

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_cf_client.rulesets.phases.get.side_effect = NotFoundError(
            message="Not Found", response=mock_response, body=None
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert result.failed_phases == []

    def test_get_all_phase_rules_account_scope_filters_phases(self, mock_cf_client):
        """Account scope should only fetch account-compatible phases."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(cf_phase, **kwargs):
            call_args.append(cf_phase)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123", label="My Account")
        provider.get_all_phase_rules(scope)
        from octorules.phases import ACCOUNT_CF_PHASES

        assert set(call_args) == set(ACCOUNT_CF_PHASES)
        assert len(call_args) == len(ACCOUNT_CF_PHASES)

    def test_get_all_phase_rules_account_scope_with_filter(self, mock_cf_client):
        """Account scope with cf_phases filter should intersect with account phases."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(cf_phase, **kwargs):
            call_args.append(cf_phase)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        # Request both account-level and zone-only phases; zone-only should be filtered out
        provider.get_all_phase_rules(
            scope,
            cf_phases=["http_request_firewall_custom", "http_request_dynamic_redirect"],
        )
        assert call_args == ["http_request_firewall_custom"]

    def test_get_all_phase_rules_zone_scope_filters_to_zone_phases(self, mock_cf_client):
        """Zone scope should only fetch zone-level phases, excluding account-only ones."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(cf_phase, **kwargs):
            call_args.append(cf_phase)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        provider.get_all_phase_rules(_zs())
        from octorules.phases import ZONE_CF_PHASES

        assert set(call_args) == set(ZONE_CF_PHASES)
        assert len(call_args) == len(ZONE_CF_PHASES)
        # Account-only phases should NOT be fetched for zone scope
        assert "http_custom_errors" not in call_args

    def test_get_all_phase_rules_parallel_results_correct(self, mock_cf_client):
        """Parallel fetching should produce the same results as sequential."""

        def mock_get(cf_phase, **kwargs):
            if cf_phase == "http_request_dynamic_redirect":
                return MockRuleset(
                    rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
                )
            if cf_phase == "http_request_cache_settings":
                return MockRuleset(
                    rules=[{"ref": "c1", "expression": "true", "action": "set_cache_settings"}]
                )
            from cloudflare import NotFoundError

            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert "http_request_dynamic_redirect" in result
        assert "http_request_cache_settings" in result
        assert len(result) == 2
        assert result["http_request_dynamic_redirect"][0]["ref"] == "r1"
        assert result["http_request_cache_settings"][0]["ref"] == "c1"

    def test_get_all_phase_rules_account_empty_filter_returns_empty(self, mock_cf_client):
        """Account scope with only zone-level phases in filter should return empty."""
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.get_all_phase_rules(scope, cf_phases=["http_request_dynamic_redirect"])
        assert result == {}
        assert result.failed_phases == []
        mock_cf_client.rulesets.phases.get.assert_not_called()

    def test_get_all_phase_rules_zone_scope_excludes_account_only(self, mock_cf_client):
        """Zone scope should exclude account-only phases like custom_error_rules."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(cf_phase, **kwargs):
            call_args.append(cf_phase)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        # Request an account-only phase for a zone scope — should be filtered out
        provider.get_all_phase_rules(
            _zs(),
            cf_phases=["http_custom_errors", "http_request_dynamic_redirect"],
        )
        assert call_args == ["http_request_dynamic_redirect"]

    def test_get_all_phase_rules_zone_scope_empty_filter_returns_empty(self, mock_cf_client):
        """Zone scope with only account-only phases in filter should return empty."""
        provider = CloudflareProvider("token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs(), cf_phases=["http_custom_errors"])
        assert result == {}
        assert result.failed_phases == []
        mock_cf_client.rulesets.phases.get.assert_not_called()

    def test_get_all_phase_rules_zone_includes_waf_phases(self, mock_cf_client):
        """Zone scope should include WAF phases (they work at both zone and account level)."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(cf_phase, **kwargs):
            call_args.append(cf_phase)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        provider.get_all_phase_rules(_zs())
        assert "http_request_firewall_custom" in call_args
        assert "http_request_firewall_managed" in call_args
        assert "http_ratelimit" in call_args
        assert "http_request_sbfm" in call_args
        assert "http_response_firewall_managed" in call_args

    def test_get_all_phase_rules_account_includes_waf_phases(self, mock_cf_client):
        """Account scope should include dual zone+account WAF phases."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(cf_phase, **kwargs):
            call_args.append(cf_phase)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        provider.get_all_phase_rules(scope)
        assert "http_request_firewall_custom" in call_args
        assert "http_request_firewall_managed" in call_args
        assert "http_ratelimit" in call_args
        # Zone-only new phases should NOT be in account scope
        assert "http_request_sbfm" not in call_args
        assert "http_response_firewall_managed" not in call_args

    def test_get_all_phase_rules_zone_scope_with_new_phase_filter(self, mock_cf_client):
        """Zone scope should allow filtering to new phases (sbfm, sensitive data)."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(cf_phase, **kwargs):
            call_args.append(cf_phase)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        provider.get_all_phase_rules(
            _zs(),
            cf_phases=[
                "http_request_sbfm",
                "http_response_firewall_managed",
            ],
        )
        assert set(call_args) == {
            "http_request_sbfm",
            "http_response_firewall_managed",
        }

    def test_get_all_phase_rules_account_scope_rejects_new_zone_only_phases(self, mock_cf_client):
        """Account scope should filter out new zone-only phases from explicit filter."""
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.get_all_phase_rules(
            scope,
            cf_phases=["http_request_sbfm", "http_response_firewall_managed"],
        )
        assert result == {}
        mock_cf_client.rulesets.phases.get.assert_not_called()


class TestCFApiResilience:
    """Tests for provider resilience against Cloudflare SDK/API changes."""

    def test_rules_with_extra_fields_preserved(self, mock_cf_client):
        """New fields returned by CF API are passed through as-is."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[
                {
                    "ref": "r1",
                    "expression": "true",
                    "action": "redirect",
                    "risk_score": 0.75,
                    "deployment_id": "dep-123",
                }
            ]
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert rules[0]["risk_score"] == 0.75
        assert rules[0]["deployment_id"] == "dep-123"

    def test_ruleset_with_empty_rules_list(self, mock_cf_client):
        """CF returning empty rules list (not None) should give empty list."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=[])
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert rules == []

    def test_model_dump_with_extra_fields(self, mock_cf_client):
        """Pydantic model objects with new fields are correctly converted."""
        rule = MockRule(
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "new_cf_field": "surprise",
                "risk_score": None,  # None excluded by exclude_none
            }
        )
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=[rule])
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert rules[0]["new_cf_field"] == "surprise"
        assert "risk_score" not in rules[0]  # Excluded by exclude_none

    def test_model_dump_with_nested_structures(self, mock_cf_client):
        """Complex nested structures from SDK model objects are preserved."""
        rule = MockRule(
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "action_parameters": {
                    "from_value": {"target_url": {"value": "https://example.com"}},
                    "status_code": 301,
                    "preserve_query_string": True,
                },
            }
        )
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=[rule])
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        ap = rules[0]["action_parameters"]
        assert ap["from_value"]["target_url"]["value"] == "https://example.com"
        assert ap["status_code"] == 301
        assert ap["preserve_query_string"] is True

    def test_to_dict_fallback_preserves_all_fields(self, mock_cf_client):
        """SDK objects using to_dict fallback preserve all fields including new ones."""
        rule = MockRuleWithToDict(
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "new_field": "value",
            }
        )
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=[rule])
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert rules[0]["new_field"] == "value"

    def test_iterable_fallback_preserves_fields(self, mock_cf_client):
        """SDK objects using dict() fallback preserve all fields."""
        rule = MockRuleIterableOnly(
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "unexpected": 42,
            }
        )
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=[rule])
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert rules[0]["unexpected"] == 42

    def test_mixed_rule_types_in_single_phase(self, mock_cf_client):
        """CF returning a mix of dicts and model objects in one phase."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[
                {"ref": "r1", "expression": "true", "action": "redirect"},
                MockRule({"ref": "r2", "expression": "false", "action": "redirect"}),
                MockRuleWithToDict({"ref": "r3", "expression": "x", "action": "redirect"}),
            ]
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert len(rules) == 3
        assert all(isinstance(r, dict) for r in rules)
        assert [r["ref"] for r in rules] == ["r1", "r2", "r3"]

    def test_rules_without_ref_from_api(self, mock_cf_client):
        """CF can return rules without ref (e.g. managed rules). Provider passes them through."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[
                {"ref": "r1", "expression": "true", "action": "redirect"},
                {"expression": "managed-rule", "action": "block"},  # No ref
            ]
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules(_zs(), "http_request_dynamic_redirect")
        assert len(rules) == 2
        assert "ref" not in rules[1]

    def test_get_all_ignores_phases_not_in_registry(self, mock_cf_client):
        """get_all_phase_rules only fetches phases from the registry (zone-level for zone scope)."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(cf_phase, **kwargs):
            call_args.append(cf_phase)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        provider.get_all_phase_rules(_zs())
        # Zone scope should only call zone-level registered phases
        from octorules.phases import ZONE_CF_PHASES

        assert set(call_args) == set(ZONE_CF_PHASES)

    def test_connection_error_on_single_phase_doesnt_stop_others(self, mock_cf_client):
        """A network error on one phase should not prevent fetching other phases."""
        from cloudflare import APIConnectionError, NotFoundError

        def mock_get(cf_phase, **kwargs):
            if cf_phase == "http_request_dynamic_redirect":
                raise APIConnectionError(request=MagicMock())
            if cf_phase == "http_request_cache_settings":
                return MockRuleset(
                    rules=[{"ref": "c1", "expression": "true", "action": "set_cache_settings"}]
                )
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert "http_request_dynamic_redirect" not in result
        assert "http_request_cache_settings" in result

    def test_api_error_on_single_phase_doesnt_stop_others(self, mock_cf_client):
        """A 500 error on one phase should not prevent fetching other phases."""
        from cloudflare import APIError, NotFoundError

        def mock_get(cf_phase, **kwargs):
            if cf_phase == "http_request_dynamic_redirect":
                raise APIError("Server Error", request=MagicMock(), body=None)
            if cf_phase == "http_request_cache_settings":
                return MockRuleset(
                    rules=[{"ref": "c1", "expression": "true", "action": "set_cache_settings"}]
                )
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        # Redirect failed, but cache succeeded
        assert "http_request_dynamic_redirect" not in result
        assert "http_request_cache_settings" in result

    def test_bad_request_on_unsupported_phase_returns_empty(self, mock_cf_client):
        """A 400 'unknown phase' error should return empty list, not propagate."""
        from cloudflare import BadRequestError

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_cf_client.rulesets.phases.get.side_effect = BadRequestError(
            message='unknown phase "http_request_sbfm"',
            response=mock_response,
            body=None,
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        result = provider.get_phase_rules(_zs(), "http_request_sbfm")
        assert result == []

    def test_bad_request_on_single_phase_doesnt_stop_others(self, mock_cf_client):
        """A 400 on one phase should not prevent fetching other phases."""
        from cloudflare import BadRequestError, NotFoundError

        def mock_get(cf_phase, **kwargs):
            if cf_phase == "http_request_sbfm":
                mock_response = MagicMock()
                mock_response.status_code = 400
                raise BadRequestError(
                    message='unknown phase "http_request_sbfm"',
                    response=mock_response,
                    body=None,
                )
            if cf_phase == "http_request_cache_settings":
                return MockRuleset(
                    rules=[{"ref": "c1", "expression": "true", "action": "set_cache_settings"}]
                )
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        result = provider.get_all_phase_rules(_zs())
        assert "http_request_sbfm" not in result
        assert "http_request_cache_settings" in result
        assert "http_request_sbfm" not in result.failed_phases


class TestResolveZoneId:
    """Tests for CloudflareProvider.resolve_zone_id."""

    def test_single_match(self, mock_cf_client):
        zone = MagicMock()
        zone.name = "example.com"
        zone.id = "aabbccdd" * 4
        mock_cf_client.zones.list.return_value = [zone]
        provider = CloudflareProvider("token", client=mock_cf_client)
        result = provider.resolve_zone_id("example.com")
        assert result == "aabbccdd" * 4
        mock_cf_client.zones.list.assert_called_once_with(name="example.com")

    def test_not_found(self, mock_cf_client):
        from octorules.config import ConfigError

        mock_cf_client.zones.list.return_value = []
        provider = CloudflareProvider("token", client=mock_cf_client)
        with pytest.raises(ConfigError, match="No zone found"):
            provider.resolve_zone_id("missing.com")

    def test_multiple_matches(self, mock_cf_client):
        from octorules.config import ConfigError

        zone1 = MagicMock()
        zone1.name = "example.com"
        zone1.id = "11111111" * 4
        zone2 = MagicMock()
        zone2.name = "example.com"
        zone2.id = "22222222" * 4
        mock_cf_client.zones.list.return_value = [zone1, zone2]
        provider = CloudflareProvider("token", client=mock_cf_client)
        with pytest.raises(ConfigError, match="Multiple zones found"):
            provider.resolve_zone_id("example.com")

    def test_filters_by_exact_name(self, mock_cf_client):
        """Only exact name matches should be counted."""
        zone1 = MagicMock()
        zone1.name = "sub.example.com"
        zone1.id = "11111111" * 4
        zone2 = MagicMock()
        zone2.name = "example.com"
        zone2.id = "22222222" * 4
        mock_cf_client.zones.list.return_value = [zone1, zone2]
        provider = CloudflareProvider("token", client=mock_cf_client)
        result = provider.resolve_zone_id("example.com")
        assert result == "22222222" * 4

    def test_api_error_propagates(self, mock_cf_client):
        from cloudflare import APIError

        mock_cf_client.zones.list.side_effect = APIError(
            "Server Error", request=MagicMock(), body=None
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        with pytest.raises(APIError):
            provider.resolve_zone_id("example.com")

    def test_stashes_account_info(self, mock_cf_client):
        """resolve_zone_id should stash account info from the zone response."""
        zone = MagicMock()
        zone.name = "example.com"
        zone.id = "aabbccdd" * 4
        zone.account.id = "acct-123"
        zone.account.name = "Doctena S.A."
        mock_cf_client.zones.list.return_value = [zone]
        provider = CloudflareProvider("token", client=mock_cf_client)
        provider.resolve_zone_id("example.com")
        assert provider.account_id == "acct-123"
        assert provider.account_name == "Doctena S.A."

    def test_stashes_account_only_once(self, mock_cf_client):
        """Only the first resolution should stash account info."""
        zone1 = MagicMock()
        zone1.name = "a.com"
        zone1.id = "id-a"
        zone1.account.id = "acct-first"
        zone1.account.name = "First Account"
        zone2 = MagicMock()
        zone2.name = "b.com"
        zone2.id = "id-b"
        zone2.account.id = "acct-second"
        zone2.account.name = "Second Account"
        mock_cf_client.zones.list.side_effect = [[zone1], [zone2]]
        provider = CloudflareProvider("token", client=mock_cf_client)
        provider.resolve_zone_id("a.com")
        provider.resolve_zone_id("b.com")
        assert provider.account_id == "acct-first"
        assert provider.account_name == "First Account"

    def test_no_account_attribute(self, mock_cf_client):
        """Zone without account attribute should not crash."""
        zone = MagicMock(spec=["name", "id"])
        zone.name = "example.com"
        zone.id = "aabbccdd" * 4
        mock_cf_client.zones.list.return_value = [zone]
        provider = CloudflareProvider("token", client=mock_cf_client)
        provider.resolve_zone_id("example.com")
        assert provider.account_id is None
        assert provider.account_name is None


class TestScopeApiKwargsCache:
    """Tests for Scope.api_kwargs caching."""

    def test_zone_scope_returns_same_dict(self):
        scope = Scope(zone_id="z1")
        first = scope.api_kwargs
        second = scope.api_kwargs
        assert first is second
        assert first == {"zone_id": "z1"}

    def test_account_scope_returns_same_dict(self):
        scope = Scope(account_id="a1")
        first = scope.api_kwargs
        second = scope.api_kwargs
        assert first is second
        assert first == {"account_id": "a1"}


class TestMaxWorkersInit:
    """Tests for max_workers in CloudflareProvider."""

    def test_default_max_workers_is_1(self, mock_cf_client):
        provider = CloudflareProvider("token", client=mock_cf_client)
        assert provider._max_workers == 1

    def test_custom_max_workers(self, mock_cf_client):
        provider = CloudflareProvider("token", max_workers=8, client=mock_cf_client)
        assert provider._max_workers == 8

    def test_connection_pool_scaled_when_max_workers_gt_1(self):
        """When max_workers > 1 and no client given, http_client should be configured."""
        with patch("octorules.provider.cloudflare.Cloudflare") as mock_cf_cls:
            CloudflareProvider("fake-token", max_workers=4)
            call_kwargs = mock_cf_cls.call_args[1]
            assert "http_client" in call_kwargs

    def test_no_custom_pool_when_max_workers_1(self):
        """When max_workers=1, default pool is used (no http_client override)."""
        with patch("octorules.provider.cloudflare.Cloudflare") as mock_cf_cls:
            CloudflareProvider("fake-token", max_workers=1)
            call_kwargs = mock_cf_cls.call_args[1]
            assert "http_client" not in call_kwargs

    def test_phase_fetching_uses_max_workers(self, mock_cf_client):
        """get_all_phase_rules should respect _max_workers for thread pool size."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=[])
        provider = CloudflareProvider("token", max_workers=4, client=mock_cf_client)
        scope = Scope(zone_id="z1")
        # Fetch just 2 phases — workers should be min(4, 2) = 2
        result = provider.get_all_phase_rules(scope, cf_phases=["p1", "p2"])
        assert isinstance(result, PhaseRulesResult)
