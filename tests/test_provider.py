"""Tests for the Cloudflare provider."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

from octorules.provider import CloudflareProvider, _rule_to_dict


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
        rules = provider.get_phase_rules("zone-123", "http_request_dynamic_redirect")
        assert len(rules) == 1
        assert rules[0]["ref"] == "r1"
        mock_cf_client.rulesets.phases.get.assert_called_once_with(
            "http_request_dynamic_redirect",
            zone_id="zone-123",
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
        rules = provider.get_phase_rules("zone-123", "http_request_dynamic_redirect")
        assert rules == []

    def test_get_phase_rules_empty_ruleset(self, mock_cf_client):
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=None)
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules("zone-123", "http_request_dynamic_redirect")
        assert rules == []

    def test_get_phase_rules_multiple(self, mock_cf_client):
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[
                {"ref": "r1", "expression": "true", "action": "redirect"},
                {"ref": "r2", "expression": "false", "action": "redirect"},
            ]
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules("zone-123", "http_request_dynamic_redirect")
        assert len(rules) == 2
        assert rules[0]["ref"] == "r1"
        assert rules[1]["ref"] == "r2"

    def test_get_phase_rules_with_model_objects(self, mock_cf_client):
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[MockRule({"ref": "r1", "expression": "true", "action": "redirect"})]
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules("zone-123", "http_request_dynamic_redirect")
        assert len(rules) == 1
        assert rules[0]["ref"] == "r1"

    def test_put_phase_rules(self, mock_cf_client):
        rules = [{"ref": "r1", "expression": "true", "action": "redirect"}]
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(rules=list(rules))
        provider = CloudflareProvider("token", client=mock_cf_client)
        count = provider.put_phase_rules("zone-123", "http_request_dynamic_redirect", rules)
        assert count == 1
        mock_cf_client.rulesets.phases.update.assert_called_once_with(
            "http_request_dynamic_redirect",
            zone_id="zone-123",
            rules=rules,
        )

    def test_put_phase_rules_empty(self, mock_cf_client):
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(rules=[])
        provider = CloudflareProvider("token", client=mock_cf_client)
        count = provider.put_phase_rules("zone-123", "http_request_dynamic_redirect", [])
        assert count == 0
        mock_cf_client.rulesets.phases.update.assert_called_once_with(
            "http_request_dynamic_redirect",
            zone_id="zone-123",
            rules=[],
        )

    def test_get_all_phase_rules(self, mock_cf_client):
        def mock_get(cf_phase, zone_id):
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
        result = provider.get_all_phase_rules("zone-123")
        assert "http_request_dynamic_redirect" in result
        assert len(result) == 1

    def test_get_all_phase_rules_multiple(self, mock_cf_client):
        def mock_get(cf_phase, zone_id):
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
        result = provider.get_all_phase_rules("zone-123")
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
        result = provider.get_all_phase_rules("zone-123")
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
            provider.get_phase_rules("zone-123", "http_request_dynamic_redirect")
        assert "GET rulesets/phases/http_request_dynamic_redirect zone=zone-123" in caplog.text

    def test_get_all_phase_rules_partial_failure(self, mock_cf_client, caplog):
        """Non-404 error on one phase should log warning and continue."""
        from cloudflare import APIError

        call_count = 0

        def mock_get(cf_phase, zone_id):
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
            result = provider.get_all_phase_rules("zone-123")
        # redirect phase succeeded, cache phase failed, rest were 404
        assert "http_request_dynamic_redirect" in result
        assert "http_request_cache_settings" not in result
        assert "Failed to fetch phase" in caplog.text
        assert "http_request_cache_settings" in caplog.text
        # All 11 phases should have been attempted
        assert call_count == 11

    def test_get_all_phase_rules_filtered(self, mock_cf_client):
        """When cf_phases is given, only those phases should be fetched."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(
            rules=[{"ref": "r1", "expression": "true", "action": "redirect"}]
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        result = provider.get_all_phase_rules(
            "zone-123", cf_phases=["http_request_dynamic_redirect"]
        )
        assert "http_request_dynamic_redirect" in result
        # Should only have been called once (for the single filtered phase)
        mock_cf_client.rulesets.phases.get.assert_called_once()

    def test_get_all_phase_rules_filter_none_fetches_all(self, mock_cf_client):
        """When cf_phases is None, all phases should be fetched."""
        from cloudflare import NotFoundError

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_cf_client.rulesets.phases.get.side_effect = NotFoundError(
            message="Not Found", response=mock_response, body=None
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        provider.get_all_phase_rules("zone-123", cf_phases=None)
        # Should have been called for all 11 phases
        assert mock_cf_client.rulesets.phases.get.call_count == 11

    def test_put_phase_rules_logs_debug(self, mock_cf_client, caplog):
        rules = [{"ref": "r1"}, {"ref": "r2"}]
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(rules=list(rules))
        provider = CloudflareProvider("token", client=mock_cf_client)
        with caplog.at_level(logging.DEBUG, logger="octorules"):
            provider.put_phase_rules("zone-123", "http_request_dynamic_redirect", rules)
        assert "PUT rulesets/phases/http_request_dynamic_redirect" in caplog.text
        assert "zone=zone-123 rules=2" in caplog.text

    def test_put_phase_rules_count_mismatch_warns(self, mock_cf_client, caplog):
        """PUT response with different rule count should log a warning."""
        rules = [{"ref": "r1"}, {"ref": "r2"}]
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(
            rules=[{"ref": "r1"}]  # Only 1 rule in response
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        with caplog.at_level(logging.WARNING, logger="octorules"):
            count = provider.put_phase_rules("zone-123", "http_request_dynamic_redirect", rules)
        assert count == 1
        assert "sent 2 rule(s) but response contains 1" in caplog.text

    def test_put_phase_rules_null_response_rules(self, mock_cf_client, caplog):
        """PUT response with null rules should treat as 0 rules."""
        rules = [{"ref": "r1"}]
        mock_cf_client.rulesets.phases.update.return_value = MockRuleset(rules=None)
        provider = CloudflareProvider("token", client=mock_cf_client)
        with caplog.at_level(logging.WARNING, logger="octorules"):
            count = provider.put_phase_rules("zone-123", "http_request_dynamic_redirect", rules)
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
        import pytest

        with pytest.raises(AuthenticationError):
            provider.get_all_phase_rules("zone-123")

    def test_get_all_phase_rules_permission_error_propagates(self, mock_cf_client):
        """PermissionDeniedError should propagate immediately, not be caught."""
        from cloudflare import PermissionDeniedError

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_cf_client.rulesets.phases.get.side_effect = PermissionDeniedError(
            message="Missing zone permission", response=mock_response, body=None
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        import pytest

        with pytest.raises(PermissionDeniedError):
            provider.get_all_phase_rules("zone-123")

    def test_get_all_phase_rules_failed_phases_tracked(self, mock_cf_client):
        """Transient errors should be tracked in result.failed_phases."""
        from cloudflare import APIError, NotFoundError

        def mock_get(cf_phase, zone_id):
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
        result = provider.get_all_phase_rules("zone-123")
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
        result = provider.get_all_phase_rules("zone-123")
        assert result.failed_phases == []


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
        rules = provider.get_phase_rules("zone-123", "http_request_dynamic_redirect")
        assert rules[0]["risk_score"] == 0.75
        assert rules[0]["deployment_id"] == "dep-123"

    def test_ruleset_with_empty_rules_list(self, mock_cf_client):
        """CF returning empty rules list (not None) should give empty list."""
        mock_cf_client.rulesets.phases.get.return_value = MockRuleset(rules=[])
        provider = CloudflareProvider("token", client=mock_cf_client)
        rules = provider.get_phase_rules("zone-123", "http_request_dynamic_redirect")
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
        rules = provider.get_phase_rules("zone-123", "http_request_dynamic_redirect")
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
        rules = provider.get_phase_rules("zone-123", "http_request_dynamic_redirect")
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
        rules = provider.get_phase_rules("zone-123", "http_request_dynamic_redirect")
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
        rules = provider.get_phase_rules("zone-123", "http_request_dynamic_redirect")
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
        rules = provider.get_phase_rules("zone-123", "http_request_dynamic_redirect")
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
        rules = provider.get_phase_rules("zone-123", "http_request_dynamic_redirect")
        assert len(rules) == 2
        assert "ref" not in rules[1]

    def test_get_all_ignores_phases_not_in_registry(self, mock_cf_client):
        """get_all_phase_rules only fetches phases from the registry."""
        from cloudflare import NotFoundError

        call_args = []

        def mock_get(cf_phase, zone_id):
            call_args.append(cf_phase)
            mock_response = MagicMock()
            mock_response.status_code = 404
            raise NotFoundError(message="Not Found", response=mock_response, body=None)

        mock_cf_client.rulesets.phases.get.side_effect = mock_get
        provider = CloudflareProvider("token", client=mock_cf_client)
        provider.get_all_phase_rules("zone-123")
        # Should only call registered phases, not any hypothetical new ones
        from octorules.phases import ALL_CF_PHASES

        assert set(call_args) == set(ALL_CF_PHASES)

    def test_connection_error_on_single_phase_doesnt_stop_others(self, mock_cf_client):
        """A network error on one phase should not prevent fetching other phases."""
        from cloudflare import APIConnectionError, NotFoundError

        def mock_get(cf_phase, zone_id):
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
        result = provider.get_all_phase_rules("zone-123")
        assert "http_request_dynamic_redirect" not in result
        assert "http_request_cache_settings" in result

    def test_api_error_on_single_phase_doesnt_stop_others(self, mock_cf_client):
        """A 500 error on one phase should not prevent fetching other phases."""
        from cloudflare import APIError, NotFoundError

        def mock_get(cf_phase, zone_id):
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
        result = provider.get_all_phase_rules("zone-123")
        # Redirect failed, but cache succeeded
        assert "http_request_dynamic_redirect" not in result
        assert "http_request_cache_settings" in result


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
