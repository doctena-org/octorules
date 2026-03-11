"""Tests for CloudflareProvider Page Shield policy methods."""

from __future__ import annotations

from octorules.provider import (
    CloudflareProvider,
    Scope,
)

from .mocks import MockRule


class TestPageShieldPolicies:
    """Tests for CloudflareProvider Page Shield policy methods."""

    def test_list_page_shield_policies(self, mock_cf_client):
        """list_page_shield_policies returns filtered dicts."""
        mock_cf_client.page_shield.policies.list.return_value = [
            MockRule(
                {
                    "id": "pol-1",
                    "description": "CSP on all",
                    "action": "allow",
                    "expression": "true",
                    "enabled": True,
                    "value": "script-src 'self'",
                    "last_updated": "2024-01-01T00:00:00Z",
                }
            ),
        ]
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")
        result = provider.list_page_shield_policies(scope)
        assert len(result) == 1
        assert result[0] == {
            "id": "pol-1",
            "description": "CSP on all",
            "action": "allow",
            "expression": "true",
            "enabled": True,
            "value": "script-src 'self'",
        }
        mock_cf_client.page_shield.policies.list.assert_called_once_with(zone_id="zone-123")

    def test_list_page_shield_policies_empty(self, mock_cf_client):
        """list_page_shield_policies returns empty list when no policies."""
        mock_cf_client.page_shield.policies.list.return_value = []
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")
        result = provider.list_page_shield_policies(scope)
        assert result == []

    def test_create_page_shield_policy(self, mock_cf_client):
        """create_page_shield_policy calls SDK and returns dict."""
        mock_cf_client.page_shield.policies.create.return_value = MockRule(
            {
                "id": "pol-new",
                "description": "New CSP",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "script-src 'self'",
            }
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")
        result = provider.create_page_shield_policy(
            scope,
            description="New CSP",
            action="allow",
            expression="true",
            enabled=True,
            value="script-src 'self'",
        )
        assert result["id"] == "pol-new"
        assert result["description"] == "New CSP"
        mock_cf_client.page_shield.policies.create.assert_called_once_with(
            zone_id="zone-123",
            description="New CSP",
            action="allow",
            expression="true",
            enabled=True,
            value="script-src 'self'",
        )

    def test_update_page_shield_policy(self, mock_cf_client):
        """update_page_shield_policy calls SDK with policy_id."""
        mock_cf_client.page_shield.policies.update.return_value = MockRule(
            {
                "id": "pol-1",
                "description": "Updated CSP",
                "action": "log",
                "expression": "true",
                "enabled": True,
                "value": "script-src 'self' https:",
            }
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")
        result = provider.update_page_shield_policy(
            scope,
            "pol-1",
            description="Updated CSP",
            action="log",
            expression="true",
            enabled=True,
            value="script-src 'self' https:",
        )
        assert result["id"] == "pol-1"
        assert result["action"] == "log"
        mock_cf_client.page_shield.policies.update.assert_called_once_with(
            "pol-1",
            zone_id="zone-123",
            description="Updated CSP",
            action="log",
            expression="true",
            enabled=True,
            value="script-src 'self' https:",
        )

    def test_delete_page_shield_policy(self, mock_cf_client):
        """delete_page_shield_policy calls SDK with correct args."""
        mock_cf_client.page_shield.policies.delete.return_value = None
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")
        provider.delete_page_shield_policy(scope, "pol-1")
        mock_cf_client.page_shield.policies.delete.assert_called_once_with(
            "pol-1", zone_id="zone-123"
        )

    def test_get_all_page_shield_policies(self, mock_cf_client):
        """get_all_page_shield_policies strips API fields."""
        mock_cf_client.page_shield.policies.list.return_value = [
            MockRule(
                {
                    "id": "pol-1",
                    "description": "CSP on all",
                    "action": "allow",
                    "expression": "true",
                    "enabled": True,
                    "value": "script-src 'self'",
                    "last_updated": "2024-01-01T00:00:00Z",
                }
            ),
        ]
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")
        result = provider.get_all_page_shield_policies(scope)
        assert len(result) == 1
        assert "id" not in result[0]
        assert "last_updated" not in result[0]
        assert result[0] == {
            "description": "CSP on all",
            "action": "allow",
            "expression": "true",
            "enabled": True,
            "value": "script-src 'self'",
        }

    def test_get_all_page_shield_policies_empty(self, mock_cf_client):
        """get_all_page_shield_policies returns empty list when no policies."""
        mock_cf_client.page_shield.policies.list.return_value = []
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(zone_id="zone-123")
        result = provider.get_all_page_shield_policies(scope)
        assert result == []
