"""Tests for CloudflareProvider list-related methods."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from octorules.provider import (
    CloudflareProvider,
    Scope,
)


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


class TestListMethods:
    """Tests for CloudflareProvider list-related methods."""

    # --- list_lists ---

    def test_list_lists(self, mock_cf_client):
        """list_lists returns filtered dicts with id, name, kind, description."""
        mock_cf_client.rules.lists.list.return_value = [
            MockRule(
                {
                    "id": "lst-1",
                    "name": "ip_blocklist",
                    "kind": "ip",
                    "description": "Blocked IPs",
                    "extra_field": "ignored",
                }
            ),
            MockRule(
                {
                    "id": "lst-2",
                    "name": "asn_list",
                    "kind": "asn",
                    "description": "Bad ASNs",
                }
            ),
        ]
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.list_lists(scope)
        assert len(result) == 2
        assert result[0] == {
            "id": "lst-1",
            "name": "ip_blocklist",
            "kind": "ip",
            "description": "Blocked IPs",
        }
        assert result[1] == {
            "id": "lst-2",
            "name": "asn_list",
            "kind": "asn",
            "description": "Bad ASNs",
        }
        mock_cf_client.rules.lists.list.assert_called_once_with(account_id="acct-123")

    def test_list_lists_empty(self, mock_cf_client):
        """list_lists returns empty list when no lists exist."""
        mock_cf_client.rules.lists.list.return_value = []
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.list_lists(scope)
        assert result == []

    def test_list_lists_uses_ruleset_to_dict(self, mock_cf_client):
        """list_lists should convert SDK objects via _ruleset_to_dict (model_dump)."""
        mock_cf_client.rules.lists.list.return_value = [
            MockRule(
                {
                    "id": "lst-1",
                    "name": "test",
                    "kind": "ip",
                    "description": "desc",
                    "nullable_field": None,
                }
            ),
        ]
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.list_lists(scope)
        # nullable_field excluded by model_dump(exclude_none=True), and then
        # only id/name/kind/description are picked
        assert result == [{"id": "lst-1", "name": "test", "kind": "ip", "description": "desc"}]

    def test_list_lists_to_dict_fallback(self, mock_cf_client):
        """list_lists handles SDK objects with to_dict fallback."""
        mock_cf_client.rules.lists.list.return_value = [
            MockRuleWithToDict({"id": "lst-1", "name": "test", "kind": "ip", "description": "d"}),
        ]
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.list_lists(scope)
        assert result == [{"id": "lst-1", "name": "test", "kind": "ip", "description": "d"}]

    # --- create_list ---

    def test_create_list(self, mock_cf_client):
        """create_list calls SDK and returns converted dict."""
        mock_cf_client.rules.lists.create.return_value = MockRule(
            {"id": "lst-new", "name": "my_list", "kind": "ip", "description": "new list"}
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.create_list(scope, "my_list", "ip", "new list")
        assert result["id"] == "lst-new"
        assert result["name"] == "my_list"
        assert result["kind"] == "ip"
        assert result["description"] == "new list"
        mock_cf_client.rules.lists.create.assert_called_once_with(
            account_id="acct-123", kind="ip", name="my_list", description="new list"
        )

    def test_create_list_default_description(self, mock_cf_client):
        """create_list passes empty string as default description."""
        mock_cf_client.rules.lists.create.return_value = MockRule(
            {"id": "lst-new", "name": "my_list", "kind": "ip"}
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        provider.create_list(scope, "my_list", "ip")
        mock_cf_client.rules.lists.create.assert_called_once_with(
            account_id="acct-123", kind="ip", name="my_list", description=""
        )

    # --- delete_list ---

    def test_delete_list(self, mock_cf_client):
        """delete_list calls SDK with correct args."""
        mock_cf_client.rules.lists.delete.return_value = None
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        provider.delete_list(scope, "lst-1")
        mock_cf_client.rules.lists.delete.assert_called_once_with("lst-1", account_id="acct-123")

    # --- update_list_description ---

    def test_update_list_description(self, mock_cf_client):
        """update_list_description calls SDK with correct args."""
        mock_cf_client.rules.lists.update.return_value = None
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        provider.update_list_description(scope, "lst-1", "new description")
        mock_cf_client.rules.lists.update.assert_called_once_with(
            "lst-1", account_id="acct-123", description="new description"
        )

    # --- get_list_items ---

    @staticmethod
    def _mock_raw_items_response(items, cursor_after=None):
        """Build a mock raw response for rules.lists.items.with_raw_response.list."""
        import json

        body = {"result": items, "result_info": {}}
        if cursor_after:
            body["result_info"]["cursors"] = {"after": cursor_after}
        raw = MagicMock()
        raw.http_response.text = json.dumps(body)
        return raw

    def test_get_list_items_single_page(self, mock_cf_client):
        """get_list_items returns items from a single page."""
        items_data = [
            {"ip": "1.2.3.4/32", "comment": "bad"},
            {"ip": "5.6.7.8/32", "comment": "worse"},
        ]
        raw = self._mock_raw_items_response(items_data)
        mock_cf_client.rules.lists.items.with_raw_response.list.return_value = raw
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        items = provider.get_list_items(scope, "lst-1")
        assert len(items) == 2
        assert items[0] == {"ip": "1.2.3.4/32", "comment": "bad"}
        assert items[1] == {"ip": "5.6.7.8/32", "comment": "worse"}
        mock_cf_client.rules.lists.items.with_raw_response.list.assert_called_once_with(
            "lst-1", account_id="acct-123", per_page=500
        )

    def test_get_list_items_strips_api_fields(self, mock_cf_client):
        """get_list_items strips id, created_on, modified_on from items."""
        items_data = [
            {
                "id": "item-1",
                "ip": "1.2.3.4/32",
                "comment": "test",
                "created_on": "2024-01-01T00:00:00Z",
                "modified_on": "2024-01-02T00:00:00Z",
            },
        ]
        raw = self._mock_raw_items_response(items_data)
        mock_cf_client.rules.lists.items.with_raw_response.list.return_value = raw
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        items = provider.get_list_items(scope, "lst-1")
        assert len(items) == 1
        assert "id" not in items[0]
        assert "created_on" not in items[0]
        assert "modified_on" not in items[0]
        assert items[0] == {"ip": "1.2.3.4/32", "comment": "test"}

    def test_get_list_items_pagination(self, mock_cf_client):
        """get_list_items follows cursor-based pagination across multiple pages."""
        page1 = self._mock_raw_items_response([{"ip": "1.1.1.1/32"}], cursor_after="cursor-page2")
        page2 = self._mock_raw_items_response([{"ip": "2.2.2.2/32"}], cursor_after="cursor-page3")
        page3 = self._mock_raw_items_response([{"ip": "3.3.3.3/32"}])

        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = [
            page1,
            page2,
            page3,
        ]
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        items = provider.get_list_items(scope, "lst-1")
        assert len(items) == 3
        assert items[0] == {"ip": "1.1.1.1/32"}
        assert items[1] == {"ip": "2.2.2.2/32"}
        assert items[2] == {"ip": "3.3.3.3/32"}
        # Verify pagination calls
        calls = mock_cf_client.rules.lists.items.with_raw_response.list.call_args_list
        assert len(calls) == 3
        kw = {"account_id": "acct-123", "per_page": 500}
        assert calls[0] == (("lst-1",), kw)
        assert calls[1] == (("lst-1",), {**kw, "cursor": "cursor-page2"})
        assert calls[2] == (("lst-1",), {**kw, "cursor": "cursor-page3"})

    def test_get_list_items_empty(self, mock_cf_client):
        """get_list_items returns empty list when list has no items."""
        raw = self._mock_raw_items_response([])
        mock_cf_client.rules.lists.items.with_raw_response.list.return_value = raw
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        items = provider.get_list_items(scope, "lst-1")
        assert items == []

    # --- put_list_items ---

    def test_put_list_items(self, mock_cf_client):
        """put_list_items returns operation_id from response."""
        mock_cf_client.rules.lists.items.update.return_value = MockRule(
            {"operation_id": "op-abc-123"}
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        items = [{"ip": "1.2.3.4/32"}, {"ip": "5.6.7.8/32"}]
        op_id = provider.put_list_items(scope, "lst-1", items)
        assert op_id == "op-abc-123"
        mock_cf_client.rules.lists.items.update.assert_called_once_with(
            "lst-1", account_id="acct-123", body=items
        )

    def test_put_list_items_empty_operation_id(self, mock_cf_client):
        """put_list_items returns empty string when operation_id missing."""
        mock_cf_client.rules.lists.items.update.return_value = MockRule({})
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        op_id = provider.put_list_items(scope, "lst-1", [])
        assert op_id == ""

    # --- poll_bulk_operation ---

    def test_poll_bulk_operation_completed(self, mock_cf_client):
        """poll_bulk_operation returns 'completed' on success."""
        mock_cf_client.rules.lists.bulk_operations.get.return_value = MockRule(
            {"status": "completed"}
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.poll_bulk_operation(scope, "op-123")
        assert result == "completed"
        mock_cf_client.rules.lists.bulk_operations.get.assert_called_once_with(
            "op-123", account_id="acct-123"
        )

    def test_poll_bulk_operation_failed_raises(self, mock_cf_client):
        """poll_bulk_operation raises APIError on failed status."""
        from cloudflare import APIError

        mock_cf_client.rules.lists.bulk_operations.get.return_value = MockRule(
            {"status": "failed", "error": "Invalid IP address"}
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with pytest.raises(APIError, match="Bulk operation op-123 failed: Invalid IP address"):
            provider.poll_bulk_operation(scope, "op-123")

    def test_poll_bulk_operation_failed_unknown_error(self, mock_cf_client):
        """poll_bulk_operation uses 'unknown error' when error field missing."""
        from cloudflare import APIError

        mock_cf_client.rules.lists.bulk_operations.get.return_value = MockRule({"status": "failed"})
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with pytest.raises(APIError, match="unknown error"):
            provider.poll_bulk_operation(scope, "op-123")

    def test_poll_bulk_operation_timeout_raises(self, mock_cf_client):
        """poll_bulk_operation raises TimeoutError when timeout exceeded."""
        mock_cf_client.rules.lists.bulk_operations.get.return_value = MockRule(
            {"status": "running"}
        )
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with pytest.raises(TimeoutError, match="Bulk operation op-123 timed out after 0.01s"):
            provider.poll_bulk_operation(scope, "op-123", timeout=0.01, interval=0.001)

    def test_poll_bulk_operation_completes_after_retries(self, mock_cf_client):
        """poll_bulk_operation succeeds after polling through pending status."""
        mock_cf_client.rules.lists.bulk_operations.get.side_effect = [
            MockRule({"status": "running"}),
            MockRule({"status": "running"}),
            MockRule({"status": "completed"}),
        ]
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.poll_bulk_operation(scope, "op-123", timeout=10.0, interval=0.001)
        assert result == "completed"
        assert mock_cf_client.rules.lists.bulk_operations.get.call_count == 3

    # --- get_all_lists ---

    def test_get_all_lists_discovers_and_fetches(self, mock_cf_client):
        """get_all_lists discovers lists and fetches items in parallel."""
        mock_cf_client.rules.lists.list.return_value = [
            MockRule(
                {"id": "lst-1", "name": "ip_blocklist", "kind": "ip", "description": "Blocked IPs"}
            ),
            MockRule({"id": "lst-2", "name": "asn_list", "kind": "asn", "description": "Bad ASNs"}),
        ]

        def mock_raw_items(list_id, **kwargs):
            if list_id == "lst-1":
                return self._mock_raw_items_response([{"ip": "1.2.3.4/32", "comment": "bad"}])
            elif list_id == "lst-2":
                return self._mock_raw_items_response([{"asn": 64496, "comment": "test"}])
            return self._mock_raw_items_response([])

        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = mock_raw_items
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.get_all_lists(scope)
        assert len(result) == 2
        assert "ip_blocklist" in result
        assert result["ip_blocklist"]["id"] == "lst-1"
        assert result["ip_blocklist"]["kind"] == "ip"
        assert result["ip_blocklist"]["description"] == "Blocked IPs"
        assert result["ip_blocklist"]["items"] == [{"ip": "1.2.3.4/32", "comment": "bad"}]
        assert "asn_list" in result
        assert result["asn_list"]["id"] == "lst-2"
        assert result["asn_list"]["items"] == [{"asn": 64496, "comment": "test"}]

    def test_get_all_lists_with_list_names_filter(self, mock_cf_client):
        """get_all_lists filters to specified list_names."""
        mock_cf_client.rules.lists.list.return_value = [
            MockRule({"id": "lst-1", "name": "ip_blocklist", "kind": "ip", "description": ""}),
            MockRule({"id": "lst-2", "name": "asn_list", "kind": "asn", "description": ""}),
            MockRule(
                {"id": "lst-3", "name": "hostname_list", "kind": "hostname", "description": ""}
            ),
        ]

        def mock_raw_items(list_id, **kwargs):
            return self._mock_raw_items_response([{"ip": "1.1.1.1/32"}])

        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = mock_raw_items
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.get_all_lists(scope, list_names=["ip_blocklist", "hostname_list"])
        assert len(result) == 2
        assert "ip_blocklist" in result
        assert "hostname_list" in result
        assert "asn_list" not in result

    def test_get_all_lists_empty(self, mock_cf_client):
        """get_all_lists returns empty when no lists exist."""
        mock_cf_client.rules.lists.list.return_value = []
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.get_all_lists(scope)
        assert result == {}

    def test_get_all_lists_filter_matches_none(self, mock_cf_client):
        """get_all_lists returns empty when filter matches no lists."""
        mock_cf_client.rules.lists.list.return_value = [
            MockRule({"id": "lst-1", "name": "ip_blocklist", "kind": "ip", "description": ""}),
        ]
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        result = provider.get_all_lists(scope, list_names=["nonexistent_list"])
        assert result == {}
        # Should not attempt to fetch items since no lists matched
        mock_cf_client.rules.lists.items.with_raw_response.list.assert_not_called()

    def test_get_all_lists_auth_error_propagates(self, mock_cf_client):
        """AuthenticationError should propagate from get_all_lists."""
        from cloudflare import AuthenticationError

        mock_cf_client.rules.lists.list.return_value = [
            MockRule({"id": "lst-1", "name": "test", "kind": "ip", "description": ""})
        ]

        mock_response = MagicMock()
        mock_response.status_code = 401

        def mock_raw_items(list_id, **kwargs):
            raise AuthenticationError(
                message="Invalid API token", response=mock_response, body=None
            )

        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = mock_raw_items
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with pytest.raises(AuthenticationError):
            provider.get_all_lists(scope)

    def test_get_all_lists_transient_error_skips(self, mock_cf_client, caplog):
        """Transient API error on one list should skip it and continue."""
        from cloudflare import APIError

        mock_cf_client.rules.lists.list.return_value = [
            MockRule({"id": "lst-1", "name": "good_list", "kind": "ip", "description": "ok"}),
            MockRule({"id": "lst-2", "name": "bad_list", "kind": "ip", "description": "fail"}),
        ]

        def mock_raw_items(list_id, **kwargs):
            if list_id == "lst-2":
                raise APIError("Server Error", request=MagicMock(), body=None)
            return self._mock_raw_items_response([{"ip": "1.1.1.1/32"}])

        mock_cf_client.rules.lists.items.with_raw_response.list.side_effect = mock_raw_items
        provider = CloudflareProvider("token", client=mock_cf_client)
        scope = Scope(account_id="acct-123")
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = provider.get_all_lists(scope)
        assert "good_list" in result
        assert "bad_list" not in result
        assert "Failed to fetch items for list bad_list" in caplog.text
