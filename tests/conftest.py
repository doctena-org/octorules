"""Shared fixtures for octorules tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def tmp_config(tmp_path: Path):
    """Create a minimal config file and rules dir, return config path."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "providers:\n"
        "  cloudflare:\n"
        "    token: test-token-123\n"
        "  rules:\n"
        "    directory: ./rules\n"
        "zones:\n"
        "  example.com:\n"
        "    sources:\n"
        "      - rules\n"
    )
    return config_file


@pytest.fixture
def mock_cf_client():
    """Create a mock Cloudflare client."""
    client = MagicMock()
    client.rulesets = MagicMock()
    client.rulesets.phases = MagicMock()
    return client
