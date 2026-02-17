"""Tests for __main__.py entry point."""

from __future__ import annotations

from unittest.mock import patch


class TestMainModule:
    @patch("octorules.cli.main")
    def test_main_module_calls_cli_main(self, mock_main):
        """Verify python -m octorules calls cli.main()."""
        # Import triggers the call
        import importlib

        import octorules.__main__  # noqa: F401

        # Re-execute to trigger the call in a controlled way
        with patch("octorules.cli.main") as mock:
            importlib.reload(__import__("octorules.__main__", fromlist=["__main__"]))
            mock.assert_called_once()
