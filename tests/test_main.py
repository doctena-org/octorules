"""Tests for __main__.py entry point."""

from unittest.mock import patch


class TestMainModule:
    @patch("octorules.cli.main")  # suppress side-effect of the first __main__ import
    def test_main_module_calls_cli_main(self, _suppress):
        """Verify python -m octorules calls cli.main()."""
        import importlib

        import octorules.__main__  # noqa: F401  — first import primes the module cache

        with patch("octorules.cli.main") as mock:
            importlib.reload(__import__("octorules.__main__", fromlist=["__main__"]))
            mock.assert_called_once()
