"""Tests for the check modes of the maintainer script ``scripts/sync_cdn_ranges.py``."""

import importlib.util
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "sync_cdn_ranges.py"
_spec = importlib.util.spec_from_file_location("sync_cdn_ranges", _SCRIPT)
sync_cdn_ranges = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sync_cdn_ranges)


def _write_data(data_dir: Path, age: timedelta) -> None:
    stamp = (datetime.now(timezone.utc) - age).strftime("%Y-%m-%dT%H:%M:%SZ")
    for filename, _provider, _src, _fmt in sync_cdn_ranges._SOURCES:
        payload = {"_generated_at": stamp, "cidrs": ["192.0.2.0/24"]}
        (data_dir / filename).write_text(json.dumps(payload))


def _run_main(monkeypatch, *args: str) -> int:
    monkeypatch.setattr("sys.argv", ["sync_cdn_ranges.py", *args])
    try:
        sync_cdn_ranges.main()
    except SystemExit as e:
        return e.code
    return 0


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(sync_cdn_ranges, "_DATA_DIR", tmp_path)
    return tmp_path


class TestCheck:
    def test_within_release_bar_passes(self, data_dir):
        _write_data(data_dir, timedelta(days=6))
        assert sync_cdn_ranges.check()

    def test_past_release_bar_fails(self, data_dir):
        _write_data(data_dir, timedelta(days=8))
        assert not sync_cdn_ranges.check()

    def test_missing_file_fails(self, data_dir):
        _write_data(data_dir, timedelta(days=1))
        (data_dir / "bunny.json").unlink()
        assert not sync_cdn_ranges.check()

    def test_cli_check_defaults_to_release_bar(self, data_dir, monkeypatch):
        _write_data(data_dir, timedelta(days=8))
        assert _run_main(monkeypatch, "--check") == 1

    def test_cli_check_custom_threshold(self, data_dir, monkeypatch):
        _write_data(data_dir, timedelta(days=8))
        assert _run_main(monkeypatch, "--check", "30") == 0


class TestVersion:
    def test_reads_project_version(self):
        assert sync_cdn_ranges._version('[project]\nname = "x"\nversion = "1.2.3"\n') == "1.2.3"

    def test_ignores_other_version_keys(self):
        text = '[project]\nname = "x"\n\n[tool.ruff]\ntarget-version = "py310"\n'
        assert sync_cdn_ranges._version(text) is None

    def test_none_when_file_absent(self):
        assert sync_cdn_ranges._version(None) is None


class TestStagedVersionChanged:
    @staticmethod
    def _git(monkeypatch, staged: str | None, head: str | None) -> None:
        blobs = {":pyproject.toml": staged, "HEAD:pyproject.toml": head}
        monkeypatch.setattr(sync_cdn_ranges, "_git_show", blobs.get)

    def test_bumped_version(self, monkeypatch):
        self._git(monkeypatch, 'version = "1.1.0"\n', 'version = "1.0.0"\n')
        assert sync_cdn_ranges._staged_version_changed()

    def test_same_version_other_edits(self, monkeypatch):
        self._git(monkeypatch, 'version = "1.0.0"\ndeps = ["a"]\n', 'version = "1.0.0"\n')
        assert not sync_cdn_ranges._staged_version_changed()

    def test_no_head_counts_as_changed(self, monkeypatch):
        self._git(monkeypatch, 'version = "0.1.0"\n', None)
        assert sync_cdn_ranges._staged_version_changed()

    def test_reads_index_and_head_from_real_git(self, tmp_path, monkeypatch):
        # Staging only, no commit: HEAD does not resolve, the index does.
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.1.0"\n')
        subprocess.run(["git", "-C", str(tmp_path), "add", "pyproject.toml"], check=True)
        monkeypatch.setattr(sync_cdn_ranges, "_REPO_ROOT", tmp_path)
        assert sync_cdn_ranges._git_show("HEAD:pyproject.toml") is None
        assert 'version = "0.1.0"' in sync_cdn_ranges._git_show(":pyproject.toml")
        assert sync_cdn_ranges._staged_version_changed()


class TestReleaseCommitMode:
    def test_version_bump_with_stale_data_fails(self, data_dir, monkeypatch):
        _write_data(data_dir, timedelta(days=8))
        monkeypatch.setattr(sync_cdn_ranges, "_staged_version_changed", lambda: True)
        assert _run_main(monkeypatch, "--release-commit") == 1

    def test_version_bump_with_fresh_data_passes(self, data_dir, monkeypatch):
        _write_data(data_dir, timedelta(days=1))
        monkeypatch.setattr(sync_cdn_ranges, "_staged_version_changed", lambda: True)
        assert _run_main(monkeypatch, "--release-commit") == 0

    def test_other_commit_with_stale_data_passes(self, data_dir, monkeypatch):
        _write_data(data_dir, timedelta(days=90))
        monkeypatch.setattr(sync_cdn_ranges, "_staged_version_changed", lambda: False)
        assert _run_main(monkeypatch, "--release-commit") == 0
