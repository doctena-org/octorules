"""Tests for _map_ordered, _run_staged_tasks, and apply_parallel threading helpers."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from octorules.commands._helpers import _map_ordered, _run_staged_tasks
from octorules.provider.exceptions import ProviderAuthError, ProviderError
from octorules.provider.utils import apply_parallel


# ---------------------------------------------------------------------------
# _map_ordered
# ---------------------------------------------------------------------------
class TestMapOrdered:
    def test_sequential_returns_in_order(self):
        result = _map_ordered(lambda x: x * 2, [1, 2, 3], max_workers=1)
        assert result == [2, 4, 6]

    def test_parallel_returns_in_order(self):
        """Results are in input order even when threads finish out of order."""

        def slow_fn(x):
            # Lower values sleep longer — without ordering, results would be reversed
            time.sleep(0.01 * (4 - x))
            return x * 10

        result = _map_ordered(slow_fn, [1, 2, 3, 4], max_workers=4)
        assert result == [10, 20, 30, 40]

    def test_empty_list(self):
        assert _map_ordered(lambda x: x, [], max_workers=4) == []

    def test_single_item(self):
        assert _map_ordered(lambda x: x + 1, [5], max_workers=4) == [6]

    def test_exception_propagates(self):
        def fail(x):
            if x == 2:
                raise ValueError("boom")
            return x

        with pytest.raises(ValueError, match="boom"):
            _map_ordered(fail, [1, 2, 3], max_workers=2)

    def test_exception_propagates_sequential(self):
        def fail(x):
            if x == 2:
                raise ValueError("boom")
            return x

        with pytest.raises(ValueError, match="boom"):
            _map_ordered(fail, [1, 2, 3], max_workers=1)

    def test_reuse_executor(self):
        """Passing an existing executor works and doesn't close it."""
        with ThreadPoolExecutor(max_workers=2) as ex:
            r1 = _map_ordered(lambda x: x + 1, [1, 2], max_workers=2, executor=ex)
            r2 = _map_ordered(lambda x: x * 2, [3, 4], max_workers=2, executor=ex)
        assert r1 == [2, 3]
        assert r2 == [6, 8]

    def test_actually_runs_concurrently(self):
        """Verify threads actually run in parallel, not sequentially."""
        active = threading.Event()
        both_active = threading.Event()

        def fn(x):
            if x == 0:
                active.set()
                both_active.wait(timeout=2)
            else:
                active.wait(timeout=2)
                both_active.set()
            return x

        result = _map_ordered(fn, [0, 1], max_workers=2)
        assert result == [0, 1]
        assert both_active.is_set()


# ---------------------------------------------------------------------------
# _run_staged_tasks
# ---------------------------------------------------------------------------
class TestRunStagedTasks:
    def test_two_stages_success(self):
        results = []

        def stage1_fn():
            results.append("s1")

        def stage2_fn():
            results.append("s2")

        stages = [
            (True, [("stage1", stage1_fn)]),
            (True, [("stage2", stage2_fn)]),
        ]
        synced, error = _run_staged_tasks(stages, max_workers=1)
        assert error is None
        assert synced == ["stage1", "stage2"]
        assert results == ["s1", "s2"]

    def test_error_in_stage1_stops_stage2(self):
        results = []

        def fail_fn():
            raise ProviderError("stage1 failed")

        def stage2_fn():
            results.append("s2")

        stages = [
            (True, [("stage1", fail_fn)]),
            (True, [("stage2", stage2_fn)]),
        ]
        synced, error = _run_staged_tasks(stages, max_workers=1)
        assert error is not None
        assert "stage1" in error
        assert synced == []
        assert results == []  # stage2 never ran

    def test_collect_false_excludes_labels(self):
        stages = [
            (False, [("setup", lambda: None)]),
            (True, [("main", lambda: None)]),
        ]
        synced, error = _run_staged_tasks(stages, max_workers=1)
        assert error is None
        assert synced == ["main"]  # "setup" not collected

    def test_empty_stages(self):
        synced, error = _run_staged_tasks([], max_workers=1)
        assert synced == []
        assert error is None

    def test_empty_task_list_in_stage(self):
        stages = [
            (True, []),
            (True, [("task", lambda: None)]),
        ]
        synced, _error = _run_staged_tasks(stages, max_workers=1)
        assert synced == ["task"]

    def test_callable_stage_builder(self):
        """Stage can be a callable that returns task list (for dependencies)."""
        created_ids = []

        def create_fn():
            created_ids.append("id-1")

        def make_update_tasks():
            return [(f"update:{cid}", lambda: None) for cid in created_ids]

        stages = [
            (False, [("create", create_fn)]),
            (True, make_update_tasks),
        ]
        synced, error = _run_staged_tasks(stages, max_workers=1)
        assert error is None
        assert synced == ["update:id-1"]

    def test_auth_error_propagates(self):
        def auth_fail():
            raise ProviderAuthError("forbidden")

        stages = [
            (True, [("task", auth_fail)]),
        ]
        with pytest.raises(ProviderAuthError):
            _run_staged_tasks(stages, max_workers=1)


# ---------------------------------------------------------------------------
# apply_parallel additional edge cases
# ---------------------------------------------------------------------------
class TestApplyParallelEdgeCases:
    def test_parallel_collects_successes_on_error(self):
        """In parallel mode, other tasks' successes are collected even when one fails."""
        barrier = threading.Barrier(2, timeout=5)

        def succeed():
            barrier.wait()

        def fail():
            barrier.wait()
            raise ProviderError("boom")

        tasks = [("ok", succeed), ("fail", fail)]
        synced, error = apply_parallel(tasks, max_workers=2)
        assert "ok" in synced
        assert error is not None
        assert "fail" in error

    def test_sequential_stops_on_first_error(self):
        results = []

        def succeed():
            results.append("ok")

        def fail():
            raise ProviderError("boom")

        tasks = [("a", succeed), ("b", fail), ("c", succeed)]
        synced, error = apply_parallel(tasks, max_workers=1)
        assert synced == ["a"]
        assert error is not None
        assert results == ["ok"]  # "c" never ran
