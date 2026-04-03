"""Tests for octorules.retry."""

from unittest.mock import MagicMock, patch

import pytest

from octorules.retry import retry_with_backoff


class TestRetryWithBackoff:
    """Tests for retry_with_backoff()."""

    def test_success_on_first_attempt(self):
        op = MagicMock(return_value=42)
        result = retry_with_backoff(op, retryable=(ValueError,), label="test")
        assert result == 42
        assert op.call_count == 1

    @patch("octorules.retry.time.sleep")
    def test_retries_on_retryable_exception(self, mock_sleep):
        op = MagicMock(side_effect=[ValueError("boom"), 42])
        result = retry_with_backoff(op, retryable=(ValueError,), max_attempts=3, label="test")
        assert result == 42
        assert op.call_count == 2
        assert mock_sleep.call_count == 1

    @patch("octorules.retry.time.sleep")
    def test_raises_after_max_attempts(self, mock_sleep):
        op = MagicMock(side_effect=ValueError("boom"))
        with pytest.raises(ValueError, match="boom"):
            retry_with_backoff(op, retryable=(ValueError,), max_attempts=3, label="test")
        assert op.call_count == 3
        assert mock_sleep.call_count == 2

    def test_non_retryable_exception_propagates(self):
        op = MagicMock(side_effect=TypeError("wrong"))
        with pytest.raises(TypeError, match="wrong"):
            retry_with_backoff(op, retryable=(ValueError,), label="test")
        assert op.call_count == 1

    @patch("octorules.retry.time.sleep")
    def test_backoff_reuses_last_entry(self, mock_sleep):
        op = MagicMock(side_effect=[ValueError("a"), ValueError("b"), ValueError("c"), 42])
        with patch("octorules.retry.random.uniform", return_value=0):
            retry_with_backoff(
                op,
                retryable=(ValueError,),
                max_attempts=4,
                backoff=(1.0,),
                jitter=0,
                label="test",
            )
        # All 3 sleeps should use backoff[0] = 1.0 (last entry reused)
        assert mock_sleep.call_count == 3
        for call in mock_sleep.call_args_list:
            assert call[0][0] == pytest.approx(1.0)

    @patch("octorules.retry.time.sleep")
    def test_jitter_added_to_backoff(self, mock_sleep):
        op = MagicMock(side_effect=[ValueError("a"), 42])
        with patch("octorules.retry.random.uniform", return_value=0.3):
            retry_with_backoff(
                op,
                retryable=(ValueError,),
                max_attempts=2,
                backoff=(2.0,),
                jitter=0.5,
                label="test",
            )
        mock_sleep.assert_called_once()
        assert mock_sleep.call_args[0][0] == pytest.approx(2.3)

    @patch("octorules.retry.time.sleep")
    def test_multiple_retryable_types(self, mock_sleep):
        op = MagicMock(side_effect=[ValueError("a"), OSError("b"), 42])
        result = retry_with_backoff(
            op,
            retryable=(ValueError, OSError),
            max_attempts=3,
            label="test",
        )
        assert result == 42
        assert op.call_count == 3

    def test_max_attempts_one(self):
        op = MagicMock(side_effect=ValueError("boom"))
        with pytest.raises(ValueError, match="boom"):
            retry_with_backoff(op, retryable=(ValueError,), max_attempts=1, label="test")
        assert op.call_count == 1

    @patch("octorules.retry.time.sleep")
    def test_empty_backoff_tuple(self, mock_sleep):
        """Empty backoff tuple should not crash — falls back to 0.0 delay."""
        op = MagicMock(side_effect=[ValueError("a"), 42])
        result = retry_with_backoff(
            op,
            retryable=(ValueError,),
            max_attempts=2,
            backoff=(),
            jitter=0,
            label="test",
        )
        assert result == 42
        mock_sleep.assert_called_once_with(0.0)
