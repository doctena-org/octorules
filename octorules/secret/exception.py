"""Secret handler exceptions."""

from __future__ import annotations

from octorules.config import ConfigError


class SecretsException(ConfigError):
    """Raised when secret resolution fails."""
