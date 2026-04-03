"""Secret handler exceptions."""

from octorules.config import ConfigError


class SecretsException(ConfigError):
    """Raised when secret resolution fails."""
