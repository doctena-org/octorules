"""Built-in environment variable secret handler."""

import os

from octorules.secret.base import BaseSecrets
from octorules.secret.exception import SecretsException


class EnvironSecrets(BaseSecrets):
    """Resolve secrets from environment variables.

    ``env/MY_VAR`` resolves to the value of ``$MY_VAR``.
    """

    def fetch(self, ref: str, source: str) -> str:
        result = os.environ.get(ref)
        if result is None:
            raise SecretsException(f"Environment variable {ref!r} is not set (from {source!r})")
        return result
