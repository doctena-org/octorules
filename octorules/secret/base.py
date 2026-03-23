"""Base class for secret handlers."""

from __future__ import annotations

import logging


class BaseSecrets:
    """Base class for pluggable secret handlers.

    Subclasses must implement :meth:`fetch` to resolve a secret reference
    (the part after ``handler/``) into its plaintext value.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.log = logging.getLogger(f"{__name__}.{name}")

    def fetch(self, ref: str, source: str) -> str:
        """Resolve *ref* to its secret value.

        Args:
            ref: The reference string (everything after ``handler/``).
            source: Dot-path describing where in the config this value
                appeared (for error messages).

        Raises:
            NotImplementedError: Subclasses must override this method.
        """
        raise NotImplementedError
