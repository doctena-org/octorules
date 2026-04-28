"""Octorules — WAF rules as code."""

from importlib.metadata import version

__version__ = version("octorules")

#: Shared User-Agent for any octorules-originated HTTP traffic (core audit,
#: maintainer sync script, hand-rolled provider clients). Pins the ecosystem
#: and the core version; consumers should not add their own.
USER_AGENT = f"octorules/{__version__}"

from octorules.manager import Manager  # noqa: E402  -- Manager depends on __version__

__all__ = ["USER_AGENT", "Manager", "__version__"]
