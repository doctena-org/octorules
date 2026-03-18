"""Octorules — WAF rules as code."""

from importlib.metadata import version

__version__ = version("octorules")

from octorules.manager import Manager

__all__ = ["Manager", "__version__"]
