"""Test helpers shared across octorules and provider packages.

These helpers live in the package (not in test conftests) so provider
test suites can import them without copy-pasting. The module is
intentionally lightweight — runtime code should not depend on it.
"""
