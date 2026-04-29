"""Tests for the public ``octorules.USER_AGENT`` constant."""

import re

import octorules


def test_user_agent_is_public():
    """USER_AGENT is part of the public API."""
    assert "USER_AGENT" in octorules.__all__
    assert hasattr(octorules, "USER_AGENT")


def test_user_agent_format():
    """Format: ``octorules/<version>``. Version comes from package metadata."""
    pattern = re.compile(r"^octorules/\d+\.\d+\.\d+(?:[.+-]\S+)?$")
    assert pattern.match(octorules.USER_AGENT), octorules.USER_AGENT


def test_user_agent_contains_real_version():
    """The version embedded in USER_AGENT matches __version__ (no drift)."""
    assert octorules.USER_AGENT == f"octorules/{octorules.__version__}"


def test_user_agent_used_by_audit_fetchers():
    """The audit module's HTTP fetchers send octorules.USER_AGENT.

    Sanity check that the module-level integration is intact — without this,
    `audit cdn-ranges` would silently advertise a wrong UA to upstream APIs.
    """
    from octorules.audit import USER_AGENT as audit_user_agent

    assert audit_user_agent == octorules.USER_AGENT
