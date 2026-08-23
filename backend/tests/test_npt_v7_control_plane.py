import pytest

from backend.npt_v7.catalog import TOOLS, assessment_catalog, plan_for
from backend.npt_v7.control_plane import Authorization, PolicyProfile, authorize
from backend.npt_v7.state_machine import State, transition


def test_catalog_has_thirteen_assessment_categories_and_fifteen_core_tools():
    assert len(assessment_catalog()) == 13
    assert len(TOOLS) == 15


def test_authorization_requires_matching_scope_and_enabled_tools():
    gate = authorize(
        "network",
        "127.0.0.1",
        Authorization(True, "127.0.0.1"),
        ["nmap"],
        PolicyProfile(),
    )
    assert gate["authorized"] is True
    assert gate["plan"]["planned_tools"] == ["nmap"]


def test_scope_mismatch_is_denied():
    with pytest.raises(PermissionError, match="outside the authorized scope"):
        authorize("network", "127.0.0.1", Authorization(True, "127.0.0.2"), ["nmap"])


def test_disabled_tool_is_denied_even_if_named():
    with pytest.raises((ValueError, PermissionError)):
        authorize("network", "127.0.0.1", Authorization(True, "127.0.0.1"), ["metasploit"])


def test_policy_resource_limits_are_enforced():
    with pytest.raises(PermissionError):
        authorize(
            "network",
            "127.0.0.1",
            Authorization(True, "127.0.0.1"),
            ["nmap"],
            PolicyProfile(max_runtime_seconds=5000),
        )


def test_state_machine_rejects_skipping_gates():
    assert transition(State.CREATED, State.AUTHORIZATION_CHECK) == State.AUTHORIZATION_CHECK
    with pytest.raises(ValueError):
        transition(State.CREATED, State.RUNNING)


def test_category_cannot_request_tool_outside_its_route():
    with pytest.raises(ValueError, match="not permitted"):
        plan_for("network", ["gobuster"])
