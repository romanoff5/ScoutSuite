"""P5-Hardening 2: one-fact adversarial transitions, never output-derived oracles.

Every transition mutates *one* pinned collection fact or adds *one* IAM or
resource-policy statement. Expected outcomes come from the checked-in manifest.
This test does not simulate live AWS authorization or exploitation.
"""
import copy
import json
from pathlib import Path

import pytest

from ScoutSuite.providers.aws.resources.iam.attack_paths_p5d import (
    annotate_p5d_attack_paths,
)
from tests.test_p5_phase1_synthetic_aws import (
    CATALOG, CASES, _apply_patch, _p5_fixture, assert_p5_graph_goldens,
)

TRANSITION_PATH = Path(__file__).parent / "data/p5_metamorphic_transitions.json"
MANIFEST = json.loads(TRANSITION_PATH.read_text(encoding="utf-8"))
TRANSITIONS = MANIFEST["transitions"]
BY_ID = {case["id"]: case for case in CASES}


def _scan(case):
    services = _p5_fixture(case)
    return annotate_p5d_attack_paths(
        services, sorted(services), CATALOG["account_id"])


def test_metamorphic_manifest_contract():
    assert MANIFEST["schema"] == "scoutsuite-p5-metamorphic-v1"
    assert len(TRANSITIONS) == 30
    assert len({item["id"] for item in TRANSITIONS}) == len(TRANSITIONS)
    from tools.p5_coverage_matrix import MATRIX
    covered = json.loads(MATRIX.read_text(encoding="utf-8"))["detectors"]
    for kind in covered:
        assert {item["kind"] for item in TRANSITIONS
                if item["edge_type"] == kind} == {"negative", "unknown"}
    assert sum(item["kind"] == "invariant" for item in TRANSITIONS) == 2


@pytest.mark.parametrize("transition", TRANSITIONS,
                         ids=[item["id"] for item in TRANSITIONS])
def test_p5_one_fact_metamorphic_transition(transition):
    base_case = BY_ID[transition["base_case"]]
    kind = transition["edge_type"]
    assert len(base_case["expected"]["edges"]) == 1
    assert base_case["expected"]["edges"][0]["type"] == kind

    # Check input independence: no mutation may touch a second path or
    # modify the persistent base fixture or any other test case.
    original = copy.deepcopy(CATALOG["templates"][base_case["template"]])
    for change in base_case["patches"]:
        _apply_patch(original, change)
    mutated_input = copy.deepcopy(original)
    delta = transition["change"]
    assert isinstance(delta, dict)
    assert set(delta) == {"op", "path", "value"}
    assert delta["op"] in ("set", "append")
    assert isinstance(delta["path"], list) and len(delta["path"]) >= 3
    _apply_patch(mutated_input, delta)
    assert original != mutated_input, transition["id"]

    before = _scan(base_case)
    assert_p5_graph_goldens(before, base_case)
    amended = copy.deepcopy(base_case)
    amended["id"] = transition["id"]
    amended["patches"].append(copy.deepcopy(delta))
    amended["expected"] = {
        "graph_status": transition["expected_graph_status"],
        "collection": {},
        "edges": (copy.deepcopy(base_case["expected"]["edges"])
                  if transition["kind"] == "invariant" else []),
    }
    if "api_status" in base_case["expected"]:
        amended["expected"]["api_status"] = (
            "partial" if delta["path"] == ["api", "failure"]
            else base_case["expected"]["api_status"])
    after = _scan(amended)
    assert_p5_graph_goldens(after, amended)
    if transition["kind"] == "invariant":
        # No new edge and no drift in action, basis, source, confidence or ID.
        assert before["edges"] == after["edges"]
    else:
        # Single changed condition must remove the exact known candidate.
        assert before["edges_count"] == 1
        assert after["edges_count"] == 0
        assert not set(after["edges"]) & set(before["edges"])
        if transition["kind"] == "unknown":
            assert after["status"] == "partial"
        else:
            assert after["status"] == "complete"


def test_agent_execution_role_review_has_distinct_confidence_after_one_fact():
    """Changing only ECS execution role adds REVIEW without escalating task-role."""
    baseline = BY_ID["ecs-task-role-candidate"]
    before = _scan(baseline)
    assert_p5_graph_goldens(before, baseline)
    amended = copy.deepcopy(baseline)
    amended["patches"].append({
        "op": "set",
        "path": ["services", "ecs", "regions", "eu-central-1",
                 "task_definitions", "example", "execution_role_arn"],
        "value": "arn:aws:iam::123456789012:role/Priv",
    })
    amended["expected"] = {"api_status": None}  # overridden by direct assertions
    after = _scan(amended)
    assert after["status"] == "complete"
    assert len(after["edges"]) == 2
    original = next(e for e in after["edges"].values()
                    if e["type"] == "iam_ecs_run_task")
    review = next(e for e in after["edges"].values()
                  if e["type"] == "iam_ecs_execution_role_review")
    assert original == next(iter(before["edges"].values()))
    assert (original["confidence"], original["verification"]) == (
        "MEDIUM", "POTENTIAL")
    assert (review["confidence"], review["verification"]) == ("LOW", "REVIEW")
    assert review["action"] == "ecs:RunTask"
    assert "container access NOT proven" in review["evidence"]["basis"]
    assert review["effective_permission_verified"] is False
    assert review["execution_verified"] is False
