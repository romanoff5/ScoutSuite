"""P5-Hardening 2: prove exact golden oracles and metamorphic gate fail closed."""
import copy
import json

import pytest

from ScoutSuite.providers.aws.resources.iam.attack_paths_p5d import (
    annotate_p5d_attack_paths,
)
from tests.test_p5_phase1_synthetic_aws import (
    CATALOG, CASES, _p5_fixture, assert_p5_graph_goldens,
)
from tools.p5_coverage_matrix import MATRIX, METAMORPHIC, validate_metamorphic


def _positive():
    case = next(row for row in CASES if row["id"] == "iam-lambda-passrole-allow")
    services = _p5_fixture(case)
    graph = annotate_p5d_attack_paths(
        services, sorted(services), CATALOG["account_id"])
    assert_p5_graph_goldens(graph, case)
    return graph, case


@pytest.mark.parametrize("change", [
    "action", "confidence", "basis", "source", "execution", "collection",
])
def test_pinned_golden_rejects_action_confidence_provenance_and_claim_mutations(change):
    graph, baseline = _positive()
    damaged = copy.deepcopy(baseline)
    oracle = damaged["expected"]["edges"][0]
    if change == "action":
        oracle["action"] = "lambda:DeleteFunction"
    elif change == "confidence":
        oracle["confidence"] = "HIGH"
    elif change == "basis":
        oracle["evidence"]["basis"] = "generic unverified guess"
    elif change == "source":
        oracle["evidence"]["source"] = "arn:aws:iam::999999999999:role/Fake"
    elif change == "execution":
        oracle["execution_verified"] = True
    elif change == "collection":
        oracle["collection"] = "unknown"
    with pytest.raises(AssertionError):
        assert_p5_graph_goldens(graph, damaged)


def test_missing_single_fact_transition_is_a_mandatory_gate_failure():
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    manifest = json.loads(METAMORPHIC.read_text(encoding="utf-8"))
    missing = copy.deepcopy(manifest)
    missing["transitions"] = [
        row for row in missing["transitions"]
        if row["id"] != "meta-iam_lambda_update-incomplete"
    ]
    with pytest.raises(AssertionError, match="missing single-fact"):
        validate_metamorphic(matrix, CATALOG, missing)


def test_two_condition_transition_cannot_fake_a_single_change():
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    manifest = json.loads(METAMORPHIC.read_text(encoding="utf-8"))
    broken = copy.deepcopy(manifest)
    broken["transitions"][0]["change"] = {
        "op": "append", "path": ["services", "iam", "roles", "operator"],
        "value": {}, "also_change": "unsafe second modification",
    }
    with pytest.raises(AssertionError):
        validate_metamorphic(matrix, CATALOG, broken)
