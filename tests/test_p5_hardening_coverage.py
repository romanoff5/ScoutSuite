"""P5-Hardening: ensure the independent coverage gate fails under mutation."""
import copy
import json

import pytest

from tools.p5_coverage_matrix import (
    CATALOG, CORRELATOR, MATRIX, RULESET, check, discover_edge_kinds, validate,
)


def inputs():
    return (json.loads(MATRIX.read_text(encoding="utf-8")),
            json.loads(CATALOG.read_text(encoding="utf-8")),
            CORRELATOR.read_text(encoding="utf-8"),
            json.loads(RULESET.read_text(encoding="utf-8")))


def test_p5_hardening_source_derived_gate_is_complete():
    actual = check()
    assert actual["detectors"] == 14
    assert actual["finding_rules"] == 8
    assert actual["scenarios"] >= 53
    assert actual["checked_states"] == 42


def test_new_detector_must_have_positive_negative_unknown_cases():
    manifest, catalog, code, rules = inputs()
    new_code = code.replace(
        "    return paths\n",
        "    paths.append(('new_escalation', 'fake:Action', 'witness'))\n"
        "    return paths\n", 1)
    assert "iam_new_escalation" in discover_edge_kinds(new_code)
    with pytest.raises(AssertionError, match="detector coverage drift"):
        validate(manifest, catalog, new_code, rules)


def test_missing_or_wrong_unknown_case_fails_even_when_detector_is_listed():
    manifest, catalog, code, rules = inputs()
    bad = copy.deepcopy(manifest)
    bad["detectors"]["iam_ec2_profile_mutation"][2] = "iam-ec2-profile-mutation-positive"
    with pytest.raises(AssertionError):
        validate(bad, catalog, code, rules)
    bad = copy.deepcopy(manifest)
    bad["detectors"]["iam_ec2_profile_mutation"][2] = "iam-ec2-profile-mutation-deny"
    with pytest.raises(AssertionError, match="unsafe unknown graph status"):
        validate(bad, catalog, code, rules)


def test_stale_case_reference_or_bad_oracle_does_not_pass():
    manifest, catalog, code, rules = inputs()
    bad = copy.deepcopy(manifest)
    bad["detectors"]["iam_lambda_update"][0] = "fixture-does-not-exist"
    with pytest.raises(AssertionError, match="missing positive fixture"):
        validate(bad, catalog, code, rules)
    malformed = copy.deepcopy(catalog)
    pos = next(c for c in malformed["cases"]
               if c["id"] == "iam-lambda-update-positive")
    pos["expected"]["edges"] = []
    with pytest.raises(AssertionError, match="bad positive edge oracle"):
        validate(manifest, malformed, code, rules)


def test_disabling_new_rule_or_adding_uncovered_rule_fails():
    manifest, catalog, code, rules = inputs()
    bad = copy.deepcopy(rules)
    bad["rules"]["s3-p5d-cross-account-access-point.json"][0]["enabled"] = False
    with pytest.raises(AssertionError, match="finding rule missing"):
        validate(manifest, catalog, code, bad)
    bad = copy.deepcopy(rules)
    bad["rules"]["eks-p5d-new-graph-rule.json"] = [{"enabled": True, "level": "review"}]
    with pytest.raises(AssertionError, match="finding rule missing"):
        validate(manifest, catalog, code, bad)


def test_user_delegation_requires_user_source_and_ecs_agent_review_not_escalation():
    manifest, catalog, code, rules = inputs()
    bad = copy.deepcopy(manifest)
    bad["finding_rules"]["iam-p5d-user-workload-delegation.json"] = "iam-lambda-passrole-allow"
    with pytest.raises(AssertionError, match="incorrectly assigned"):
        validate(bad, catalog, code, rules)
    assert manifest["detectors"]["iam_ecs_execution_role_review"][0] == (
        "ecs-agent-execution-role-review")


def test_new_direct_graph_emitter_in_annotator_must_be_reviewed():
    manifest, catalog, code, rules = inputs()
    modified = code.replace(
        "    return graph\n",
        "    emit('synthetic/source', 'synthetic/target', 'new_direct_edge', "
        "'iam:NotARealAction', 'test-only')\n    return graph\n", 1)
    assert modified != code
    assert "new_direct_edge" in discover_edge_kinds(modified)
    with pytest.raises(AssertionError, match="detector coverage drift"):
        validate(manifest, catalog, modified, rules)
