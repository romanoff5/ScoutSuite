"""P5-Hardening 3: independent finding oracles and P5-C privacy regressions.

All resource names and ARNs here are synthetic; actual reports are deliberately
not anonymized, while exported P5-C semantic snapshots must be.
"""
import copy
import hashlib
import hmac
import json

import pytest

from ScoutSuite.core import semantic_replay
from ScoutSuite.core.evidence_snapshot import SnapshotError, _canonical
from ScoutSuite.providers.aws.resources.iam.attack_paths_p5d import (
    annotate_p5d_attack_paths,
)
from tests.test_p5_phase1_synthetic_aws import (
    CATALOG, CASES, _p5_fixture, assert_p5_graph_goldens,
)
from tools.p5_finding_goldens import (
    RULES, check, load, validate_manifest, assert_rule_finding,
)

KEY1, KEY2 = b"P" * 32, b"Q" * 32
BY_ID = {row["id"]: row for row in CASES}
GOLDENS = validate_manifest(load(), CATALOG)


def test_independent_finding_manifest_is_complete_and_positive_paths_are_pinned():
    summary = check()
    assert summary == {"cases": 53, "flagged": 18, "unknown": 19}
    assert set(GOLDENS) == set(BY_ID)
    found_rules = {entry["rule"] for case in GOLDENS.values()
                   for entry in case["flagged"]}
    assert found_rules == set(RULES)
    # A real graph edge is intentionally NOT always a finding:
    # ECS execution role is agent-only review, not task privilege escalation.
    candidate = GOLDENS["ecs-agent-execution-role-review"]
    assert candidate["flagged"] == []


@pytest.mark.parametrize("mutation", ["phantom", "missing", "wrong_arn",
                                       "unknown_removed", "unexpected_positive"])
def test_finding_golden_catalog_mutations_fail_closed(mutation):
    bad = copy.deepcopy(load())
    rows = {row["id"]: row for row in bad["cases"]}
    pos = rows["iam-lambda-passrole-allow"]
    if mutation == "phantom":
        pos["flagged"].append({
            "rule": "iam-p5d-role-workload-delegation.json",
            "path": "iam.roles.nonexistent",
            "resource_arn": "arn:aws:iam::123456789012:role/Nonexistent"})
    elif mutation == "missing":
        pos["flagged"].clear()
    elif mutation == "wrong_arn":
        pos["flagged"][0]["resource_arn"] = "not-an-arn"
    elif mutation == "unknown_removed":
        rows["iam-lambda-boundary-unverified"]["unknown_scope"] = []
    else:
        bad["cases"].append(copy.deepcopy(pos))
    with pytest.raises(AssertionError):
        validate_manifest(bad, CATALOG)


@pytest.mark.parametrize("fault", ["false_positive", "missing_finding",
                                   "unknown_marked_pass", "unknown_high",
                                   "changed_resource_arn"])
def test_rule_level_goldens_detect_false_positives_and_unknown_pass(fault):
    pos = GOLDENS["iam-lambda-passrole-allow"]
    path = pos["flagged"][0]["path"]
    arn = pos["flagged"][0]["resource_arn"]
    candidate = {"resource_path": path, "resource_arn": arn,
                 "outcome": "insecure", "confidence": "MEDIUM",
                 "verification_status": "POTENTIAL", "collection": "PARTIAL",
                 "supporting_evidence": [
                     {"label": "Cross-service graph witness", "state": "CONFIRMED",
                      "source": "iam.attack_paths_p5d.edges.abc123"},
                     {"state": "NOT_VERIFIED"}]}
    finding = {
        "items": [path + ".p5d_service_delegation_status"],
        "flagged_items": 1,
        "evaluation_summary": {"counts": {"insecure": 1, "unknown": 0},
                               "observations": []},
        "finding_cards": [candidate],
        "confidence_assessment": {"verification_status": "POTENTIAL"},
    }
    if fault == "false_positive":
        finding["items"].append("iam.roles.attacker.p5d_service_delegation_status")
    elif fault == "missing_finding":
        finding["items"].clear()
    elif fault == "changed_resource_arn":
        candidate["resource_arn"] = "arn:aws:iam::123456789012:role/Wrong"
    else:
        # Negative/unknown regression must not be mislabeled as clean PASS.
        pos = GOLDENS["iam-lambda-boundary-unverified"]
        unknown_path = pos["unknown_scope"][0]["path"]
        finding = {
            "items": [], "flagged_items": 0,
            "evaluation_summary": {
                "counts": {"insecure": 0, "unknown": 1},
                "observations": [{"resource_path": unknown_path, "outcome": "unknown"}]},
            "finding_cards": [{
                "resource_path": unknown_path, "outcome": "unknown",
                "resource_arn": pos["unknown_scope"][0]["resource_arn"],
                "confidence": "UNKNOWN", "verification_status": "UNKNOWN"}],
            "confidence_assessment": {"verification_status": "UNKNOWN"},
        }
        if fault == "unknown_marked_pass":
            finding["evaluation_summary"]["observations"][0]["outcome"] = "secure"
        else:
            finding["finding_cards"][0]["confidence"] = "HIGH"
    with pytest.raises(AssertionError):
        assert_rule_finding(
            "iam-lambda-boundary-unverified" if fault.startswith("unknown")
            else "iam-lambda-passrole-allow",
            "iam-p5d-role-workload-delegation.json", finding, pos)


@pytest.mark.parametrize("case_id", [
    "iam-lambda-passrole-allow",
    "iam-user-lambda-delegation-positive",
    "eks-irsa-exact-issuer-aud-sub",
    "eks-podidentity-list-describe-complete",
    "s3-govcloud-partition",
    "s3-access-point-external-positive",
    "kms-key-policy-external-decrypt",
    "kms-grant-unconstrained",
    "lambda-external-invoke-review",
    "s3-bucket-policy-accessdenied",
    "iam-lambda-boundary-unverified",
])
def test_full_p5d_source_never_leaks_into_p5c_semantic_snapshot(case_id):
    case = BY_ID[case_id]
    services = _p5_fixture(case)
    graph = annotate_p5d_attack_paths(
        services, sorted(services), CATALOG["account_id"])
    assert_p5_graph_goldens(graph, case)
    marker = "CLIENT_NEVER_EXPORT_PRIVATE_POLICY_BODY_92XA"
    services["iam"]["p5d_private_notes"] = {
        "raw_iam_policy": {"Statement": [{"Resource": marker}]},
        "aws_account": "123456789012",
        "canary": "arn:aws:iam::123456789012:role/KeepRealInReports",
    }
    source = {
        "report_schema_version": 1,
        "account_id": CATALOG["account_id"],
        "services": services,
        "collection_status": {
            "status": "success" if graph["status"] == "complete" else "partial",
            "complete": graph["status"] == "complete",
            "issues": [],
        },
    }
    before = copy.deepcopy(source)
    snapshot = semantic_replay.export_semantic_facts(source, KEY1)
    snapshot_again = semantic_replay.export_semantic_facts(source, KEY1)
    assert snapshot == snapshot_again
    assert source == before, "P5-C changed the non-anonymized Scout report"
    assert graph["edges"] == before["services"]["iam"]["attack_paths_p5d"]["edges"]
    dump = json.dumps(snapshot, sort_keys=True)
    for secret in (
        marker, "CLIENT_NEVER_EXPORT", "123456789012",
        "999999999999", "arn:", "role/Priv", "role/Operator",
        "accesspoint/synthetic", "task-definition/example",
        "reports/P5DObjectWitness", "KeepRealInReports",
        "oidc.eks.eu-central-1.amazonaws.com",
    ):
        assert secret not in dump, (case_id, secret)
    assert len(snapshot["rules"]) == len(semantic_replay.ADAPTERS) == 27
    for rule, record in snapshot["rules"].items():
        assert set(record) == {"source_rule_sha256", "scope",
                               "source_assessment_status", "facts"}
        for fact in record["facts"]:
            assert set(fact) == {"token", "value"}
            assert semantic_replay.HMAC_RE.fullmatch(fact["token"]), rule
            assert fact["value"] in semantic_replay.ADAPTERS[rule].allowed
    result = semantic_replay.replay_semantic_facts(snapshot, KEY1)
    assert result["snapshot_verified"] is True
    assert result["cloud_api_calls"] == 0
    assert result["raw_resource_identifiers_available"] is False
    assert result["effective_permission_verified"] is False
    assert result["compliance_verified"] is False
    if graph["status"] == "partial":
        assert snapshot["source_collection_status"] == "incomplete"
        assert all(record["status"] != "replayed"
                   for record in result["rules"].values())


def test_p5c_identity_key_changes_hmac_not_real_source_identifiers():
    case = BY_ID["iam-lambda-passrole-allow"]
    services = _p5_fixture(case)
    annotate_p5d_attack_paths(services, sorted(services), CATALOG["account_id"])
    source = {"account_id": CATALOG["account_id"],
              "report_schema_version": 1,
              "services": services,
              "collection_status": {"complete": True, "status": "success"}}
    original = copy.deepcopy(source)
    first = semantic_replay.export_semantic_facts(source, KEY1)
    second = semantic_replay.export_semantic_facts(source, KEY2)
    assert first["key_id"] != second["key_id"]
    assert first["integrity"] != second["integrity"]
    tokens_a = {r: [f["token"] for f in row["facts"]]
                for r, row in first["rules"].items() if row["facts"]}
    tokens_b = {r: [f["token"] for f in row["facts"]]
                for r, row in second["rules"].items() if row["facts"]}
    assert tokens_a and tokens_b and tokens_a != tokens_b
    assert source == original
    with pytest.raises(SnapshotError):
        semantic_replay.replay_semantic_facts(first, KEY2)


@pytest.mark.parametrize("malicious_field", ["token", "value", "extra"])
def test_even_validly_resigned_semantic_snapshot_rejects_raw_identity_injection(
        malicious_field):
    case = BY_ID["iam-lambda-passrole-allow"]
    source = {"account_id": CATALOG["account_id"],
              "report_schema_version": 1,
              "services": _p5_fixture(case),
              "collection_status": {"complete": True, "status": "success"}}
    snapshot = semantic_replay.export_semantic_facts(source, KEY1)
    item = next(row for row in snapshot["rules"].values() if row["facts"])["facts"][0]
    if malicious_field == "token":
        item["token"] = "arn:aws:iam::123456789012:role/Priv"
    elif malicious_field == "value":
        item["value"] = "arn:aws:iam::123456789012:role/Priv"
    else:
        item["raw_arn"] = "arn:aws:iam::123456789012:role/Priv"
    body = {k: v for k, v in snapshot.items() if k != "integrity"}
    raw = _canonical(body)
    snapshot["integrity"] = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "hmac_sha256": hmac.new(
            KEY1, b"scoutsuite-p4f2-v1\x00" + raw, hashlib.sha256).hexdigest(),
    }
    with pytest.raises(SnapshotError):
        semantic_replay.replay_semantic_facts(snapshot, KEY1)
