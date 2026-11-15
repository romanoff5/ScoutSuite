"""P5-Hardening 3: checked-in finding outcomes, identity and fail-closed oracles.

No expected finding is inferred from the production rule engine or its
output: the manifest pins resource paths, real report ARNs and unknown scopes.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOLDENS = ROOT / "tests/data/p5_finding_goldens.json"
CATALOG = ROOT / "tests/data/p5_phase1_synthetic_aws.json"

RULES = (
    "iam-p5d-user-workload-delegation.json",
    "iam-p5d-role-workload-delegation.json",
    "iam-p5d-eks-role-identity.json",
    "eks-p5d-workload-identity.json",
    "s3-p5d-cross-account-bucket.json",
    "s3-p5d-cross-account-access-point.json",
    "kms-p5d-cross-account-key.json",
    "awslambda-p5d-external-privileged-invoke-review.json",
)
NO_SAFE_VERIFICATION = frozenset((
    "CONFIRMED_CONFIGURATION", "NO_MATCH_OBSERVED", "POLICY_VIOLATION",
))
NO_SAFE_OUTCOME = frozenset(("secure", "pass", "safe"))


def load():
    return json.loads(GOLDENS.read_text(encoding="utf-8"))


def validate_manifest(manifest, catalog):
    assert manifest.get("schema") == "scoutsuite-p5-finding-goldens-v1"
    rows = manifest.get("cases")
    assert isinstance(rows, list) and len(rows) == len(catalog["cases"])
    cases = {x["id"]: x for x in catalog["cases"]}
    goldens = {x["id"]: x for x in rows}
    assert len(cases) == len(catalog["cases"])
    assert len(goldens) == len(rows) and set(goldens) == set(cases), (
        "Missing/duplicate finding-golden scenario")
    positive_rules = set()
    for case_id, row in goldens.items():
        expected = cases[case_id]["expected"]
        assert set(row) == {"id", "graph_status", "flagged", "unknown_scope"}
        assert row["graph_status"] == expected["graph_status"], case_id
        assert isinstance(row["flagged"], list)
        assert isinstance(row["unknown_scope"], list)
        if expected["graph_status"] == "partial":
            assert row["unknown_scope"], case_id + " lacks UNKNOWN scope oracle"
        else:
            assert not row["unknown_scope"], case_id
        seen = set()
        for name in ("flagged", "unknown_scope"):
            for item in row[name]:
                assert isinstance(item, dict) and set(item) == (
                    {"rule", "path", "resource_arn"}), (case_id, item)
                assert item["rule"] in RULES, (case_id, item["rule"])
                assert isinstance(item["path"], str) and item["path"]
                assert isinstance(item["resource_arn"], str)
                assert item["resource_arn"].startswith("arn:"), (case_id, item)
                identity = (name, item["rule"], item["path"])
                assert identity not in seen, (case_id, identity)
                seen.add(identity)
                if name == "flagged":
                    positive_rules.add(item["rule"])
        assert len(row["flagged"]) == (0 if not expected["edges"] else
                 0 if all(edge["type"] == "iam_ecs_execution_role_review"
                          for edge in expected["edges"]) else
                 len(expected["edges"]) + sum(
                     edge["type"] in ("eks_irsa_role", "eks_pod_identity")
                     for edge in expected["edges"])), case_id
    assert positive_rules == set(RULES), (
        "Some enabled finding rules lack golden positive findings")
    return goldens


def _under(path, resource):
    return (isinstance(path, str) and (
        path == resource or path.startswith(resource + ".")))


def _entries(finding, expected, case_id, rule):
    items = finding.get("items", [])
    assert isinstance(items, list), (case_id, rule, "invalid items")
    paths = {row["path"] for row in expected}
    matched = set()
    for item in items:
        hits = {path for path in paths if _under(item, path)}
        assert len(hits) == 1, (case_id, rule, "unexpected finding/FP", item)
        matched.update(hits)
    assert matched == paths, (case_id, rule, "missing findings/FN", matched, paths)
    assert len(items) == len(paths), (case_id, rule, "duplicate findings")


def assert_rule_finding(case_id, rule, finding, golden):
    """Same exact checks on in-memory rules and SQLite/HTTP-restored findings."""
    expected = [item for item in golden["flagged"] if item["rule"] == rule]
    unknowns = [item for item in golden["unknown_scope"]
                if item["rule"] == rule]
    _entries(finding, expected, case_id, rule)
    assert finding["flagged_items"] == len(expected), (case_id, rule)
    summary = finding["evaluation_summary"]
    assert summary["counts"]["insecure"] == len(expected), (case_id, rule)
    observations = summary.get("observations", [])
    assert isinstance(observations, list), (case_id, rule)
    cards = finding.get("finding_cards", [])
    assert isinstance(cards, list), (case_id, rule)
    insecure = [x for x in cards if x.get("outcome") == "insecure"]
    assert len(insecure) == len(expected), (case_id, rule, "unexpected cards/FP")
    for item in expected:
        selected = [c for c in insecure if _under(c.get("resource_path"), item["path"])]
        assert len(selected) == 1, (case_id, rule, item["path"])
        card = selected[0]
        assert card.get("resource_arn") == item["resource_arn"], (
            case_id, rule, "real ARN not preserved", card.get("resource_arn"))
        assert card["confidence"] == (
            "LOW" if rule.startswith("awslambda-") else "MEDIUM")
        assert card["verification_status"] == (
            "REVIEW" if rule.startswith("awslambda-") else "POTENTIAL")
        assert card["collection"] in ("COMPLETE", "PARTIAL")
        checks = card.get("supporting_evidence", [])
        assert any(c.get("label") == "Cross-service graph witness"
                   and c.get("state") == "CONFIRMED"
                   and c.get("source", "").startswith("iam.attack_paths_p5d.edges.")
                   for c in checks), (case_id, rule, "provenance missing")
        assert any(c.get("state") == "NOT_VERIFIED" for c in checks)
    # An unsupported/denied API result is not proof of safety. Restrict the
    # assertion to explicitly pinned affected rule/resource scopes so an
    # independent unrelated observation cannot pollute the oracle.
    for item in unknowns:
        affected = [o for o in observations
                    if _under(o.get("resource_path"), item["path"])]
        assert len(affected) == 1, (
            case_id, rule, "UNKNOWN resource not evaluated", item["path"])
        assert affected[0].get("outcome") not in NO_SAFE_OUTCOME, (
            case_id, rule, "UNKNOWN promoted to PASS", affected[0])
        scoped = [c for c in cards if _under(c.get("resource_path"), item["path"])]
        for card in scoped:
            assert card.get("resource_arn") in (None, item["resource_arn"]), (
                case_id, rule, "UNKNOWN ARN changed")
            assert card.get("verification_status") not in NO_SAFE_VERIFICATION
            assert card.get("outcome") not in NO_SAFE_OUTCOME
            assert card.get("confidence") not in ("HIGH",)
    if unknowns and not expected:
        confidence = finding.get("confidence_assessment", {})
        assert confidence.get("verification_status") not in NO_SAFE_VERIFICATION, (
            case_id, rule, "UNKNOWN rule marked verified safe")
    return True


def check():
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    rows = validate_manifest(load(), catalog)
    flagged = sum(len(x["flagged"]) for x in rows.values())
    unknown = sum(len(x["unknown_scope"]) for x in rows.values())
    print("P5 finding goldens: PASS ({} scenarios, {} flagged resource"
          " witnesses, {} UNKNOWN scopes, {} rules)".format(
              len(rows), flagged, unknown, len(RULES)), flush=True)
    return {"cases": len(rows), "flagged": flagged, "unknown": unknown}


if __name__ == "__main__":
    check()
