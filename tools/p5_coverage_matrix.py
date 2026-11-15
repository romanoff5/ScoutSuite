"""P5-Hardening: offline, fail-closed detector/fixture coverage gate.

Independent inputs: Python AST of the production correlator, AWS ruleset
definitions, checked-in case oracles and a reviewed case-ID matrix.
No AWS credentials, network access, or importing production detectors.
"""
import argparse
import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORRELATOR = ROOT / "ScoutSuite/providers/aws/resources/iam/attack_paths_p5d.py"
CATALOG = ROOT / "tests/data/p5_phase1_synthetic_aws.json"
MATRIX = ROOT / "tests/data/p5_detector_coverage.json"
METAMORPHIC = ROOT / "tests/data/p5_metamorphic_transitions.json"
RULESET = ROOT / "ScoutSuite/providers/aws/rules/rulesets/default.json"
STATUSES = ("positive", "negative", "unknown")


def discover_edge_kinds(code):
    """Read all statically enumerable P5-D emitters without executing AWS code.

    A new dynamic/unparseable emitter is a gate failure, never silently omitted.
    """
    tree = ast.parse(code)
    functions = {node.name: node for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    required = {"_workload_routes", "_eks_routes", "_resource_routes",
                "annotate_p5d_attack_paths"}
    assert required <= functions.keys(), "P5-D emitter entrypoint changed"
    routes = functions["_workload_routes"]
    services = set()
    for node in ast.walk(routes):
        if isinstance(node, ast.For) and isinstance(node.target, ast.Tuple):
            names = [part.id for part in node.target.elts if isinstance(part, ast.Name)]
            if names == ["service", "principal", "action"]:
                values = ast.literal_eval(node.iter)
                services.update(row[0] for row in values)
    assert services, "No service creation emitters found"

    kinds = set()
    dynamic = 0
    for node in ast.walk(routes):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "paths" and node.func.attr == "append"):
            continue
        assert len(node.args) == 1 and isinstance(node.args[0], ast.Tuple)
        expression = node.args[0].elts[0]
        if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
            kinds.add("iam_" + expression.value)
        elif (isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add)
              and isinstance(expression.left, ast.Name)
              and expression.left.id == "service"
              and isinstance(expression.right, ast.Constant)
              and isinstance(expression.right.value, str)):
            kinds.update("iam_" + service + expression.right.value
                         for service in services)
        else:
            raise AssertionError("Unrecognized P5-D workload emitter: "
                                 + ast.dump(expression))
    # Discover every callsite, including direct emitters added to the main
    # graph function. Do not silently omit a future new detector there.
    bridges = 0
    for function in ("_eks_routes", "_resource_routes",
                     "annotate_p5d_attack_paths"):
        for node in ast.walk(functions[function]):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "emit"):
                continue
            assert len(node.args) >= 3, "P5-D emit without graph kind"
            expr = node.args[2]
            if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
                kinds.add(expr.value)
            elif (function == "annotate_p5d_attack_paths"
                  and isinstance(expr, ast.BinOp)
                  and isinstance(expr.op, ast.Add)
                  and isinstance(expr.left, ast.Constant)
                  and expr.left.value == "iam_"
                  and isinstance(expr.right, ast.Name)
                  and expr.right.id == "service"):
                bridges += 1
            else:
                raise AssertionError(
                    "Unreviewed dynamic P5-D graph kind in " + function)
    assert bridges == 1, "Workload->IAM edge binding changed"
    assert len(kinds) > 0, "No P5-D detectors discovered"
    return kinds


def validate(matrix, catalog, code, ruleset):
    """Reject any missing detector, state, case, rule or contradictory oracle."""
    assert matrix.get("schema") == "scoutsuite-p5-detector-coverage-v1"
    assert catalog.get("schema") == "scoutsuite-p5-synthetic-aws-v1"
    cases = catalog.get("cases", [])
    assert isinstance(cases, list) and cases
    by_id = {row["id"]: row for row in cases}
    assert len(by_id) == len(cases), "Duplicate P5 scenario IDs"
    expected_types = discover_edge_kinds(code)
    detectors = matrix.get("detectors")
    assert isinstance(detectors, dict) and set(detectors) == expected_types, (
        "P5 detector coverage drift; uncovered=" +
        str(sorted(expected_types - set(detectors or {}))) + " obsolete=" +
        str(sorted(set(detectors or {}) - expected_types)))
    for kind, witness_ids in sorted(detectors.items()):
        assert isinstance(witness_ids, list) and len(witness_ids) == 3, (
            kind + " must pin positive/negative/unknown")
        assert len(set(witness_ids)) == 3, kind + " reuses a witness"
        for state, case_id in zip(STATUSES, witness_ids):
            assert case_id in by_id, kind + " missing " + state + " fixture " + case_id
            case = by_id[case_id]
            actual = case["expected"]
            linked = [row for row in actual["edges"] if row["type"] == kind]
            assert (bool(linked) if state == "positive" else not linked), (
                kind + " bad " + state + " edge oracle in " + case_id)
            assert actual["graph_status"] == (
                "partial" if state == "unknown" else "complete"), (
                kind + " unsafe " + state + " graph status in " + case_id)
            assert state == "positive" or case["patches"], (
                kind + " requires independently changed negative/unknown facts")

    enabled = {name for name, definitions in ruleset["rules"].items()
               if "-p5d-" in name and any(item.get("enabled") is True
                                            for item in definitions)}
    all_p5 = {name for name in ruleset["rules"] if "-p5d-" in name}
    rules = matrix.get("finding_rules")
    assert isinstance(rules, dict) and set(rules) == all_p5 == enabled, (
        "P5 finding rule missing/disabled/uncovered: " + repr(
            (all_p5 - set(rules or {}), set(rules or {}) - all_p5,
             all_p5 - enabled)))
    for rule, case_id in sorted(rules.items()):
        assert case_id in by_id, rule + " has no positive case"
        links = by_id[case_id]["expected"]["edges"]
        assert links, rule + " does not lead to a finding"
        assert (
            any(e["type"].startswith("iam_") and ":user/" in e["source"]
                and e["type"] != "iam_ecs_execution_role_review" for e in links)
            if rule == "iam-p5d-user-workload-delegation.json" else
            any(e["type"].startswith("iam_") and ":role/" in e["source"]
                and e["type"] != "iam_ecs_execution_role_review" for e in links)
            if rule == "iam-p5d-role-workload-delegation.json" else
            any(e["type"].startswith("eks_") for e in links)
            if rule in ("iam-p5d-eks-role-identity.json",
                        "eks-p5d-workload-identity.json") else
            any(e["type"] == "s3_cross_account_resource_policy" for e in links)
            if rule == "s3-p5d-cross-account-bucket.json" else
            any(e["type"] == "s3_access_point_cross_account" for e in links)
            if rule == "s3-p5d-cross-account-access-point.json" else
            any(e["type"].startswith("kms_") for e in links)
            if rule == "kms-p5d-cross-account-key.json" else
            any(e["type"] == "lambda_external_invoke_review" for e in links)
            if rule == "awslambda-p5d-external-privileged-invoke-review.json"
            else False
        ), rule + " incorrectly assigned positive fixture " + case_id
    # Reject silently introduced oracle detector kinds, even when unrelated
    # to this gate's explicit witness case selection.
    observed = {edge["type"] for case in cases for edge in case["expected"]["edges"]}
    assert observed <= expected_types, "Orphan or obsolete fixture kinds"
    # The graph oracle pins every observable edge field. No test may use
    # runtime-generated action/provenance/confidence as its own oracle.
    required = {"type", "source", "target", "action", "verification",
                "confidence", "collection", "effective_permission_verified",
                "execution_verified", "evidence"}
    golden_count = 0
    for case in cases:
        for edge in case["expected"]["edges"]:
            assert set(edge) == required, "Incomplete P5 edge golden: " + case["id"]
            provenance = edge["evidence"]
            assert set(provenance) == {"source", "resource", "basis"}
            assert provenance["source"] == edge["source"]
            assert provenance["resource"] == edge["target"]
            assert isinstance(provenance["basis"], str) and provenance["basis"]
            assert isinstance(edge["action"], str) and edge["action"]
            assert edge["confidence"] == (
                "LOW" if edge["verification"] == "REVIEW" else "MEDIUM")
            assert edge["collection"] == "complete"
            assert edge["effective_permission_verified"] is False
            assert edge["execution_verified"] is False
            golden_count += 1
    return {
        "detectors": len(detectors),
        "finding_rules": len(rules),
        "scenarios": len(cases),
        "checked_states": len(detectors) * len(STATUSES),
        "golden_edges": golden_count,
    }


def validate_metamorphic(matrix, catalog, manifest):
    """Every active P5 graph kind requires a single-fact negative and UNKNOWN transition."""
    assert manifest.get("schema") == "scoutsuite-p5-metamorphic-v1"
    cases = {case["id"]: case for case in catalog["cases"]}
    transitions = manifest.get("transitions")
    assert isinstance(transitions, list) and len(transitions) >= 28
    assert len({tr["id"] for tr in transitions}) == len(transitions)
    coverage = {kind: set() for kind in matrix["detectors"]}
    for tr in transitions:
        kind = tr["edge_type"]
        assert kind in coverage, "Unknown metamorphic detector: " + kind
        category = tr["kind"]
        assert category in ("negative", "unknown", "invariant")
        assert category not in coverage[kind], "Repeated metamorphic transition"
        coverage[kind].add(category)
        assert tr["base_case"] in cases, "Metamorphic base missing"
        base = cases[tr["base_case"]]
        assert len(base["expected"]["edges"]) == 1
        assert base["expected"]["edges"][0]["type"] == kind
        assert tr["expected_graph_status"] == (
            "partial" if category == "unknown" else "complete")
        delta = tr["change"]
        assert isinstance(delta, dict) and set(delta) == {"op", "path", "value"}
        assert delta["op"] in ("set", "append")
        assert isinstance(delta["path"], list) and len(delta["path"]) >= 3
        assert delta["path"][0] in ("services", "api")
    for kind, states in coverage.items():
        assert {"negative", "unknown"} <= states, (
            kind + " missing single-fact negative/UNKNOWN transition")
    return len(transitions)


def check():
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    result = validate(matrix, catalog,
                      CORRELATOR.read_text(encoding="utf-8"),
                      json.loads(RULESET.read_text(encoding="utf-8")))
    result["metamorphic_transitions"] = validate_metamorphic(
        matrix, catalog, json.loads(METAMORPHIC.read_text(encoding="utf-8")))
    print("P5 detector coverage: PASS (" +
          ", ".join(str(value) + " " + key for key, value in result.items()) +
          ")", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", required=True)
    parser.parse_args()
    check()


if __name__ == "__main__":
    main()
