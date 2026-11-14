"""P4-F: authenticated anonymized evidence snapshots; synthetic data only."""
import copy
import importlib.util
import json
import os
import stat
from pathlib import Path

import pytest

from ScoutSuite.core.evidence_snapshot import (
    SnapshotError, diff_evidence_snapshots, export_evidence_snapshot,
    verify_evidence_snapshot,
)


KEY = b"\x15" * 32
KEY2 = b"\x23" * 32
ROOT = Path(__file__).resolve().parents[1]
RULE = "ec2-instance-imdsv1-enabled"


def report(*, flagged=True, unknown=True):
    resource = "ec2.regions.eu-central-1.vpcs.vpc-s3cr3t.instances.i-client-secret"
    findings = {RULE: {
        "items": [resource] if flagged else [],
        "flagged_items": int(flagged),
        "checked_items": 2,
        "assessment_status": "incomplete" if unknown else "evaluated",
        "evaluation_summary": {
            "assessment_status": "incomplete" if unknown else "evaluated",
            "counts": {"secure": int(not flagged), "insecure": int(flagged),
                       "unknown": int(unknown), "not_applicable": 0},
            "unknown_resources": [resource + ".missing"] if unknown else [],
            "compliance_verified": False,
        },
    }}
    return {
        "report_schema_version": 1,
        "account_id": "123456789012",
        "credentials": {"aws_secret_access_key": "NEVER_COPY_SECRET"},
        "profile": "/Users/Customer/acme-private",
        "services": {"ec2": {"findings": findings,
                             "regions": {"eu-central-1": {
                                 "config": "PRIVATE_DNS_NAME_TOKEN",
                                 "SecurityGroup": "PRIVATE_GROUP_NAME_TOKEN"}}}},
        "collection_status": {"complete": not unknown,
                              "status": "partial" if unknown else "success",
                              "issues": [{"status": "denied", "scope": "ec2",
                                          "reason_code": "AWS_REPORTED_PRIVATE_REASON",
                                          "region": "eu-central-1"}] if unknown else []},
    }


def _summary(snapshot):
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":"))


def test_export_privacy_no_original_identifiers_or_sensitive_configuration():
    source = report()
    snapshot = export_evidence_snapshot(source, KEY)
    exported = _summary(snapshot)
    for secret in ("123456789012", "NEVER_COPY_SECRET", "vpc-s3cr3t",
                   "i-client-secret", "AWS_REPORTED_PRIVATE_REASON",
                   "PRIVATE_DNS_NAME_TOKEN", "PRIVATE_GROUP_NAME_TOKEN",
                   "acme-private", "Client"):
        assert secret not in exported
    assert snapshot["format"] == "scoutsuite-evidence-snapshot"
    assert snapshot["key_id"] != "123456789012"
    assert snapshot["collection"]["complete"] is False
    assert snapshot["collection"]["issues"][0]["reason_token"].startswith("hmac:")
    assert source["services"]["ec2"]["findings"][RULE]["items"]  # no mutations


def test_same_key_and_different_dict_order_produce_identical_signed_snapshot():
    first = report()
    second = copy.deepcopy(first)
    second["services"] = dict(reversed(list(second["services"].items())))
    snap = export_evidence_snapshot(first, KEY)
    assert snap == export_evidence_snapshot(second, KEY)
    assert verify_evidence_snapshot(snap, KEY)["snapshot_verified"] is True


def test_changed_key_changes_tokens_and_cannot_verify_old_snapshot():
    old = export_evidence_snapshot(report(), KEY)
    new = export_evidence_snapshot(report(), KEY2)
    assert old["key_id"] != new["key_id"]
    assert old["findings"]["ec2"][RULE]["flagged_identity_tokens"] != new["findings"]["ec2"][RULE]["flagged_identity_tokens"]
    with pytest.raises(SnapshotError):
        verify_evidence_snapshot(old, KEY2)
    with pytest.raises(SnapshotError):
        diff_evidence_snapshots(old, new, KEY)


@pytest.mark.parametrize("path,value", [
    (("findings", "ec2", RULE, "flagged_items"), 0),
    (("findings", "ec2", RULE, "assessment_status"), "passed"),
    (("collection", "complete"), True),
    (("integrity", "sha256"), "0" * 64),
])
def test_mutation_is_rejected_even_when_metadata_looks_harmless(path, value):
    snapshot = export_evidence_snapshot(report(), KEY)
    branch = snapshot
    for key in path[:-1]:
        branch = branch[key]
    branch[path[-1]] = value
    with pytest.raises(SnapshotError):
        verify_evidence_snapshot(snapshot, KEY)


def test_missing_evidence_is_not_pass_and_missing_collection_is_incomplete():
    src = report()
    del src["services"]["ec2"]["findings"][RULE]["evaluation_summary"]
    del src["collection_status"]
    result = export_evidence_snapshot(src, KEY)
    row = result["findings"]["ec2"][RULE]
    assert row["evidence_status"] == "unavailable"
    assert row["evidence_counts"] is None
    assert result["collection"]["complete"] is False
    assert verify_evidence_snapshot(result, KEY)["rules_with_unknown_evidence"] == 1


def test_false_evaluated_claim_with_unknown_data_fails_closed():
    source = report()
    source["services"]["ec2"]["findings"][RULE]["evaluation_summary"]["assessment_status"] = "evaluated"
    with pytest.raises(SnapshotError):
        export_evidence_snapshot(source, KEY)


@pytest.mark.parametrize("change", [
    lambda s: s["services"]["ec2"]["findings"][RULE].update(flagged_items=2),
    lambda s: s["services"]["ec2"]["findings"][RULE].update(items=[{"secret": "bad"}]),
    lambda s: s["services"]["ec2"]["findings"][RULE]["evaluation_summary"]["counts"].update(unknown=-1),
    lambda s: s["services"].update({"MyClientSecret": {"findings": {}}}),
    lambda s: s["services"]["ec2"]["findings"].update({"veryprivate.customer.rule": {
        "items": [], "flagged_items": 0}}),
])
def test_invalid_report_fails_closed_without_raw_export(change):
    source = report()
    change(source)
    if "veryprivate.customer.rule" in source["services"]["ec2"]["findings"]:
        # This is a syntactically acceptable custom rule name and MUST be HMACed.
        out = export_evidence_snapshot(source, KEY)
        assert "veryprivate.customer.rule" not in _summary(out)
    else:
        with pytest.raises(SnapshotError):
            export_evidence_snapshot(source, KEY)


def test_snapshot_diff_new_resolved_and_incomplete_status():
    before = export_evidence_snapshot(report(flagged=True, unknown=True), KEY)
    after = export_evidence_snapshot(report(flagged=False, unknown=False), KEY)
    diff = diff_evidence_snapshots(before, after, KEY)
    assert len(diff["changes"]) == 1
    change = diff["changes"][0]
    assert len(change["resolved_tokens"]) == 1
    assert change["new_tokens"] == []
    assert change["observation_status_before"] == "incomplete"
    assert change["observation_status_after"] == "evaluated"
    assert change["rule"] == RULE
    assert "i-client-secret" not in _summary(diff)


def test_rule_definition_drift_never_means_reexecuted_rule(monkeypatch):
    from ScoutSuite.core import evidence_snapshot as engine
    snapshot = export_evidence_snapshot(report(), KEY)
    real = engine._rule_definition_digest
    monkeypatch.setattr(engine, "_rule_definition_digest",
                        lambda k: "e" * 64 if k == RULE else real(k))
    result = verify_evidence_snapshot(snapshot, KEY)
    assert result["replay_status"] == "rule_definition_drift"
    assert result["rule_conditions_reexecuted"] is False
    assert result["rules_with_changed_definitions"] == ["ec2." + RULE]


def test_unknown_custom_rule_name_is_not_serialized_or_claimed_verified():
    source = report()
    source["services"]["ec2"]["findings"]["customer-private-name"] = {
        "flagged_items": 0, "items": [], "assessment_status": "unknown"}
    snapshot = export_evidence_snapshot(source, KEY)
    assert "customer-private-name" not in _summary(snapshot)
    result = verify_evidence_snapshot(snapshot, KEY)
    assert result["replay_status"] == "rule_definition_unavailable"
    assert result["rules_with_unavailable_definitions"]


def test_cli_init_key_export_replay_and_diff_are_offline_and_private(tmp_path, capsys):
    # Import CLI without launching a subprocess or loading AWS clients.
    spec = importlib.util.spec_from_file_location("p4f_cli", ROOT / "tools/p4f_evidence.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    key = tmp_path / "identity.snapshot-key"
    result_file = tmp_path / "RESULTS.js"
    result_file.write_text("scoutsuite_results =\n" + json.dumps(report()) + ";\n",
                           encoding="utf-8")
    snapshot_file = tmp_path / "snapshot.json"
    assert mod.main(["init-key", "--key-file", str(key)]) == 0
    assert key.stat().st_size == 32
    if os.name != "nt":
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert mod.main(["export", "--report", str(result_file),
                     "--output", str(snapshot_file), "--key-file", str(key)]) == 0
    assert mod.main(["export", "--report", str(result_file),
                     "--output", str(snapshot_file), "--key-file", str(key)]) == 3
    assert mod.main(["replay", "--snapshot", str(snapshot_file),
                     "--key-file", str(key)]) == 0
    assert mod.main(["diff", "--before", str(snapshot_file), "--after", str(snapshot_file),
                     "--key-file", str(key)]) == 0
    exposed = capsys.readouterr()
    for secret in ("123456789012", "PRIVATE_DNS_NAME_TOKEN",
                   "AWS_REPORTED_PRIVATE_REASON", "vpc-s3cr3t",
                   "identity.snapshot-key", "i-client-secret"):
        assert secret not in exposed.out + exposed.err


def test_cli_rejects_raw_js_code_and_never_executes_it(tmp_path, capsys):
    spec = importlib.util.spec_from_file_location("p4f_cli_bad", ROOT / "tools/p4f_evidence.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    source = tmp_path / "poison.js"
    source.write_text("scoutsuite_results = eval('private-code');")
    secret = tmp_path / "secret.snapshot-key"
    secret.write_bytes(KEY)
    if os.name != "nt":
        secret.chmod(0o600)
    assert mod.main(["export", "--report", str(source),
                     "--key-file", str(secret),
                     "--output", str(tmp_path / "out.json")]) == 3
    assert "private-code" not in capsys.readouterr().err
