"""P4-F2: semantic AWS replay runs Scout's actual JSON predicates offline.

All source IDs are synthetic and never leave the explicit allowlist projection.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path

import pytest

from ScoutSuite.core.evidence_snapshot import SnapshotError
from ScoutSuite.core import semantic_replay as engine

KEY = b"1" * 32
OTHER_KEY = b"2" * 32
ROOT = Path(__file__).resolve().parents[1]
NAMES = frozenset(engine.ADAPTERS)


def report(*, complete=True):
    return {
        "report_schema_version": 1,
        "account_id": "123456789012",
        "credentials": "SYNTHETIC_SECRET_DO_NOT_LEAK",
        "metadata_path": "SYNTHETIC_CLIENT_PRIVATE_PATH",
        "services": {
            "ec2": {
                "regions": {
                    "eu-central-1": {
                        "vpcs": {
                            "vpc-private": {
                                "instances": {
                                    "i-secret-instance": {"imds_v2_status": "optional",
                                                          "arn": "arn:aws:ec2:eu-central-1:123456789012:instance/i-secret-instance",
                                                          "name": "PrivateCustomerInstance"},
                                    "i-secure-instance": {"imds_v2_status": "required"},
                                }
                            }
                        },
                        "regional_settings": {
                            "0": {"account_imds_default_status": "not_required",
                                  "account_imds_defaults": {"HttpTokens": "optional"}}
                        }
                    }
                },
                "findings": {},
            },
            "cloudwatch": {
                "regions": {
                    "eu-central-1": {
                        "log_groups": {
                            "client-log": {"retention_status": "unlimited",
                                           "customer_kms_status": "aws_managed",
                                           "name": "private-client-log"},
                            "other-log": {"retention_status": "configured",
                                          "customer_kms_status": "customer_kms"},
                        }
                    }
                },
                "findings": {},
            },
            "rds": {
                "regions": {
                    "eu-central-1": {
                        "proxies": {
                            "private-db-proxy": {"tls_status": "disabled",
                                                 "arn": "arn:aws:rds:eu-central-1:123456789012:db-proxy:secret"},
                            "secure-db-proxy": {"tls_status": "enabled"},
                        }
                    }
                },
                "findings": {},
            }
        },
        "collection_status": {
            "complete": complete, "status": "success" if complete else "partial",
            "issues": [] if complete else [{"status": "denied", "scope": "ec2",
                                            "reason_code": "AccessDenied"}],
        },
    }


def export(source=None):
    return engine.export_semantic_facts(source if source is not None else report(), KEY)


def test_export_signed_privacy_stable_and_normal_report_unchanged():
    original = report()
    before = copy.deepcopy(original)
    snap = export(original)
    body = json.dumps(snap, sort_keys=True)
    for private in ("123456789012", "SYNTHETIC_SECRET_DO_NOT_LEAK",
                    "SYNTHETIC_CLIENT_PRIVATE_PATH", "vpc-private",
                    "i-secret-instance", "PrivateCustomerInstance",
                    "private-client-log", "arn:aws", "private-db-proxy"):
        assert private not in body
    assert original == before
    assert original["services"]["ec2"]["regions"]["eu-central-1"]["vpcs"][
        "vpc-private"]["instances"]["i-secret-instance"]["arn"].startswith("arn:aws")
    assert len(snap["rules"]) == 5
    assert export(before) == snap
    for record in snap["rules"].values():
        assert all(fact["token"].startswith("hmac:") for fact in record["facts"])


def test_replay_current_actual_rule_conditions_all_five():
    snapshot = export()
    replay = engine.replay_semantic_facts(snapshot, KEY)
    assert replay["snapshot_verified"] is True
    assert replay["cloud_api_calls"] == 0
    assert replay["raw_resource_identifiers_available"] is False
    assert replay["compliance_verified"] is False
    assert set(replay["rules"]) == NAMES
    for name, row in replay["rules"].items():
        assert row["status"] == "replayed", name
        assert row["conditions_reexecuted"] is True
        assert row["predicate_changed"] is False
        assert row["unknown"] == 0
        assert row["checked"] > 0
        assert len(row["matched_tokens"]) == 1, name


def test_changed_supported_predicate_is_actually_reexecuted(monkeypatch):
    snapshot = export()
    real = engine._expected_rule
    name = "ec2-instance-imdsv1-enabled"

    def changed(rule_name):
        definition, sha = real(rule_name)
        if rule_name == name:
            definition = copy.deepcopy(definition)
            definition["conditions"][1][2] = "required"  # invert which instance is flagged
            return definition, "e" * 64
        return definition, sha

    monkeypatch.setattr(engine, "_expected_rule", changed)
    replay = engine.replay_semantic_facts(snapshot, KEY)
    result = replay["rules"][name]
    assert result["predicate_changed"] is True
    assert result["conditions_reexecuted"] is True
    assert result["status"] == "replayed"
    assert len(result["matched_tokens"]) == 1
    old_value = engine._synthetic_info(
        engine.ADAPTERS[name], snapshot["rules"][name]["facts"][0]["token"], "optional")
    assert isinstance(old_value, dict)
    # Confirm changed JSON condition selects a *different* pseudonymized instance.
    monkeypatch.setattr(engine, "_expected_rule", real)
    original = engine.replay_semantic_facts(snapshot, KEY)["rules"][name]
    assert result["matched_tokens"] != original["matched_tokens"]


@pytest.mark.parametrize("change", [
    lambda definition: definition.update(path="ec2.regions.id.vpcs.id.instances.id.arn"),
    lambda definition: definition.update(conditions=["or", ["this", "equal", "optional"]]),
    lambda definition: definition.update(conditions=["and", ["arn", "equal", "PRIVATE"]]),
    lambda definition: definition.update(conditions=["and", ["this", "match", ".*"]]),
])
def test_unsupported_changed_predicate_never_appears_as_safe(monkeypatch, change):
    snap = export()
    real = engine._expected_rule

    def mutated(rule_name):
        definition, sha = real(rule_name)
        if rule_name == "ec2-instance-imdsv1-enabled":
            definition = copy.deepcopy(definition)
            change(definition)
            return definition, "f" * 64
        return definition, sha

    monkeypatch.setattr(engine, "_expected_rule", mutated)
    result = engine.replay_semantic_facts(snap, KEY)["rules"]["ec2-instance-imdsv1-enabled"]
    assert result["status"] == "rule_not_replayable"
    assert result["conditions_reexecuted"] is False
    assert result["matched_tokens"] == []
    assert result["predicate_changed"] is True


def test_unknown_fact_and_collection_denied_never_return_clean_replay():
    source = report(complete=False)
    resource = source["services"]["ec2"]["regions"]["eu-central-1"]["vpcs"][
        "vpc-private"]["instances"]["i-secret-instance"]
    del resource["imds_v2_status"]
    snap = export(source)
    result = engine.replay_semantic_facts(snap, KEY)
    for row in result["rules"].values():
        assert row["status"] == "partial"
    assert result["rules"]["ec2-instance-imdsv1-enabled"]["unknown"] == 1


def test_uncollected_service_is_unknown_not_zero_resources():
    source = report()
    del source["services"]["rds"]
    snap = export(source)
    record = snap["rules"]["rds-proxy-require-tls-disabled"]
    assert record["scope"] == "partial"
    assert record["facts"] == []
    result = engine.replay_semantic_facts(snap, KEY)
    assert result["rules"]["rds-proxy-require-tls-disabled"]["status"] == "partial"


@pytest.mark.parametrize("tamper", [
    lambda s: s["rules"]["ec2-instance-imdsv1-enabled"]["facts"][0].update(
        value="optional" if s["rules"]["ec2-instance-imdsv1-enabled"]["facts"][0]["value"] != "optional"
        else "required"),
    lambda s: s["rules"]["rds-proxy-require-tls-disabled"]["facts"][0].update(
        token="hmac:" + "0" * 40),
    lambda s: s["integrity"].update(sha256="f" * 64),
    lambda s: s.update(replay_contract="untrusted"),
])
def test_any_mutation_fails_integrity(tamper):
    snap = export()
    tamper(snap)
    with pytest.raises(SnapshotError):
        engine.replay_semantic_facts(snap, KEY)


def test_wrong_identity_key_cannot_link_or_replay():
    snap = export()
    with pytest.raises(SnapshotError):
        engine.replay_semantic_facts(snap, OTHER_KEY)


def test_unexpected_values_not_exported_as_raw_private_data():
    source = report()
    source["services"]["cloudwatch"]["regions"]["eu-central-1"][
        "log_groups"]["client-log"]["retention_status"] = "my-client-private-name"
    snapshot = export(source)
    raw = json.dumps(snapshot)
    assert "my-client-private-name" not in raw
    assert snapshot["rules"]["cloudwatch-log-group-unlimited-retention"][
        "facts"][0]["value"] in ("configured", "unknown") or snapshot["rules"][
        "cloudwatch-log-group-unlimited-retention"]["facts"][1]["value"] == "unknown"


def test_cli_facts_export_and_replay(tmp_path, capsys):
    spec = importlib.util.spec_from_file_location("p4f2_cli", ROOT / "tools/p4f_evidence.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    inp = tmp_path / "RESULTS.json"
    inp.write_text(json.dumps(report()), encoding="utf-8")
    key = tmp_path / "local.snapshot-key"
    assert tool.main(["init-key", "--key-file", str(key)]) == 0
    target = tmp_path / "semantic.p4f2.snapshot.json"
    assert tool.main(["facts-export", "--report", str(inp),
                      "--key-file", str(key), "--output", str(target)]) == 0
    content = json.loads(target.read_text(encoding="utf-8"))
    assert content["format"] == engine.FORMAT
    assert tool.main(["facts-replay", "--snapshot", str(target),
                      "--key-file", str(key)]) == 0
    assert tool.main(["facts-export", "--report", str(inp),
                      "--key-file", str(key), "--output", str(target)]) == 3
    outputs = capsys.readouterr()
    assert "123456789012" not in outputs.out + outputs.err
    assert "SYNTHETIC_SECRET" not in outputs.out + outputs.err


def test_safe_unknown_policy_never_converts_to_pass():
    source = report()
    source["services"]["rds"]["regions"]["eu-central-1"]["proxies"][
        "private-db-proxy"]["tls_status"] = "secret-value"
    replay = engine.replay_semantic_facts(export(source), KEY)
    result = replay["rules"]["rds-proxy-require-tls-disabled"]
    assert result["status"] == "partial"
    assert result["unknown"] == 1
