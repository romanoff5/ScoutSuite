"""P5-C: pinned semantic rule oracles, metamorphic transitions and mutation kills.

All evidence is synthetic. This is NOT field precision/recall, IAM effective-
permission verification or Internet reachability confirmation.
"""
import copy
import hashlib
import hmac
import json
from pathlib import Path

import pytest

from ScoutSuite.core import semantic_replay as replay
from ScoutSuite.core.utils import recurse
from ScoutSuite.providers.aws.resources.ec2.direct_https import (
    _ingress_world_https, _port_covers_443,
)
from ScoutSuite.providers.aws.resources.iam.trust_review import review_trust
from ScoutSuite.providers.aws.resources.s3.exposure import combine_public_access_blocks

KEY = b"3" * 32
ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "tests/data/p5c_semantic_cases.json").read_text(
    encoding="utf-8"))["cases"]
IDS = tuple(row["rule_id"] for row in CASES)


def _insert(source, adapter, label, value):
    """Build a minimal legitimate shape for a single allowlisted AWS path."""
    path = adapter.path.split(".")
    last_id = max(i for i, part in enumerate(path) if part == "id")
    cursor = source["services"]
    # The full adapter path begins with a service name.
    for i, part in enumerate(path):
        segment = label if part == "id" and i == last_id else (
            "scope-" + str(i) if part == "id" else part)
        if i == len(path) - 1:
            cursor[segment] = (value if adapter.field == "this"
                               else {adapter.field: value})
        else:
            cursor = cursor.setdefault(segment, {})


def _source(case, *, positive=None, negative=None, complete=True):
    source = {
        "report_schema_version": 1,
        "account_id": "000000000000",
        "services": {},
        "collection_status": {
            "complete": complete, "status": "success" if complete else "partial",
            "issues": [],
        },
        "synthetic_private_name": "CLIENT_ONLY_NEVER_EXPORT",
    }
    adapter = replay.ADAPTERS[case["rule_id"]]
    _insert(source, adapter, "positive", case["positive"] if positive is None else positive)
    _insert(source, adapter, "negative", case["negative"] if negative is None else negative)
    return source


def _outcome(source, name):
    snapshot = replay.export_semantic_facts(source, KEY)
    outcome = replay.replay_semantic_facts(snapshot, KEY)["rules"][name]
    return snapshot, outcome


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_synthetic_positive_negative_and_single_field_metamorphic_flip(case):
    """One changed terminal fact must change a published rule-engine decision."""
    name = case["rule_id"]
    baseline, original = _outcome(_source(case), name)
    facts = baseline["rules"][name]["facts"]
    assert baseline["rules"][name]["scope"] == "observed"
    assert sorted(x["value"] for x in facts) == sorted((case["positive"], case["negative"]))
    positive_token = next(x["token"] for x in facts if x["value"] == case["positive"])
    negative_token = next(x["token"] for x in facts if x["value"] == case["negative"])
    assert original["status"] == "replayed"
    assert original["conditions_reexecuted"] is True
    assert original["predicate_changed"] is False
    assert original["checked"] == 2 and original["unknown"] == 0
    assert original["matched_tokens"] == [positive_token]

    # Change precisely one terminal observation, preserving every other input.
    _, switched = _outcome(_source(case, positive=case["negative"]), name)
    assert switched["status"] == "replayed"
    assert switched["checked"] == 2 and switched["unknown"] == 0
    assert switched["matched_tokens"] == []  # fixed known-negative oracle

    _, two_positive = _outcome(_source(case, negative=case["positive"]), name)
    assert two_positive["status"] == "replayed"
    assert len(two_positive["matched_tokens"]) == 2
    assert negative_token != positive_token


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_unknown_denial_and_partial_collection_are_not_verified_pass(case):
    name = case["rule_id"]
    # One unsupported scalar is projected to "unknown", not exported raw.
    dirty = _source(case, positive="CLIENT_ONLY_NEVER_EXPORT")
    snapshot, result = _outcome(dirty, name)
    assert "CLIENT_ONLY_NEVER_EXPORT" not in json.dumps(snapshot)
    assert result["status"] == "partial"
    assert result["unknown"] == 1 and result["checked"] == 1
    assert result["matched_tokens"] == []

    # API denial / truncated collection: no complete positive or negative claim.
    unavailable = _source(case, complete=False)
    _, denied = _outcome(unavailable, name)
    assert denied["status"] == "partial"
    assert denied["conditions_reexecuted"] is True
    assert denied["matched_tokens"]  # observed candidate retained, NOT proven
    missing = _source(case)
    del missing["services"][replay.ADAPTERS[name].service]
    _, absent = _outcome(missing, name)
    assert absent["status"] == "partial"
    assert absent["checked"] == 0 and absent["matched_tokens"] == []


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_condition_mutants_are_killed_by_pinned_fixtures(case, monkeypatch):
    """Mutation: replace finding's risky literal(s) with the known-safe literal.

    Real installed JSON is rerun by the production recurse/pass_conditions code;
    independent fixture expectations kill the mutated predicate, not just detect
    a changed SHA or a successful pytest invocation.
    """
    name = case["rule_id"]
    snapshot = replay.export_semantic_facts(_source(case), KEY)
    original = replay.replay_semantic_facts(snapshot, KEY)["rules"][name]
    assert len(original["matched_tokens"]) == 1
    actual = replay._expected_rule

    def mutant(rule_id):
        definition, sha = actual(rule_id)
        if rule_id != name:
            return definition, sha
        definition = copy.deepcopy(definition)
        assert definition["conditions"][0] in ("and", "or")
        for predicate in definition["conditions"][1:]:
            assert predicate[1] == "equal"
            predicate[2] = case["negative"]
        return definition, "f" * 64

    monkeypatch.setattr(replay, "_expected_rule", mutant)
    changed = replay.replay_semantic_facts(snapshot, KEY)["rules"][name]
    assert changed["predicate_changed"] is True
    assert changed["conditions_reexecuted"] is True
    assert changed["status"] == "replayed"
    assert len(changed["matched_tokens"]) == 1
    assert changed["matched_tokens"] != original["matched_tokens"]


def test_allowlist_and_fixed_benchmark_census():
    assert len(CASES) == len(set(IDS)) == len(replay.ADAPTERS) == 27
    assert set(IDS) == set(replay.ADAPTERS)
    assert len(replay.LEGACY_ADAPTERS) == 5
    assert {name.split("-")[0] for name in IDS} == {
        "ec2", "cloudwatch", "iam", "rds", "s3"}
    old = json.loads((ROOT / "tests/data/p3c_detection_triads.json").read_text(
        encoding="utf-8"))["triads"]
    assert len(old) == 30  # retained, not silently relabelled as replay coverage
    for case in CASES:
        adapter = replay.ADAPTERS[case["rule_id"]]
        assert case["positive"] in adapter.allowed
        assert case["negative"] in adapter.allowed
        assert case["unknown"] == "unknown" and case["unknown"] in adapter.allowed
        definition, _ = replay._expected_rule(case["rule_id"])
        assert replay._safe_condition(definition, adapter) is not None


def test_legacy_five_rule_artifact_still_authenticates_and_replays():
    case = CASES[0]
    full = replay.export_semantic_facts(_source(case), KEY)
    original = copy.deepcopy(full)
    legacy = copy.deepcopy(full)
    legacy["rules"] = {name: legacy["rules"][name]
                       for name in replay.LEGACY_ADAPTERS}
    body = {k: v for k, v in legacy.items() if k != "integrity"}
    encoded = replay._canonical(body)
    legacy["integrity"] = {
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "hmac_sha256": hmac.new(KEY, b"scoutsuite-p4f2-v1\x00"
                               + encoded, hashlib.sha256).hexdigest(),
    }
    result = replay.replay_semantic_facts(legacy, KEY)
    assert set(result["rules"]) == replay.LEGACY_ADAPTERS
    assert full == original  # no mutation of original snapshot
    # Arbitrary subsets are never accepted even with a valid HMAC.
    legacy["rules"].pop(next(iter(legacy["rules"])))
    body = {k: v for k, v in legacy.items() if k != "integrity"}
    encoded = replay._canonical(body)
    legacy["integrity"] = {
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "hmac_sha256": hmac.new(KEY, b"scoutsuite-p4f2-v1\x00" + encoded,
                               hashlib.sha256).hexdigest(),
    }
    with pytest.raises(replay.SnapshotError):
        replay.replay_semantic_facts(legacy, KEY)


@pytest.mark.parametrize("start,end,expected", [
    (442, 442, False), (443, 443, True),
    (444, 445, False), (442, 443, True), (443, 444, True),
    (0, 65535, True), (1, 65535, True),
])
def test_https_port_boundaries(start, end, expected):
    assert _port_covers_443(str(start) + "-" + str(end)) is expected


@pytest.mark.parametrize("port,cidr,v4,v6,expected", [
    ("443", "0.0.0.0/0", True, False, True),
    ("443", "0.0.0.0/1", True, False, False),
    ("443", "::/0", False, True, True),
    ("443", "2000::/3", False, True, False),
    ("442", "0.0.0.0/0", True, False, False),
    ("444", "0.0.0.0/0", True, False, False),
])
def test_world_cidr_and_port_boundaries(port, cidr, v4, v6, expected):
    group = {"rules": {"ingress": {"protocols": {"TCP": {"ports": {
        port: {"cidrs": [{"CIDR": cidr}]}
    }}}}}}
    assert _ingress_world_https(group, v4, v6) is expected


@pytest.mark.parametrize("days,short,disabled", [
    (0, False, True), (1, True, False),
    (29, True, False), (30, False, False),
])
def test_rds_retention_thresholds_on_published_rules(days, short, disabled):
    def hits(rule_id):
        definition, _ = replay._expected_rule(rule_id)
        data = {"rds": {"regions": {"test": {"vpcs": {"vpc": {
            "instances": {"db": {"BackupRetentionPeriod": days,
                                 "is_read_replica": False}}
        }}}}}}
        from types import SimpleNamespace
        rule = SimpleNamespace(path=definition["path"],
                               conditions=definition["conditions"], checked_items=0)
        return bool(recurse(data, data, definition["path"].split("."), [], rule, False))
    assert hits("rds-instance-short-backup-retention-period") is short
    assert hits("rds-instance-backup-disabled") is disabled


@pytest.mark.parametrize("value,expected", [
    ("000000000000", "scoped"), ("111111111111", "unknown"),
    ("*", "unknown"),
])
def test_iam_trust_account_arn_boundary(value, expected):
    role = "arn:aws:iam::000000000000:role/test-only"
    policy = {"PolicyDocument": {"Statement": [{
        "Effect": "Allow", "Action": "sts:AssumeRole",
        "Principal": {"Service": "codebuild.amazonaws.com"},
        "Condition": {"StringEquals": {"aws:SourceAccount": value}},
    }]}}
    assert review_trust(policy, role) == expected


def test_effective_s3_bpa_does_not_promote_unknown_to_secure():
    required = ("BlockPublicAcls", "IgnorePublicAcls",
                "BlockPublicPolicy", "RestrictPublicBuckets")
    account = {name: None for name in required}
    bucket = {name: True for name in required}
    effective = combine_public_access_blocks(account, bucket)
    assert all(effective[name] is True for name in required)
    bucket["RestrictPublicBuckets"] = None
    effective = combine_public_access_blocks(account, bucket)
    assert effective["RestrictPublicBuckets"] is None
    bucket["RestrictPublicBuckets"] = False
    effective = combine_public_access_blocks(account, bucket)
    assert effective["RestrictPublicBuckets"] is None
