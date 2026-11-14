"""P4-B2 synthetic IAM relationship graph, negative states and real rule traversal."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.core.utils import recurse
from ScoutSuite.providers.aws.facade.iam import IAMFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.iam.relationship_graph import build_relationship_graph
from ScoutSuite.providers.aws.resources.iam.relationship_graph_b2 import (
    extend_relationship_graph_b2, _oidc_audience_and_subject,
)

ACCOUNT = "123456789012"
ROOT = Path(__file__).resolve().parents[1] / "ScoutSuite/providers/aws/rules"
NEW = (
    "iam-p4b2-user-passrole-to-privileged-role.json",
    "iam-p4b2-user-assumerole-privileged.json",
    "iam-p4b2-role-assumerole-privileged.json",
    "iam-p4b2-group-contributed-passrole.json",
    "iam-p4b2-oidc-audience-review.json",
    "iam-p4b2-oidc-subject-wildcard-review.json",
    "iam-p4b2-access-analyzer-trust-warning.json",
)


def role(name, policy, *, service=None, aws_principal=None, oidc=None):
    arn = f"arn:aws:iam::{ACCOUNT}:role/{name}"
    trust = []
    if service:
        trust.append({"Effect": "Allow", "Action": "sts:AssumeRole",
                      "Principal": {"Service": service}})
    if aws_principal:
        trust.append({"Effect": "Allow", "Action": "sts:AssumeRole",
                      "Principal": {"AWS": aws_principal}})
    if oidc:
        host, conditions = oidc
        trust.append({"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
                      "Principal": {"Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/{host}"},
                      "Condition": conditions})
    return {"id": "ARO" + name, "name": name, "arn": arn,
            "inline_policies": {"p": {"PolicyDocument": {"Statement": policy}}},
            "inline_policy_collection_status": "complete",
            "attached_managed_policy_collection_status": "complete",
            "attached_managed_policy_arns": [],
            "role_boundary_collection_status": "complete",
            "permissions_boundary": None,
            "assume_role_policy": {"PolicyDocument": {"Statement": trust}}}


def grant(action, resource="*", effect="Allow", condition=None):
    row = {"Effect": effect, "Action": action, "Resource": resource}
    if condition is not None:
        row["Condition"] = condition
    return row


def user(name, docs=None, groups=None):
    return {"id": "AIDA" + name, "name": name,
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
            "inline_policies": {"p": {"PolicyDocument": {"Statement": docs or []}}},
            "inline_policy_collection_status": "complete",
            "p4b2_managed_status": "complete", "p4b2_managed_arns": [],
            "p4b2_boundary_status": "complete", "p4b2_boundary": None,
            "p4b2_membership_status": "complete", "groups": groups or []}


def group(name, docs=None):
    return {"id": "AGPA" + name, "name": name,
            "arn": f"arn:aws:iam::{ACCOUNT}:group/{name}",
            "inline_policies": {"p": {"PolicyDocument": {"Statement": docs or []}}},
            "inline_policy_collection_status": "complete",
            "p4b2_managed_status": "complete", "p4b2_managed_arns": []}


def run(roles, users=None, groups=None, policies=None):
    users, groups, policies = users or {}, groups or {}, policies or {}
    first = build_relationship_graph(roles, policies)
    return extend_relationship_graph_b2(first, roles, users, groups, policies)


def check(name, data):
    rule = json.loads((ROOT / "findings" / name).read_text(encoding="utf-8"))
    cfg = SimpleNamespace(filename=name, path=rule["path"], conditions=rule["conditions"],
                          evidence_policy=rule["evidence_policy"], checked_items=0)
    hits = recurse(data, data, cfg.path.split("."), [], cfg, True)
    return hits, evaluate_rule_evidence(cfg, data)


def test_user_passrole_privileged_service_and_json_finding():
    target = role("Admin", [grant("*")], service="lambda.amazonaws.com")
    builder = user("Builder", [grant("iam:PassRole", target["arn"]),
                               grant("lambda:CreateFunction")])
    roles, users = {"a": target}, {"u": builder}
    graph = run(roles, users)
    assert graph["status"] == "complete"
    assert builder["p4b2_user_passrole_status"] == "candidate"
    assert any(e["type"] == "user_passrole_privileged_candidate"
               for e in graph["edges"].values())
    hits, evidence = check(NEW[0], {"iam": {"users": users}})
    assert len(hits) == 1 and evidence["counts"]["insecure"] == 1
    assert evidence["compliance_verified"] is False


def test_group_inheritance_user_passrole_and_group_contribution():
    target = role("Admin", [grant("*")], service="lambda.amazonaws.com")
    ops = group("Ops", [grant("iam:PassRole", target["arn"]),
                         grant("lambda:CreateFunction")])
    builder = user("Builder", [], ["Ops"])
    graph = run({"a": target}, {"u": builder}, {"g": ops})
    assert graph["status"] == "complete"
    assert builder["p4b2_user_passrole_status"] == "candidate"
    assert ops["p4b2_group_passrole_status"] == "candidate"
    hits, ev = check(NEW[3], {"iam": {"groups": {"g": ops}}})
    assert len(hits) == 1 and ev["counts"]["insecure"] == 1
    assert any(e["type"] == "group_membership" for e in graph["edges"].values())


def test_user_and_role_assumerole_need_both_identity_allow_and_trust():
    bob = user("Bob", [grant("sts:AssumeRole", f"arn:aws:iam::{ACCOUNT}:role/Admin")])
    caller = role("Caller", [grant("sts:AssumeRole",
                                   f"arn:aws:iam::{ACCOUNT}:role/Admin")])
    target = role("Admin", [grant("*")], aws_principal=[
        bob["arn"], caller["arn"]])
    users = {"u": bob}
    roles = {"a": target, "c": caller}
    graph = run(roles, users)
    assert graph["status"] == "complete"
    assert bob["p4b2_user_assumerole_status"] == "candidate"
    assert caller["p4b2_role_assumerole_status"] == "candidate"
    for name, collection in ((NEW[1], users), (NEW[2], roles)):
        hits, ev = check(name, {"iam": {
            "users" if name == NEW[1] else "roles": collection}})
        assert len(hits) == 1 and ev["counts"]["insecure"] == 1


def test_assumerole_without_matching_trust_is_unknown_not_candidate():
    bob = user("Bob", [grant("sts:AssumeRole", f"arn:aws:iam::{ACCOUNT}:role/Admin")])
    target = role("Admin", [grant("*")], aws_principal=f"arn:aws:iam::{ACCOUNT}:user/Alice")
    graph = run({"a": target}, {"u": bob})
    assert graph["status"] == "complete"
    assert bob["p4b2_user_assumerole_status"] == "unknown"
    assert not any(e["type"] == "assumerole_privileged_candidate"
                   for e in graph["edges"].values())


@pytest.mark.parametrize("failure", [
    "groups", "attached", "inline", "boundary", "conditional", "deny",
])
def test_incomplete_or_constrained_source_never_produces_candidate(failure):
    target = role("Admin", [grant("*")], service="lambda.amazonaws.com")
    u = user("Builder", [grant("iam:PassRole", target["arn"]),
                         grant("lambda:CreateFunction")])
    if failure == "groups":
        u["p4b2_membership_status"] = "unknown"
    if failure == "attached":
        u["p4b2_managed_status"] = "unknown"
    if failure == "inline":
        u["inline_policy_collection_status"] = "unknown"
    if failure == "boundary":
        u["p4b2_boundary"] = {"PermissionsBoundaryArn": "arn:aws:iam::123:policy/Restrict"}
    if failure == "conditional":
        u["inline_policies"]["p"]["PolicyDocument"]["Statement"][0]["Condition"] = {
            "Bool": {"aws:MultiFactorAuthPresent": "true"}}
    if failure == "deny":
        u["inline_policies"]["p"]["PolicyDocument"]["Statement"].append(
            grant("iam:PassRole", target["arn"], effect="Deny"))
    graph = run({"a": target}, {"u": u})
    assert u["p4b2_user_passrole_status"] == "unknown"
    assert not any(e["type"] == "user_passrole_privileged_candidate"
                   for e in graph["edges"].values())


def test_oidc_audience_and_subject_scoping():
    host = "token.actions.githubusercontent.com"
    broad = role("Broad", [grant("*")], oidc=(host, {
        "StringLike": {host + ":sub": "repo:org/*", host + ":aud": "*"}}))
    safe = role("Scoped", [grant("*")], oidc=(host, {
        "StringEquals": {host + ":sub": "repo:org/repo:ref:refs/heads/main",
                         host + ":aud": "sts.amazonaws.com"}}))
    missing_aud = role("Missing", [grant("*")], oidc=(host, {
        "StringEquals": {host + ":sub": "repo:org/repo:ref:refs/heads/main"}}))
    roles = {"b": broad, "s": safe, "m": missing_aud}
    run(roles)
    assert broad["p4b2_oidc_audience_status"] == "review"
    assert broad["p4b2_oidc_subject_status"] == "review"
    assert safe["p4b2_oidc_audience_status"] == "scoped"
    assert safe["p4b2_oidc_subject_status"] == "scoped"
    assert missing_aud["p4b2_oidc_audience_status"] == "review"
    for name, count in ((NEW[4], 2), (NEW[5], 1)):
        hits, ev = check(name, {"iam": {"roles": roles}})
        assert len(hits) == count and ev["counts"]["insecure"] == count


def test_access_analyzer_security_warning_is_review_not_effective_permission():
    arn = f"arn:aws:iam::{ACCOUNT}:role/OIDC"
    trust = {"Statement": [{"Effect": "Allow",
                             "Principal": {"Federated":
                                 f"arn:aws:iam::{ACCOUNT}:oidc-provider/example.com"},
                             "Action": "sts:AssumeRoleWithWebIdentity",
                             "Condition": {"StringEquals": {
                                 "example.com:sub": "service-account",
                                 "example.com:aud": "sts.amazonaws.com"}}}]}
    target = {"p4b2_oidc_claims_status": "scoped",
              "assume_role_policy": {"PolicyDocument": trust}}
    calls = []
    client = SimpleNamespace(validate_policy=lambda **kwargs: (
        calls.append(kwargs) or {"findings": [
            {"findingType": "SECURITY_WARNING", "issueCode": "TEST_ISSUE"}]}))
    facade = IAMFacade(object())
    with patch.object(AWSFacadeUtils, "get_client", return_value=client):
        result = asyncio.run(facade.validate_p4b2_role_trusts({arn: target}))
    assert result[arn] == {"status": "security_warning",
                           "issue_codes": ["TEST_ISSUE"]}
    assert calls[0]["validatePolicyResourceType"] == "AWS::IAM::AssumeRolePolicyDocument"
    hits, ev = check(NEW[6], {"iam": {"roles": {"oidc": {
        "p4b2_access_analyzer_status": result[arn]["status"]}}}})
    assert len(hits) == 1 and ev["counts"]["insecure"] == 1


def test_access_analyzer_denied_and_validated_policy_never_pass_effective_privilege():
    arn = f"arn:aws:iam::{ACCOUNT}:role/OIDC"
    role_data = {"p4b2_oidc_claims_status": "scoped",
                 "assume_role_policy": {"PolicyDocument": {"Statement": []}}}
    facade = IAMFacade(object())
    denied = SimpleNamespace(validate_policy=lambda **kw: (
        _ for _ in ()).throw(PermissionError("AccessDenied")))
    with patch.object(AWSFacadeUtils, "get_client", return_value=denied):
        outcome = asyncio.run(facade.validate_p4b2_role_trusts({arn: role_data}))
    assert outcome[arn]["status"] == "unknown"
    with patch.object(AWSFacadeUtils, "get_client", return_value=SimpleNamespace(
            validate_policy=lambda **kw: {"findings": []})):
        outcome = asyncio.run(facade.validate_p4b2_role_trusts({arn: role_data}))
    assert outcome[arn]["status"] == "validated"
    _, evidence = check(NEW[6], {"iam": {"roles": {"r": {
        "p4b2_access_analyzer_status": "validated"}}}})
    assert evidence["counts"]["insecure"] == 0
    assert evidence["compliance_verified"] is False


def test_bounded_graph_does_not_publish_candidate_on_truncation(monkeypatch):
    from ScoutSuite.providers.aws.resources.iam import relationship_graph_b2
    monkeypatch.setattr(relationship_graph_b2, "MAX_PAIRS", 0)
    target = role("Admin", [grant("*")], service="lambda.amazonaws.com")
    u = user("Builder", [grant("iam:PassRole", target["arn"]),
                         grant("lambda:CreateFunction")])
    result = run({"a": target}, {"u": u})
    assert result["status"] == "partial"
    assert u["p4b2_user_passrole_status"] == "unknown"


def test_all_rule_json_and_profile_review_contracts():
    for name in NEW:
        rule = json.loads((ROOT / "findings" / name).read_text(encoding="utf-8"))
        assert rule["evidence_policy"].startswith("iam-p4b2")
        for profile in ("default.json", "detailed.json"):
            config = json.loads((ROOT / "rulesets" / profile).read_text())
            assert config["rules"][name][0] == {"enabled": True, "level": "review"}


def test_unknown_oidc_notaction_or_notprincipal_does_not_become_not_applicable():
    host = "token.actions.githubusercontent.com"
    bad = role("Ambiguous", [grant("*")], oidc=(host, {
        "StringEquals": {host + ":sub": "repo:org/project:ref:refs/heads/main",
                         host + ":aud": "sts.amazonaws.com"}}))
    rows = bad["assume_role_policy"]["PolicyDocument"]["Statement"]
    rows[0].pop("Action")
    rows[0]["NotAction"] = "sts:AssumeRole"
    assert _oidc_audience_and_subject(bad) == ("unknown", "unknown")
    rows[0].pop("NotAction")
    rows[0]["Action"] = "sts:AssumeRoleWithWebIdentity"
    rows[0]["NotPrincipal"] = {"AWS": "arn:aws:iam::123456789012:root"}
    assert _oidc_audience_and_subject(bad) == ("unknown", "unknown")
