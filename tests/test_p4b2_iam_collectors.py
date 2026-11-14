"""P4-B2 IAM collector permission failures, pagination and report provenance."""
import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ScoutSuite.providers.aws.facade.iam import IAMFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils


class Paginator:
    def __init__(self, pages):
        self.pages = pages
    def paginate(self, **kwargs):
        return iter(self.pages)


class Client:
    def __init__(self, fail=None):
        self.fail = fail
        self.observed = []
    def get_user(self, *, UserName):
        self.observed.append("get_user")
        if self.fail == "get_user":
            raise PermissionError("AccessDenied")
        return {"User": {"Arn": "arn:aws:iam::123456789012:user/" + UserName,
                         "PermissionsBoundary": {
                             "PermissionsBoundaryArn": "arn:aws:iam::123456789012:policy/Boundary"}}}
    def get_paginator(self, op):
        self.observed.append(op)
        if self.fail == op:
            raise PermissionError("AccessDenied")
        if op == "list_groups_for_user":
            return Paginator([{"Groups": [{"GroupName": "Ops"}]}])
        return Paginator([{"AttachedPolicies": [
            {"PolicyArn": "arn:aws:iam::123456789012:policy/ReadOnly"}]}])


def run_collector(method, item, client, *args):
    facade = IAMFacade(object())
    with patch.object(AWSFacadeUtils, "get_client", return_value=client):
        asyncio.run(getattr(facade, method)(item, *args))
    return item


def test_user_boundary_get_user_and_group_membership_complete():
    raw = {"UserName": "Alice", "Arn": "arn:aws:iam::123456789012:user/Alice"}
    client = Client()
    result = run_collector("_get_and_set_p4b2_user_details", raw, client)
    assert result["p4b2_boundary_status"] == "complete"
    assert result["p4b2_boundary"]["PermissionsBoundaryArn"].endswith("/Boundary")
    result = run_collector("_get_and_set_p4b2_user_groups", raw, client)
    assert result["p4b2_membership_status"] == "complete"
    assert result["groups"] == ["Ops"]


def test_user_group_managed_census_complete_and_denied_is_unknown():
    for kind, name in (("user", "UserName"), ("group", "GroupName")):
        raw = {name: "Alice"}
        client = Client()
        run_collector("_get_and_set_p4b2_managed_attachments", raw, client, kind)
        assert raw["p4b2_managed_status"] == "complete"
        assert raw["p4b2_managed_arns"] == [
            "arn:aws:iam::123456789012:policy/ReadOnly"]
        raw = {name: "Alice"}
        client = Client("list_attached_" + kind + "_policies")
        run_collector("_get_and_set_p4b2_managed_attachments", raw, client, kind)
        assert raw["p4b2_managed_status"] == "unknown"
        assert raw["p4b2_managed_arns"] == []


def test_getuser_denied_cannot_assert_missing_boundary():
    raw = {"UserName": "Alice", "Arn": "arn:aws:iam::123456789012:user/Alice"}
    result = run_collector("_get_and_set_p4b2_user_details", raw, Client("get_user"))
    assert result["p4b2_boundary_status"] == "unknown"


def test_membership_denied_is_unknown_even_when_empty_list():
    raw = {"UserName": "Alice"}
    result = run_collector("_get_and_set_p4b2_user_groups", raw,
                           Client("list_groups_for_user"))
    assert result["p4b2_membership_status"] == "unknown"
    assert result["groups"] == []


def test_inline_policy_census_tracks_multichunk_list_and_deny():
    facade = IAMFacade(object())
    calls = []
    def list_policies(**kw):
        calls.append(dict(kw))
        if "Marker" not in kw:
            return {"PolicyNames": ["First"], "IsTruncated": True, "Marker": "next"}
        return {"PolicyNames": ["Second"], "IsTruncated": False}
    def get_policy(**kw):
        return {"PolicyDocument": {"Statement": [{
            "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["*"]}]}}
    cli = SimpleNamespace(list_user_policies=list_policies,
                          get_user_policy=get_policy)
    raw = {"UserName": "Alice"}
    with patch.object(AWSFacadeUtils, "get_client", return_value=cli):
        asyncio.run(facade._get_and_set_inline_policies(raw, "user"))
    assert raw["inline_policy_collection_status"] == "complete"
    assert raw["inline_policies_count"] == 2
    assert calls[1]["Marker"] == "next"

    cli = SimpleNamespace(list_user_policies=lambda **kw: (
        _ for _ in ()).throw(PermissionError("AccessDenied")),
        get_user_policy=get_policy)
    raw = {"UserName": "Alice"}
    with patch.object(AWSFacadeUtils, "get_client", return_value=cli):
        asyncio.run(facade._get_and_set_inline_policies(raw, "user"))
    assert raw["inline_policy_collection_status"] == "unknown"


def test_p4b2_roles_users_groups_evidence_is_escaped_in_html():
    root = Path(__file__).resolve().parents[1] / "ScoutSuite/output/data/html/partials/aws"
    checks = {
        "services.iam.users.html": ["p4b2_user_passrole_status",
                                     "p4b2_user_assumerole_status"],
        "services.iam.roles.html": ["p4b2_role_assumerole_status",
                                     "p4b2_oidc_audience_status",
                                     "p4b2_access_analyzer_status"],
        "services.iam.groups.html": ["p4b2_group_passrole_status"],
    }
    for file, fields in checks.items():
        content = (root / file).read_text(encoding="utf-8")
        assert "{{{" not in content
        for f in fields:
            assert "{{" + f + "}}" in content
