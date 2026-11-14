"""P4-B: real IAM collection completeness, boundaries and exact managed attachments."""
import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ScoutSuite.providers.aws.facade.iam import IAMFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.iam.roles import Roles
from ScoutSuite.providers.aws.resources.iam.relationship_graph import build_relationship_graph


ACCOUNT = "123456789012"


def arn(name):
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


def policy_doc(statements):
    return {"PolicyDocument": {"Statement": statements}}


def allow(action, resource="*"):
    return {"Effect": "Allow", "Action": action, "Resource": resource}


def role(name, docs, *, service=None, oidc=False, boundary=None,
         boundary_status="complete", attached=None, attached_status="complete"):
    trust = []
    if service is not None:
        trust.append({"Effect": "Allow", "Action": "sts:AssumeRole",
                      "Principal": {"Service": service}})
    if oidc:
        issuer = "token.actions.githubusercontent.com"
        trust.append({"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
                      "Principal": {"Federated":
                          f"arn:aws:iam::{ACCOUNT}:oidc-provider/{issuer}"},
                      "Condition": {"StringEquals": {
                          issuer + ":aud": "sts.amazonaws.com",
                          issuer + ":sub": "repo:org/project:ref:refs/heads/main"}}})
    raw = {
        "RoleId": "ARO" + name, "RoleName": name, "Arn": arn(name),
        "Description": "", "Path": "/", "tags": {"Tags": []},
        "assume_role_policy": policy_doc(trust),
        "inline_policies": {"inline": policy_doc(docs)},
        "role_boundary_collection_status": boundary_status,
        "permissions_boundary": boundary,
        "attached_managed_policy_collection_status": attached_status,
        "attached_managed_policy_arns": [] if attached is None else attached,
    }
    return Roles.__new__(Roles)._parse_role(raw)[1]


def test_role_parser_propagates_verified_boundary_and_attachment_status():
    boundary = {"PermissionsBoundaryArn": f"arn:aws:iam::{ACCOUNT}:policy/Limited"}
    result = role("AdminRole", [allow("*")], oidc=True, boundary=boundary)
    assert result["permissions_boundary"] == boundary
    assert result["role_boundary_collection_status"] == "complete"
    assert result["attached_managed_policy_collection_status"] == "complete"
    graph = build_relationship_graph({"a": result}, {})
    assert result["p4b_admin_policy_status"] == "unknown"
    assert result["p4b_privileged_oidc_status"] == "review"
    assert not any(edge["type"] == "passrole_privileged_role_candidate"
                   for edge in graph["edges"].values())


def test_realistic_inline_only_roles_create_candidates_if_zero_managed_confirmed():
    source = role("Builder", [allow("iam:PassRole", arn("AdminRole")),
                              allow("lambda:CreateFunction")])
    target = role("AdminRole", [allow("*")], service="lambda.amazonaws.com")
    graph = build_relationship_graph({"s": source, "t": target}, {})
    assert graph["status"] == "complete"
    assert graph["edges_count"] == 1
    assert source["p4b_passrole_path_status"] == "candidate"

    target["role_boundary_collection_status"] = "unknown"
    graph = build_relationship_graph({"s": source, "t": target}, {})
    assert graph["edges_count"] == 0
    assert source["p4b_passrole_path_status"] == "unknown"
    assert target["p4b_admin_policy_status"] == "unknown"


def test_missing_role_attachment_inventory_blocks_false_candidate():
    source = role("Builder", [allow("iam:PassRole", arn("AdminRole")),
                              allow("lambda:CreateFunction")],
                  attached_status="unknown")
    target = role("AdminRole", [allow("*")], service="lambda.amazonaws.com")
    graph = build_relationship_graph({"s": source, "t": target}, {})
    assert graph["edges_count"] == 0
    assert source["p4b_passrole_path_status"] == "unknown"


def test_collected_managed_policy_arns_resolve_documents_by_arn():
    p_arn = f"arn:aws:iam::{ACCOUNT}:policy/Administrator"
    source = role("Builder", [allow("iam:PassRole", arn("AdminRole")),
                              allow("lambda:CreateFunction")])
    target = role("AdminRole", [], service="lambda.amazonaws.com", attached=[p_arn])
    policies = {"A": {"arn": p_arn, "PolicyDocument": {"Statement": allow("*")}}}
    graph = build_relationship_graph({"s": source, "t": target}, policies)
    assert graph["edges_count"] == 1
    assert target["p4b_admin_policy_status"] == "admin_policy_candidate"
    # A known attachment with an inaccessible policy document is not a clean policy.
    target = role("AdminRole", [], service="lambda.amazonaws.com", attached=[p_arn])
    graph = build_relationship_graph({"s": source, "t": target}, {})
    assert graph["edges_count"] == 0
    assert target["p4b_admin_policy_status"] == "unknown"


class Client:
    def __init__(self, *, boundary=None, attached=None, deny=None):
        self.boundary = boundary
        self.attached = [] if attached is None else attached
        self.deny = deny
        self.calls = []

    def get_role(self, *, RoleName):
        self.calls.append("GetRole")
        if self.deny == "GetRole":
            raise PermissionError("AccessDenied")
        result = {"RoleName": RoleName, "Arn": arn(RoleName)}
        if self.boundary:
            result["PermissionsBoundary"] = self.boundary
        return {"Role": result}

    def get_paginator(self, operation):
        assert operation == "list_attached_role_policies"
        self.calls.append("ListAttachedRolePolicies")
        if self.deny == "ListAttachedRolePolicies":
            raise PermissionError("AccessDenied")
        return SimpleNamespace(paginate=lambda **kwargs: [
            {"AttachedPolicies": [{"PolicyArn": a} for a in self.attached]}
        ])


def _collect(client):
    facade = IAMFacade(object())
    raw = {"Arn": arn("Builder"), "RoleName": "Builder"}
    with patch.object(AWSFacadeUtils, "get_client", return_value=client):
        asyncio.run(facade._get_and_set_p4b_role_details(raw))
        asyncio.run(facade._get_and_set_p4b_attached_policies(raw))
    return raw


def test_getrole_and_attachment_api_returns_explicit_complete_empty():
    raw = _collect(Client())
    assert raw["role_boundary_collection_status"] == "complete"
    assert raw["permissions_boundary"] is None
    assert raw["attached_managed_policy_collection_status"] == "complete"
    assert raw["attached_managed_policy_arns"] == []


@pytest.mark.parametrize("denied_api,unknown_field", [
    ("GetRole", "role_boundary_collection_status"),
    ("ListAttachedRolePolicies", "attached_managed_policy_collection_status"),
])
def test_denied_iam_api_never_becomes_verified_empty(denied_api, unknown_field):
    raw = _collect(Client(deny=denied_api))
    assert raw[unknown_field] == "unknown"


def test_boundary_from_getrole_is_preserved_and_attached_list_has_correct_arns():
    p_arn = f"arn:aws:iam::{ACCOUNT}:policy/Readonly"
    boundary = {"PermissionsBoundaryArn": f"arn:aws:iam::{ACCOUNT}:policy/Restricted"}
    raw = _collect(Client(boundary=boundary, attached=[p_arn]))
    assert raw["permissions_boundary"] == boundary
    assert raw["attached_managed_policy_arns"] == [p_arn]


def test_partial_graph_is_not_a_verified_oidc_candidate(monkeypatch):
    from ScoutSuite.providers.aws.resources.iam import relationship_graph
    target = role("OIDCAdmin", [allow("*")], oidc=True)
    monkeypatch.setattr(relationship_graph, "MAX_EDGES", 0)
    graph = build_relationship_graph({"a": target}, {})
    assert graph["status"] == "partial"
    assert target["p4b_privileged_oidc_status"] == "unknown"
    assert target["p4b_oidc_scope_status"] == "unknown"


def test_html_evidence_includes_boundary_and_unknown_states():
    src = (Path(__file__).resolve().parents[1] /
           "ScoutSuite/output/data/html/partials/aws/services.iam.roles.html").read_text()
    assert "{{permissions_boundary.PermissionsBoundaryArn}}" in src
    assert "{{role_boundary_collection_status}}" in src
    assert "{{attached_managed_policy_collection_status}}" in src
    assert "{{{" not in src
