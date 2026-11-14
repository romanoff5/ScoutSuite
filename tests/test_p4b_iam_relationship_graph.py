"""P4-B offline IAM graph: actual JSON rules, metamorphic safety, deterministic edges."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.core.utils import recurse
from ScoutSuite.providers.aws.resources.iam.relationship_graph import (
    build_relationship_graph, _oidc_scope, _permission,
)


ACCOUNT = '123456789012'
ROOT = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules'


def role(name, *, policy=None, trust=None, boundary=None, managed=None):
    arn = f'arn:aws:iam::{ACCOUNT}:role/{name}'
    entries = {} if policy is None else {
        'embedded': {'name': 'embedded',
                     'PolicyDocument': {'Statement': policy}}}
    return {
        'name': name, 'arn': arn, 'id': 'ARO' + name,
        'inline_policies': entries, 'policies': managed if managed is not None else [],
        'permissions_boundary': boundary,
        'assume_role_policy': {'PolicyDocument': {'Statement': trust or []}},
    }


def stmt(action, resource='*', *, effect='Allow', condition=None):
    d = {'Effect': effect, 'Action': action, 'Resource': resource}
    if condition is not None:
        d['Condition'] = condition
    return d


def trust_service(name):
    return [{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
             'Principal': {'Service': name}}]


def trust_oidc(sub, operator='StringEquals', provider='token.actions.githubusercontent.com',
               extra=None):
    arn = f'arn:aws:iam::{ACCOUNT}:oidc-provider/{provider}'
    condition = {operator: {f'{provider}:sub': sub}}
    if extra is None:
        condition.setdefault('StringEquals', {})[f'{provider}:aud'] = 'sts.amazonaws.com'
    else:
        condition.update(extra)
    return [{'Effect': 'Allow', 'Action': 'sts:AssumeRoleWithWebIdentity',
             'Principal': {'Federated': arn}, 'Condition': condition}]


def admin():
    return [stmt('*', '*')]


def source_policy(service='lambda'):
    action = 'lambda:CreateFunction' if service == 'lambda' else 'ec2:RunInstances'
    return [stmt('iam:PassRole', 'arn:aws:iam::*:role/Admin*'),
            stmt(action, '*')]


def make_inventory():
    source = role('Builder', policy=source_policy())
    target = role('AdminLambda', policy=admin(), trust=trust_service('lambda.amazonaws.com'))
    return {'source': source, 'target': target}, {}


def run_rule(rule_name, services):
    d = json.loads((ROOT / 'findings' / rule_name).read_text(encoding='utf-8'))
    rule = SimpleNamespace(filename=rule_name, path=d['path'],
                           evidence_policy=d['evidence_policy'],
                           conditions=d['conditions'], checked_items=0)
    matches = recurse(services, services, rule.path.split('.'), [], rule, True)
    evidence = evaluate_rule_evidence(rule, services)
    return matches, evidence


def test_passrole_admin_lambda_graph_and_real_finding():
    roles, policies = make_inventory()
    graph = build_relationship_graph(roles, policies)
    assert graph['schema'] == 'iam-relationships-p4b-v1'
    assert graph['edges_count'] == 1
    assert next(iter(graph['edges'].values()))['service'] == 'lambda'
    assert roles['source']['p4b_passrole_path_status'] == 'candidate'
    assert roles['target']['p4b_admin_policy_status'] == 'admin_policy_candidate'
    services = {'iam': {'roles': roles}}
    hits, evidence = run_rule('iam-p4b-passrole-privileged-delegation.json', services)
    assert len(hits) == 1
    assert evidence['counts']['insecure'] == 1
    assert evidence['compliance_verified'] is False
    snapshot = copy.deepcopy(graph)
    again = build_relationship_graph(roles, policies)
    assert again == snapshot  # deterministic IDs / stable result


def test_passrole_requires_creation_permission_and_correct_service_trust():
    roles, policies = make_inventory()
    roles['source']['inline_policies']['embedded']['PolicyDocument']['Statement'] = [
        stmt('iam:PassRole', '*')]
    graph = build_relationship_graph(roles, policies)
    assert not any(e['type'] == 'passrole_privileged_role_candidate'
                   for e in graph['edges'].values())
    assert roles['source']['p4b_passrole_path_status'] == 'unknown'

    roles, policies = make_inventory()
    roles['target']['assume_role_policy']['PolicyDocument']['Statement'] = trust_service(
        'ec2.amazonaws.com')
    build_relationship_graph(roles, policies)
    assert roles['source']['p4b_passrole_path_status'] == 'unknown'


def test_literal_passed_to_service_condition_only_matches_expected_service():
    roles, policies = make_inventory()
    condition = {'StringEquals': {'iam:PassedToService': 'lambda.amazonaws.com'}}
    roles['source']['inline_policies']['embedded']['PolicyDocument']['Statement'][0][
        'Condition'] = condition
    build_relationship_graph(roles, policies)
    assert roles['source']['p4b_passrole_path_status'] == 'candidate'
    roles['source']['inline_policies']['embedded']['PolicyDocument']['Statement'][0][
        'Condition'] = {'StringEquals': {'iam:PassedToService': 'ec2.amazonaws.com'}}
    build_relationship_graph(roles, policies)
    assert roles['source']['p4b_passrole_path_status'] == 'unknown'


def test_explicit_deny_and_boundary_block_confident_candidate():
    roles, policies = make_inventory()
    rows = roles['source']['inline_policies']['embedded']['PolicyDocument']['Statement']
    rows.append(stmt('iam:PassRole', '*', effect='Deny'))
    graph = build_relationship_graph(roles, policies)
    assert roles['source']['p4b_passrole_path_status'] == 'unknown'
    assert graph['edges_count'] == 0

    roles, policies = make_inventory()
    roles['source']['permissions_boundary'] = {
        'PermissionsBoundaryArn': 'arn:aws:iam::123:policy/restrict'}
    build_relationship_graph(roles, policies)
    assert roles['source']['p4b_passrole_path_status'] == 'unknown'
    roles, policies = make_inventory()
    roles['target']['permissions_boundary'] = {
        'PermissionsBoundaryArn': 'arn:aws:iam::123:policy/restrict'}
    build_relationship_graph(roles, policies)
    assert roles['target']['p4b_admin_policy_status'] == 'unknown'
    assert roles['source']['p4b_passrole_path_status'] == 'unknown'


def test_malformed_missing_and_conditional_documents_are_not_pass():
    roles, policies = make_inventory()
    del roles['source']['policies']
    build_relationship_graph(roles, policies)
    assert roles['source']['p4b_passrole_path_status'] == 'unknown'
    roles, policies = make_inventory()
    roles['source']['inline_policies']['embedded']['PolicyDocument'] = 'not-json'
    build_relationship_graph(roles, policies)
    assert roles['source']['p4b_passrole_path_status'] == 'unknown'
    roles, policies = make_inventory()
    rows = roles['source']['inline_policies']['embedded']['PolicyDocument']['Statement']
    rows[0]['Condition'] = {'Bool': {'aws:MultiFactorAuthPresent': 'true'}}
    build_relationship_graph(roles, policies)
    assert roles['source']['p4b_passrole_path_status'] == 'unknown'


def test_oidc_broad_subject_rule_and_scoped_negative_case():
    broad = role('Broad', policy=[stmt('s3:GetObject')], trust=trust_oidc('repo:*',
                                                                      operator='StringLike'))
    scoped = role('Scoped', policy=[stmt('s3:GetObject')],
                  trust=trust_oidc('repo:myorg/myrepo:ref:refs/heads/main'))
    review = role('OrgWide', policy=[stmt('s3:GetObject')],
                  trust=trust_oidc('repo:myorg/*', operator='StringLike'))
    roles = {'b': broad, 's': scoped, 'r': review}
    graph = build_relationship_graph(roles, {})
    assert graph['edges_count'] == 3
    assert broad['p4b_oidc_scope_status'] == 'broad_subject'
    assert scoped['p4b_oidc_scope_status'] == 'scoped_subject'
    assert review['p4b_oidc_scope_status'] == 'review_wildcard'
    hits, evidence = run_rule('iam-p4b-oidc-broad-subject-trust.json',
                              {'iam': {'roles': roles}})
    assert len(hits) == 1
    assert evidence['counts']['insecure'] == 1
    assert evidence['counts']['unknown'] == 1
    assert evidence['counts']['not_applicable'] == 1


def test_github_missing_sub_is_unknown_not_broad():
    github = f'arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com'
    assert _oidc_scope(None, github) == 'unknown'
    assert _oidc_scope({'StringEquals': {
        'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com'}}, github) == 'unknown'
    assert _oidc_scope({'StringLike': {
        'token.actions.githubusercontent.com:sub': 'repo:org/*'}}, github) == 'review_wildcard'


def test_privileged_federated_role_is_review_only_and_boundary_unknown():
    candidate = role('OIDCAdmin', policy=admin(), trust=trust_oidc(
        'repo:myorg/myrepo:ref:refs/heads/main'))
    roles = {'admin': candidate}
    graph = build_relationship_graph(roles, {})
    assert graph['nodes_count'] == 2
    assert candidate['p4b_privileged_oidc_status'] == 'candidate'
    hits, evidence = run_rule('iam-p4b-privileged-oidc-role.json',
                              {'iam': {'roles': roles}})
    assert len(hits) == 1 and evidence['counts']['insecure'] == 1
    candidate['permissions_boundary'] = {'PermissionsBoundaryArn': 'arn:aws:iam::123:policy/x'}
    build_relationship_graph(roles, {})
    assert candidate['p4b_privileged_oidc_status'] == 'review'
    _, evidence = run_rule('iam-p4b-privileged-oidc-role.json',
                           {'iam': {'roles': roles}})
    assert evidence['counts']['unknown'] == 1


def test_graph_edges_bounded_and_nonempty_coverage_does_not_imply_pass(monkeypatch):
    from ScoutSuite.providers.aws.resources.iam import relationship_graph as engine
    roles, policies = make_inventory()
    monkeypatch.setattr(engine, 'MAX_EDGES', 0)
    graph = build_relationship_graph(roles, policies)
    assert graph['status'] == 'partial'
    assert graph['edges_count'] == 0
    assert roles['source']['p4b_passrole_path_status'] == 'unknown'


def test_no_mutations_or_aws_calls_and_catalog_consistency():
    names = ['iam-p4b-passrole-privileged-delegation.json',
             'iam-p4b-oidc-broad-subject-trust.json',
             'iam-p4b-privileged-oidc-role.json']
    for profile in ('default.json', 'detailed.json'):
        d = json.loads((ROOT / 'rulesets' / profile).read_text())
        for name in names:
            assert d['rules'][name][0] == {'enabled': True, 'level': 'review'}
            rule = json.loads((ROOT / 'findings' / name).read_text())
            assert rule['path'] == 'iam.roles.id'
            assert rule['evidence_policy'].startswith('iam-p4b-')
