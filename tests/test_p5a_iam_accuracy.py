"""P5-A IAM accuracy: deny precedence, path-local UNKNOWN and create ARN scopes."""
import copy

import pytest

from ScoutSuite.providers.aws.resources.iam.policy_accuracy import (
    creation_permission, identity_permission,
)
from ScoutSuite.providers.aws.resources.iam.relationship_graph import (
    _service_trust, build_relationship_graph,
)
from ScoutSuite.providers.aws.resources.iam.relationship_graph_b2 import (
    extend_relationship_graph_b2,
)

ACCOUNT = '123456789012'
TARGET = f'arn:aws:iam::{ACCOUNT}:role/Admin'
USER = f'arn:aws:iam::{ACCOUNT}:user/Builder'
ROLE = f'arn:aws:iam::{ACCOUNT}:role/Builder'
LAMBDA = f'arn:aws:lambda:eu-west-1:{ACCOUNT}:function:Project-P5A'


def stmt(action, resource='*', *, effect='Allow', condition=None, **extra):
    result = {'Effect': effect, 'Action': action, 'Resource': resource}
    if condition is not None:
        result['Condition'] = condition
    result.update(extra)
    return result


def docs(*rows):
    return [('inline:p', list(rows))]


def role(name, rows, service=None):
    trust = ([{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
               'Principal': {'Service': service}}] if service else [])
    return {'arn': f'arn:aws:iam::{ACCOUNT}:role/{name}',
            'name': name, 'id': 'ARO' + name,
            'inline_policies': {'p': {'PolicyDocument': {'Statement': rows}}},
            'inline_policy_collection_status': 'complete',
            'attached_managed_policy_collection_status': 'complete',
            'attached_managed_policy_arns': [], 'policies': [],
            'role_boundary_collection_status': 'complete',
            'permissions_boundary': None,
            'assume_role_policy': {'PolicyDocument': {'Statement': trust}}}


def user(rows):
    return {'arn': USER, 'name': 'Builder', 'id': 'AIDABuilder',
            'inline_policies': {'p': {'PolicyDocument': {'Statement': rows}}},
            'inline_policy_collection_status': 'complete',
            'p4b2_managed_status': 'complete', 'p4b2_managed_arns': [],
            'p4b2_boundary_status': 'complete', 'p4b2_boundary': None,
            'p4b2_membership_status': 'complete', 'groups': []}


def graphs(source_rows, *, as_user=True, service='lambda.amazonaws.com'):
    admin = role('Admin', [stmt('*')], service=service)
    source = user(source_rows) if as_user else role('Builder', source_rows)
    roles = {'a': admin} if as_user else {'a': admin, 'b': source}
    users = {'u': source} if as_user else {}
    graph = build_relationship_graph(roles, {})
    extend_relationship_graph_b2(graph, roles, users, {}, {})
    return graph, source


@pytest.mark.parametrize('deny', [
    stmt('s3:DeleteObject', '*', effect='Deny'),
    stmt('iam:PassRole', f'arn:aws:iam::{ACCOUNT}:role/Other', effect='Deny'),
    stmt('iam:PassRole', effect='Deny',
         condition={'StringEquals': {'iam:PassedToService': 'ec2.amazonaws.com'}}),
    {'Effect': 'Deny', 'NotAction': 'iam:PassRole', 'Resource': '*'},
    {'Effect': 'Deny', 'Action': 'iam:PassRole', 'NotResource': TARGET},
    stmt('s3:*', '*', effect='Deny',
         condition={'Bool': {'aws:MultiFactorAuthPresent': 'true'}}),
])
def test_unrelated_deny_does_not_hide_passrole(deny):
    statements = docs(stmt('iam:PassRole', TARGET), copy.deepcopy(deny))
    assert identity_permission(statements, 'iam:PassRole', TARGET,
                               'lambda.amazonaws.com') == 'yes'


@pytest.mark.parametrize('deny', [
    stmt('iam:PassRole', TARGET, effect='Deny'),
    stmt('iam:*', '*', effect='Deny'),
    {'Effect': 'Deny', 'NotAction': 's3:*', 'Resource': TARGET},
    {'Effect': 'Deny', 'Action': 'iam:PassRole',
     'NotResource': f'arn:aws:iam::{ACCOUNT}:role/Other'},
])
def test_relevant_deny_always_overrides_allow_regardless_of_order(deny):
    allow = stmt('iam:PassRole', TARGET)
    for rows in ((allow, deny), (deny, allow)):
        assert identity_permission(docs(*rows), 'iam:PassRole', TARGET,
                                   'lambda.amazonaws.com') == 'no'


def test_unknown_conditions_affect_only_relevant_path():
    unknown = {'Bool': {'aws:MultiFactorAuthPresent': 'true'}}
    allow = stmt('iam:PassRole', TARGET)
    assert identity_permission(docs(allow, stmt(
        'iam:PassRole', TARGET, effect='Deny', condition=unknown)),
        'iam:PassRole', TARGET, 'lambda.amazonaws.com') == 'unknown'
    assert identity_permission(docs(allow, stmt(
        'iam:PassRole', f'arn:aws:iam::{ACCOUNT}:role/Other',
        effect='Deny', condition=unknown)),
        'iam:PassRole', TARGET, 'lambda.amazonaws.com') == 'yes'
    assert identity_permission(docs(stmt('iam:PassRole', TARGET,
        condition=unknown)), 'iam:PassRole', TARGET,
        'lambda.amazonaws.com') == 'unknown'


def test_notaction_allow_and_passed_to_service_conditions():
    allowed = {'Effect': 'Allow', 'NotAction': 's3:*', 'Resource': TARGET}
    assert identity_permission(docs(allowed), 'iam:PassRole', TARGET,
                               'lambda.amazonaws.com') == 'yes'
    assert identity_permission(docs(allowed), 's3:DeleteObject', TARGET) == 'no'
    blocked = stmt('iam:PassRole', TARGET,
                   condition={'StringNotEquals': {
                       'iam:PassedToService': 'lambda.amazonaws.com'}})
    assert identity_permission(docs(blocked), 'iam:PassRole', TARGET,
                               'lambda.amazonaws.com') == 'no'
    assert identity_permission(docs(blocked), 'iam:PassRole', TARGET,
                               'ec2.amazonaws.com') == 'yes'


def test_resource_scoped_lambda_create_and_account_or_condition_exclusion():
    policy = docs(stmt('lambda:CreateFunction',
                       f'arn:aws:lambda:eu-west-1:{ACCOUNT}:function:Project-*'))
    assert creation_permission(policy, 'lambda:CreateFunction', USER) == 'yes'
    assert creation_permission(policy, 'lambda:CreateFunction', ROLE) == 'yes'
    wrong = docs(stmt('lambda:CreateFunction',
                      'arn:aws:lambda:eu-west-1:999999999999:function:Project-*'))
    assert creation_permission(wrong, 'lambda:CreateFunction', USER) == 'no'
    restricted = docs(stmt('lambda:CreateFunction',
                           f'arn:aws:lambda:eu-west-1:{ACCOUNT}:function:Project-*'),
                      stmt('lambda:CreateFunction',
                           f'arn:aws:lambda:eu-west-1:{ACCOUNT}:function:Project-*',
                           effect='Deny'))
    assert creation_permission(restricted, 'lambda:CreateFunction', USER) == 'no'
    conditional = docs(stmt('lambda:CreateFunction',
                            f'arn:aws:lambda:eu-west-1:{ACCOUNT}:function:Project-*',
                            condition={'Bool': {'aws:MultiFactorAuthPresent': 'true'}}))
    assert creation_permission(conditional, 'lambda:CreateFunction', USER) == 'unknown'


def test_ec2_runinstances_multiple_required_resource_types_and_scoped_arn():
    # VPC / EBS / subnet scenario, including image with empty ARN account.
    resources = [f'arn:aws:ec2:us-east-1:{"" if kind == "image" else ACCOUNT}:{kind}/*'
                 for kind in ('image', 'instance', 'network-interface',
                              'security-group', 'subnet', 'volume')]
    statement = stmt('ec2:RunInstances', resources)
    assert creation_permission(docs(statement), 'ec2:RunInstances', USER) == 'yes'
    missing_image = [p for p in resources if ':image/' not in p]
    assert creation_permission(docs(stmt('ec2:RunInstances', missing_image)),
                               'ec2:RunInstances', USER) == 'no'
    deny_subnet = stmt('ec2:RunInstances',
                       f'arn:aws:ec2:us-east-1:{ACCOUNT}:subnet/*',
                       effect='Deny')
    assert creation_permission(docs(statement, deny_subnet),
                               'ec2:RunInstances', USER) == 'no'
    unknown_subnet = stmt('ec2:RunInstances',
                          f'arn:aws:ec2:us-east-1:{ACCOUNT}:subnet/*',
                          effect='Deny',
                          condition={'Bool': {'aws:MultiFactorAuthPresent': 'true'}})
    assert creation_permission(docs(statement, unknown_subnet),
                               'ec2:RunInstances', USER) == 'unknown'


def test_narrow_deny_on_synthetic_name_does_not_hide_other_create_paths():
    arn = f'arn:aws:lambda:us-east-1:{ACCOUNT}:function:P5ACandidate'
    rows = docs(stmt('lambda:CreateFunction'),
                stmt('lambda:CreateFunction', arn, effect='Deny'))
    assert creation_permission(rows, 'lambda:CreateFunction', USER) == 'yes'

    instance = f'arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0123456789abcdef0'
    rows = docs(stmt('ec2:RunInstances'),
                stmt('ec2:RunInstances', instance, effect='Deny'))
    assert creation_permission(rows, 'ec2:RunInstances', USER) == 'yes'


def test_b2_user_unrelated_deny_and_scoped_create_is_candidate():
    rows = [stmt('iam:PassRole', TARGET),
            stmt('lambda:CreateFunction',
                 f'arn:aws:lambda:eu-west-1:{ACCOUNT}:function:Project-*'),
            stmt('s3:DeleteObject', '*', effect='Deny')]
    graph, source = graphs(rows)
    assert graph['status'] == 'complete'
    assert source['p4b2_user_passrole_status'] == 'candidate'
    assert any(x['type'] == 'user_passrole_privileged_candidate'
               for x in graph['edges'].values())
    rows.append(stmt('iam:PassRole', TARGET, effect='Deny'))
    graph, source = graphs(rows)
    assert source['p4b2_user_passrole_status'] == 'unknown'
    assert not any(x['type'] == 'user_passrole_privileged_candidate'
                   for x in graph['edges'].values())


def test_b2_unknown_deny_on_target_remains_unknown_not_candidate():
    rows = [stmt('iam:PassRole', TARGET), stmt('lambda:CreateFunction'),
            stmt('iam:PassRole', TARGET, effect='Deny',
                 condition={'Bool': {'aws:MultiFactorAuthPresent': 'true'}})]
    graph, source = graphs(rows)
    assert graph['status'] == 'complete'
    assert source['p4b2_user_passrole_status'] == 'unknown'


def test_base_role_deny_unrelated_no_longer_hides_candidate():
    roles = {'a': role('Admin', [stmt('*')], service='lambda.amazonaws.com'),
             'b': role('Builder', [stmt('iam:PassRole', TARGET),
                                   stmt('lambda:CreateFunction',
                                        f'arn:aws:lambda:eu-west-1:{ACCOUNT}:function:Project-*'),
                                   stmt('s3:DeleteObject', effect='Deny')])}
    graph = build_relationship_graph(roles, {})
    assert roles['b']['p4b_passrole_path_status'] == 'candidate'
    assert graph['edges_count'] == 1


def test_unrelated_deny_on_privileged_target_does_not_hide_admin_hint():
    target = role('Admin', [stmt('*'),
                            stmt('s3:PutObject', effect='Deny')],
                  service='lambda.amazonaws.com')
    source = role('Builder', [stmt('iam:PassRole', TARGET),
                              stmt('lambda:CreateFunction')])
    roles = {'a': target, 'b': source}
    build_relationship_graph(roles, {})
    assert target['p4b_admin_policy_status'] == 'admin_policy_candidate'
    assert source['p4b_passrole_path_status'] == 'candidate'
    target['inline_policies']['p']['PolicyDocument']['Statement'].append(
        stmt('iam:CreateRole', effect='Deny'))
    build_relationship_graph(roles, {})
    assert target['p4b_admin_policy_status'] == 'unknown'
    assert source['p4b_passrole_path_status'] == 'unknown'


def test_service_trust_deny_after_allow_must_not_be_ignored():
    target = role('Admin', [stmt('*')], service='lambda.amazonaws.com')
    target['assume_role_policy']['PolicyDocument']['Statement'].append(
        {'Effect': 'Deny', 'Action': 'sts:AssumeRole',
         'Principal': {'Service': 'lambda.amazonaws.com'}})
    assert _service_trust(target, 'lambda.amazonaws.com') == 'unknown'
    graph, source = graphs([stmt('iam:PassRole', TARGET),
                            stmt('lambda:CreateFunction')],
                           service='lambda.amazonaws.com')
    # A separately denied trust cannot create a candidate.
    graph, source = graphs([stmt('iam:PassRole', TARGET),
                            stmt('lambda:CreateFunction')])
    assert source['p4b2_user_passrole_status'] == 'candidate'
    target_role = role('Admin', [stmt('*')], service='lambda.amazonaws.com')
    target_role['assume_role_policy']['PolicyDocument']['Statement'].append(
        {'Effect': 'Deny', 'Action': 'sts:AssumeRole',
         'Principal': {'Service': 'lambda.amazonaws.com'}})
    source = user([stmt('iam:PassRole', TARGET), stmt('lambda:CreateFunction')])
    roles = {'a': target_role}
    graph = build_relationship_graph(roles, {})
    extend_relationship_graph_b2(graph, roles, {'u': source}, {}, {})
    assert source['p4b2_user_passrole_status'] == 'unknown'


def test_service_trust_wildcard_principal_explicit_deny_vetoes_allow():
    service = 'lambda.amazonaws.com'
    target = role('Admin', [stmt('*')], service=service)
    doc = target['assume_role_policy']['PolicyDocument']['Statement']
    assert _service_trust(target, service) == 'yes'
    doc.append({'Effect': 'Deny', 'Action': 'sts:AssumeRole',
                'Principal': '*'})
    assert _service_trust(target, service) == 'unknown'
    doc[-1] = {'Effect': 'Deny', 'Action': 'sts:AssumeRole',
               'Principal': {'AWS': '*'}}
    assert _service_trust(target, service) == 'unknown'
    doc[-1] = {'Effect': 'Deny', 'Action': 's3:GetObject',
               'Principal': '*'}
    assert _service_trust(target, service) == 'yes'


def test_wildcard_service_trust_deny_blocks_both_p4b_and_b2():
    admin = role('Admin', [stmt('*')], service='lambda.amazonaws.com')
    admin['assume_role_policy']['PolicyDocument']['Statement'].append({
        'Effect': 'Deny', 'Action': 'sts:AssumeRole', 'Principal': '*'})
    source = user([stmt('iam:PassRole', admin['arn']),
                   stmt('lambda:CreateFunction')])
    roles = {'admin': admin}
    graph = build_relationship_graph(roles, {})
    extend_relationship_graph_b2(graph, roles, {'source': source}, {}, {})
    assert source['p4b2_user_passrole_status'] == 'unknown'
    assert not any(edge['type'] == 'user_passrole_privileged_candidate'
                   for edge in graph['edges'].values())


def test_admin_candidate_aggregates_split_allow_statements_with_deny_precedence():
    """AWS ORs Allows across statements; unrelated scoped Deny does not veto."""
    target = role('Admin', [
        stmt('iam:CreateRole'),
        stmt('ec2:RunInstances'),
        stmt('s3:DeleteObject'),
        stmt('lambda:DeleteFunction', effect='Deny'),
    ], service='lambda.amazonaws.com')
    source = role('Builder', [
        stmt('iam:PassRole', TARGET), stmt('lambda:CreateFunction')])
    roles = {'a': target, 'b': source}
    graph = build_relationship_graph(roles, {})
    assert target['p4b_admin_policy_status'] == 'admin_policy_candidate'
    assert source['p4b_passrole_path_status'] == 'candidate'
    assert graph['edges_count'] == 1
    # A scoped relevant explicit deny vetoes the matching witness.
    target['inline_policies']['p']['PolicyDocument']['Statement'].append(
        stmt('iam:CreateRole', effect='Deny'))
    build_relationship_graph(roles, {})
    assert target['p4b_admin_policy_status'] == 'unknown'
    assert source['p4b_passrole_path_status'] == 'unknown'


def test_admin_candidate_not_broad_when_one_action_only_resource_scoped():
    target = role('Admin', [
        stmt('iam:CreateRole'),
        stmt('ec2:RunInstances', 'arn:aws:ec2:us-east-1:123456789012:instance/*'),
        stmt('s3:DeleteObject'),
    ])
    roles = {'a': target}
    build_relationship_graph(roles, {})
    assert target['p4b_admin_policy_status'] == 'no_admin_grant_observed'
