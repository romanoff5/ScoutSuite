"""P5-B IAM action/resource-specific Deny regression and conservative ambiguity."""
from ScoutSuite.providers.aws.resources.iam.relationship_graph import (
    build_relationship_graph, _identity_action_authorization,
)
from ScoutSuite.providers.aws.resources.iam.relationship_graph_b2 import extend_relationship_graph_b2


ACCOUNT = '123456789012'
TARGET_ARN = f'arn:aws:iam::{ACCOUNT}:role/Admin'


def grant(action, resource='*', effect='Allow', condition=None):
    row = {'Effect': effect, 'Action': action, 'Resource': resource}
    if condition is not None:
        row['Condition'] = condition
    return row


def role(name, statements, trust=()):
    arn = f'arn:aws:iam::{ACCOUNT}:role/{name}'
    return {
        'name': name, 'id': 'ARO' + name, 'arn': arn,
        'inline_policies': {'p': {'PolicyDocument': {'Statement': statements}}},
        'inline_policy_collection_status': 'complete',
        'attached_managed_policy_collection_status': 'complete',
        'attached_managed_policy_arns': [],
        'role_boundary_collection_status': 'complete',
        'permissions_boundary': None,
        'assume_role_policy': {'PolicyDocument': {'Statement': list(trust)}},
    }


def user(name, statements):
    return {
        'name': name, 'id': 'AIDA' + name,
        'arn': f'arn:aws:iam::{ACCOUNT}:user/{name}',
        'groups': [], 'p4b2_membership_status': 'complete',
        'inline_policies': {'p': {'PolicyDocument': {'Statement': statements}}},
        'inline_policy_collection_status': 'complete',
        'p4b2_managed_status': 'complete', 'p4b2_managed_arns': [],
        'p4b2_boundary_status': 'complete', 'p4b2_boundary': None,
    }


def trust_service():
    return [{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
             'Principal': {'Service': 'lambda.amazonaws.com'}}]


def setup(extra_source=(), extra_admin=()):
    source = role('Builder', [
        grant('iam:PassRole', TARGET_ARN),
        grant('lambda:CreateFunction'),
        *extra_source,
    ])
    target = role('Admin', [grant('*'), *extra_admin], trust_service())
    return {'s': source, 't': target}


def test_unrelated_deny_no_longer_hides_passrole_in_p4b():
    roles = setup(extra_source=[grant('s3:DeleteObject', '*', 'Deny')])
    graph = build_relationship_graph(roles, {})
    assert graph['status'] == 'complete'
    assert roles['s']['p4b_passrole_path_status'] == 'candidate'
    assert graph['edges_count'] == 1


def test_unrelated_target_deny_no_longer_erases_admin_hint():
    roles = setup(extra_admin=[grant('s3:GetObject', '*', 'Deny')])
    build_relationship_graph(roles, {})
    assert roles['t']['p4b_admin_policy_status'] == 'admin_policy_candidate'
    assert roles['s']['p4b_passrole_path_status'] == 'candidate'


def test_action_and_resource_specific_scoping():
    docs = [('inline', [
        grant('iam:PassRole', TARGET_ARN),
        grant('iam:PassRole', f'arn:aws:iam::{ACCOUNT}:role/Other', 'Deny'),
        grant('s3:DeleteObject', '*', 'Deny'),
    ])]
    assert _identity_action_authorization(docs, 'iam:PassRole', TARGET_ARN) == 'yes'
    docs[0][1].append(grant('iam:PassRole', TARGET_ARN, 'Deny'))
    assert _identity_action_authorization(docs, 'iam:PassRole', TARGET_ARN) == 'no'


def test_matching_conditional_deny_and_notaction_are_unknown():
    docs = [('inline', [
        grant('iam:PassRole', TARGET_ARN),
        grant('iam:PassRole', TARGET_ARN, 'Deny',
              {'Bool': {'aws:MultiFactorAuthPresent': 'false'}}),
    ])]
    assert _identity_action_authorization(docs, 'iam:PassRole', TARGET_ARN) == 'unknown'
    docs = [('inline', [
        grant('iam:PassRole', TARGET_ARN),
        {'Effect': 'Deny', 'NotAction': ['s3:GetObject'], 'Resource': '*'},
    ])]
    assert _identity_action_authorization(docs, 'iam:PassRole', TARGET_ARN) == 'unknown'


def test_matching_deny_still_blocks_p4b_even_when_other_grants_exist():
    roles = setup(extra_source=[grant('iam:PassRole', TARGET_ARN, 'Deny')])
    build_relationship_graph(roles, {})
    assert roles['s']['p4b_passrole_path_status'] == 'unknown'


def test_p4b2_user_unrelated_deny_survives_and_matching_deny_blocks():
    roles = {'t': role('Admin', [grant('*')], trust_service())}
    u = user('Builder', [grant('iam:PassRole', TARGET_ARN),
                         grant('lambda:CreateFunction'),
                         grant('s3:DeleteObject', '*', 'Deny')])
    graph = build_relationship_graph(roles, {})
    extend_relationship_graph_b2(graph, roles, {'u': u}, {}, {})
    assert u['p4b2_user_passrole_status'] == 'candidate'
    u['inline_policies']['p']['PolicyDocument']['Statement'].append(
        grant('lambda:CreateFunction', '*', 'Deny'))
    graph = build_relationship_graph(roles, {})
    extend_relationship_graph_b2(graph, roles, {'u': u}, {}, {})
    assert u['p4b2_user_passrole_status'] == 'unknown'
