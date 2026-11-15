"""P5 Phase 3: independent, source-anchored CloudGoat/CloudFoxable analogues.

These are normalized synthetic translations of selected pinned public Terraform
paths, NOT deployed cloud labs or proof of effective AWS authorization.
Source commits and deviations are documented in P5_PHASE3_LAB_VALIDATION.md.
No lab credentials, AWS calls, exploitation, network or Docker are required.
"""
import copy

import pytest

from ScoutSuite.providers.aws.resources.iam.relationship_graph import (
    build_relationship_graph,
)
from ScoutSuite.core.processingengine import ProcessingEngine
from tests.test_p5d_attack_paths import ACCOUNT, OTHER, allow, edges, role, scan, trust_service
from tools.verify_p5_phase2_pipeline import _aws_provider, _ruleset


PROFILE = f'arn:aws:iam::{ACCOUNT}:instance-profile/cg-ec2-meek'
ADMIN_ROLE = f'arn:aws:iam::{ACCOUNT}:role/cg-ec2-mighty'


def _graph_from_roles(roles, *, s3=None, kms=None, ecs=None):
    # Use production admin inference on real collected policy-shaped documents;
    # never set the privileged-role status by test fixture fiat.
    relationship = build_relationship_graph(roles, {})
    graph, services = scan(roles=roles, s3=s3, kms=kms, ecs=ecs)
    services['iam']['relationship_graph'] = relationship
    return graph, services


def _privileged_role(name, service, profiles=None):
    target = role(name, [allow('*')], trust=[trust_service(service)],
                  profiles=profiles)
    target['p4b_admin_policy_status'] = 'unknown'
    return target


def _candidate_edges(graph, kind):
    candidates = edges(graph, kind)
    for item in candidates:
        assert item['verification'] == 'POTENTIAL'
        assert item['confidence'] == 'MEDIUM'
        assert item['effective_permission_verified'] is False
        assert item['execution_verified'] is False
    return candidates


def test_cloudgoat_lambda_privesc_role_and_service_trust_pipeline():
    """CloudGoat lambda_privesc: Lambda manager -> debug Lambda execution role.

    The real scenario has an upstream Chris -> AssumeRole hop and a managed
    AdministratorAccess on debug; these tests isolate the second hop, with
    an equivalent synthetic broad Allow instead of the managed policy ARN.
    """
    debug = _privileged_role('cg-debug', 'lambda.amazonaws.com')
    manager = role('cg-lambdaManager', [
        allow(['lambda:*', 'iam:PassRole']),
    ], trust=[{'Effect': 'Allow', 'Principal': {
        'AWS': f'arn:aws:iam::{ACCOUNT}:user/chris'}, 'Action': 'sts:AssumeRole'}])
    graph, services = _graph_from_roles({'debug': debug, 'manager': manager})
    assert debug['p4b_admin_policy_status'] == 'admin_policy_candidate'
    assert len(_candidate_edges(graph, 'iam_lambda_create')) == 1
    assert graph['edges_count'] == 1
    # Production finding and independently assembled P5-B/B2 metadata.
    provider = _aws_provider(services)
    ProcessingEngine(_ruleset()).run(provider)
    found = provider.services['iam']['findings']['iam-p5d-role-workload-delegation']
    assert found['flagged_items'] == 1
    assert found['confidence_assessment']['verification_status'] == 'POTENTIAL'
    assert found['confidence_assessment']['confidence'] == 'MEDIUM'
    flagged = [card for card in found['finding_cards']
               if card['outcome'] == 'insecure']
    assert len(flagged) == 1
    assert flagged[0]['verification_status'] == 'POTENTIAL'
    assert flagged[0]['resource_arn'] == manager['arn']


def _cloudgoat_ec2_attachments():
    """Translates explicit policies and occupied 'meek' profile from Terraform."""
    target = _privileged_role('cg-ec2-mighty', 'ec2.amazonaws.com')
    meek = role('cg-ec2-meek', [allow('*', effect='Deny')],
                trust=[trust_service('ec2.amazonaws.com')],
                profiles={'profile-meek': {'arn': PROFILE, 'name': 'cg-ec2-meek'}})
    user = role('cg-kerrigan', [
        allow(['iam:AddRoleToInstanceProfile',
               'iam:RemoveRoleFromInstanceProfile',
               'iam:PassRole']),
        allow('ec2:RunInstances'),
    ])
    return {'mighty': target, 'meek': meek, 'kerrigan': user}


def test_cloudgoat_attachment_path_without_privileged_profile():
    """CloudGoat's mighty role has NO profile; the existing meek profile is mutable."""
    roles = _cloudgoat_ec2_attachments()
    graph, services = _graph_from_roles(roles)
    assert roles['mighty']['instance_profiles'] == {}
    assert roles['meek']['instance_profiles']
    assert roles['mighty']['p4b_admin_policy_status'] == 'admin_policy_candidate'
    assert _candidate_edges(graph, 'iam_ec2_create') == []
    found = _candidate_edges(graph, 'iam_ec2_profile_mutation')
    assert len(found) == 1, graph
    assert found[0]['source'] == roles['kerrigan']['arn']
    assert found[0]['target'] == roles['mighty']['arn']
    assert PROFILE in found[0]['evidence']['basis']
    assert graph['status'] == 'complete'
    provider = _aws_provider(services)
    ProcessingEngine(_ruleset()).run(provider)
    finding = provider.services['iam']['findings']['iam-p5d-role-workload-delegation']
    assert finding['flagged_items'] == 1
    assert finding['confidence_assessment']['verification_status'] == 'POTENTIAL'
    assert finding['confidence_assessment']['effective_permission_verified'] is False
    assert sum(card['outcome'] == 'insecure'
               for card in finding['finding_cards']) == 1


@pytest.mark.parametrize('mutation', (
    'remove_permission', 'add_permission', 'passrole_permission',
    'run_permission', 'explicit_deny', 'profile_missing',
    'trust_missing', 'boundary_unverified', 'profile_cross_account',
))
def test_cloudgoat_attachment_single_mutation_blocks_candidate(mutation):
    roles = _cloudgoat_ec2_attachments()
    source = roles['kerrigan']
    statements = source['inline_policies']['p']['PolicyDocument']['Statement']
    if mutation in ('remove_permission', 'add_permission', 'passrole_permission'):
        action = {'remove_permission': 'iam:RemoveRoleFromInstanceProfile',
                  'add_permission': 'iam:AddRoleToInstanceProfile',
                  'passrole_permission': 'iam:PassRole'}[mutation]
        statements[0]['Action'].remove(action)
    elif mutation == 'run_permission':
        statements.pop()
    elif mutation == 'explicit_deny':
        statements.append(allow('iam:AddRoleToInstanceProfile', PROFILE,
                                effect='Deny'))
    elif mutation == 'profile_missing':
        roles['meek']['instance_profiles'].clear()
    elif mutation == 'trust_missing':
        roles['mighty']['assume_role_policy']['PolicyDocument']['Statement'].clear()
    elif mutation == 'boundary_unverified':
        source['permissions_boundary'] = f'arn:aws:iam::{ACCOUNT}:policy/Unknown'
    elif mutation == 'profile_cross_account':
        roles['meek']['instance_profiles']['profile-meek']['arn'] = (
            f'arn:aws:iam::{OTHER}:instance-profile/cg-ec2-meek')
    graph, _ = _graph_from_roles(roles)
    assert not edges(graph, 'iam_ec2_profile_mutation'), mutation
    assert not edges(graph, 'iam_ec2_create'), mutation
    if mutation == 'boundary_unverified':
        assert graph['status'] == 'partial'


def test_cloudgoat_ecs_task_role_candidate_and_execution_role_not_equivalent():
    """Isolated ECS role-correlation analogue; actual CG S3 target is NOT admin."""
    target = _privileged_role('PrivilegedEcs', 'ecs-tasks.amazonaws.com')
    source = role('cg-web-developer', [allow('iam:PassRole', target['arn']),
                                      allow('ecs:RunTask',
                                            f'arn:aws:ecs:eu-central-1:{ACCOUNT}:task-definition/cg:7')])
    task = {'task_definition_arn': f'arn:aws:ecs:eu-central-1:{ACCOUNT}:task-definition/cg:7',
            'task_role_arn': target['arn'],
            'execution_role_arn': None}
    ecs = {'regions': {'eu-central-1': {'task_definitions': {'cg': task}}}}
    graph, _ = _graph_from_roles({'target': target, 'source': source}, ecs=ecs)
    assert len(_candidate_edges(graph, 'iam_ecs_run_task')) == 1
    task['task_role_arn'] = None
    task['execution_role_arn'] = target['arn']
    graph, _ = _graph_from_roles({'target': target, 'source': source}, ecs=ecs)
    assert not edges(graph, 'iam_ecs_run_task')
    review = edges(graph, 'iam_ecs_execution_role_review')
    assert len(review) == 1
    assert review[0]['verification'] == 'REVIEW'
    assert review[0]['execution_verified'] is False


def test_cloudgoat_ecs_s3fullaccess_role_is_not_misrepresented_as_admin():
    """Known coverage gap: the real target has AmazonS3FullAccess, NOT admin."""
    data_role = role('cg-s3-critical', trust=[
        trust_service('ecs-tasks.amazonaws.com')])
    data_role['attached_managed_policy_arns'] = [
        'arn:aws:iam::aws:policy/AmazonS3FullAccess']
    # Managed policy document is intentionally unavailable; a complete
    # negative result CANNOT be inferred from the incomplete role inventory.
    data_role['attached_managed_policy_collection_status'] = 'unknown'
    caller = role('cg-web-developer', [allow('iam:PassRole', data_role['arn']),
                                      allow('ecs:RunTask',
                                            f'arn:aws:ecs:eu-central-1:{ACCOUNT}:task-definition/cg:7')])
    ecs = {'regions': {'eu-central-1': {'task_definitions': {'cg': {
        'task_definition_arn': f'arn:aws:ecs:eu-central-1:{ACCOUNT}:task-definition/cg:7',
        'task_role_arn': data_role['arn']}}}}}
    graph, _ = _graph_from_roles({'target': data_role, 'caller': caller}, ecs=ecs)
    assert not edges(graph, 'iam_ecs_run_task')
    assert data_role['p4b_admin_policy_status'] != 'admin_policy_candidate'
    assert graph['collection']['iam'] == 'partial'  # Coverage debt, NOT PASS.


def test_cloudfoxable_trust_me_github_oidc_is_not_eks_irsa():
    """Pinned CloudFoxable Trust me: repo:owner/repo:* is wildcard-scoped."""
    github = f'arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com'
    trust = {'Effect': 'Allow',
             'Action': 'sts:AssumeRoleWithWebIdentity',
             'Principal': {'Federated': github},
             'Condition': {'StringLike': {
                 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
                 'token.actions.githubusercontent.com:sub': 'repo:synthetic/repo:*'}}}
    target = role('t_rodman', [allow('ssm:GetParameter',
                f'arn:aws:ssm:eu-central-1:{ACCOUNT}:parameter/trust-*')],
                  trust=[trust])
    relationship = build_relationship_graph({'github': target}, {})
    assert relationship['edges_count'] == 1
    assert target['p4b_oidc_scope_status'] == 'review_wildcard'
    graph, _ = scan(roles={'github': target})
    assert not edges(graph, 'eks_irsa_role')
    # Single-condition flip: exact GitHub branch must be scoped; still NOT
    # evidence that any actual repo workflow/token can assume this role.
    exact = copy.deepcopy(target)
    exact['assume_role_policy']['PolicyDocument']['Statement'][0]['Condition'][
        'StringLike']['token.actions.githubusercontent.com:sub'] = (
            'repo:synthetic/repo:ref:refs/heads/main')
    build_relationship_graph({'github': exact}, {})
    assert exact['p4b_oidc_scope_status'] == 'scoped_subject'


@pytest.mark.parametrize('scope', ('allow', 'deny', 'conditional', 'denied_api'))
def test_s3_cross_account_policy_adversarial_replay(scope):
    """Standalone S3 resource policy extension, NOT copied from lab Terraform."""
    external = f'arn:aws:iam::{OTHER}:role/Reader'
    rule = {'Effect': 'Allow', 'Principal': {'AWS': external},
            'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::audit/reports/*'}
    policy = {'Statement': [rule]}
    if scope == 'deny':
        policy['Statement'].append({**rule, 'Effect': 'Deny'})
    elif scope == 'conditional':
        rule['Condition'] = {'StringEquals': {'aws:SourceVpce': 'vpce-synthetic'}}
    bucket = {'name': 'audit', 'policy_collection_status': (
        'failed' if scope == 'denied_api' else 'success'),
        'policy': policy, 'policy_is_public': False}
    graph, _ = scan(s3={'buckets': {'audit': bucket}})
    assert len(_candidate_edges(graph, 's3_cross_account_resource_policy')) == (
        1 if scope == 'allow' else 0)
    if scope == 'denied_api':
        assert graph['collection']['s3_inventory'] == 'partial'
        assert graph['status'] == 'partial'


@pytest.mark.parametrize('scope', ('allow', 'explicit_deny', 'context_limited', 'denied_api'))
def test_kms_cross_account_policy_adversarial_replay(scope):
    """Standalone customer-managed KMS extension, NOT a CloudFoxable claim."""
    external = f'arn:aws:iam::{OTHER}:role/Reader'
    allow_decrypt = {'Effect': 'Allow', 'Principal': {'AWS': external},
                     'Action': 'kms:Decrypt', 'Resource': '*'}
    policy = {'Statement': [allow_decrypt]}
    if scope == 'explicit_deny':
        policy['Statement'].append({**allow_decrypt, 'Effect': 'Deny'})
    elif scope == 'context_limited':
        allow_decrypt['Condition'] = {
            'StringEquals': {'kms:EncryptionContext:purpose': 'lab'}}
    key = {'arn': f'arn:aws:kms:eu-central-1:{ACCOUNT}:key/key-uuid',
           'key_manager': 'CUSTOMER', 'key_enabled': True, 'policy': policy,
           'policy_collection_status': 'complete' if scope != 'denied_api' else 'denied',
           'grants_collection_status': 'complete', 'grants': {}}
    kms = {'regions': {'eu-central-1': {'keys': {'key': key}}}}
    graph, _ = scan(kms=kms)
    assert len(_candidate_edges(graph, 'kms_cross_account_key_policy')) == (
        1 if scope == 'allow' else 0)
    if scope == 'denied_api':
        assert graph['collection']['kms_inventory'] == 'partial'
        assert graph['status'] == 'partial'
