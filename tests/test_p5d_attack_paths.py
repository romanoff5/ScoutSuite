"""P5-D: deterministic attack path candidates, negative and fail-closed regression."""
import asyncio
from types import SimpleNamespace
from unittest.mock import patch

from ScoutSuite.providers.aws.resources.iam.attack_paths_p5d import (
    annotate_p5d_attack_paths, _resource_permission,
)
from ScoutSuite.providers.aws.facade.eks_public import EKSPublicFacade
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence

ACCOUNT = '123456789012'
OTHER = '999999999999'


def role(name, statements=(), *, trust=(), admin=False, boundary=None, profiles=None):
    arn = f'arn:aws:iam::{ACCOUNT}:role/{name}'
    return {
        'id': name, 'name': name, 'arn': arn,
        'inline_policies': {'p': {'PolicyDocument': {'Statement': list(statements)}}},
        'inline_policy_collection_status': 'complete',
        'attached_managed_policy_collection_status': 'complete',
        'attached_managed_policy_arns': [],
        'role_boundary_collection_status': 'complete',
        'permissions_boundary': boundary,
        'instance_profiles': profiles or {},
        'assume_role_policy': {'PolicyDocument': {'Statement': list(trust)}},
        'p4b_admin_policy_status': 'admin_policy_candidate' if admin
                                 else 'no_admin_grant_observed',
    }


def allow(action, resource='*', *, effect='Allow', condition=None):
    result = {'Effect': effect, 'Action': action, 'Resource': resource}
    if condition is not None:
        result['Condition'] = condition
    return result


def trust_service(service, actions='sts:AssumeRole'):
    return {'Effect': 'Allow', 'Principal': {'Service': service}, 'Action': actions}


def scan(*, roles=None, s3=None, kms=None, eks=None, ecs=None, awslambda=None):
    services = {'iam': {'roles': roles or {}, 'users': {}, 'groups': {}, 'policies': {}}}
    selected = ['iam']
    for name, resource in (('s3', s3), ('kms', kms), ('eks', eks),
                           ('ecs', ecs), ('awslambda', awslambda)):
        if resource is not None:
            services[name] = resource
            selected.append(name)
    graph = annotate_p5d_attack_paths(services, selected, ACCOUNT)
    return graph, services


def edges(graph, kind):
    return [edge for edge in graph['edges'].values() if edge['type'] == kind]


def test_lambda_creation_with_unrelated_deny_is_a_candidate():
    target = role('Priv', admin=True, trust=[trust_service('lambda.amazonaws.com')])
    src = role('Operator', [
        allow('iam:PassRole', target['arn']),
        allow('lambda:CreateFunction'),
        allow('s3:DeleteObject', effect='Deny'),
    ])
    graph, _ = scan(roles={'a': target, 'b': src})
    assert src['p5d_service_delegation_status'] == 'candidate'
    found = edges(graph, 'iam_lambda_create')
    assert len(found) == 1
    assert found[0]['verification'] == 'POTENTIAL'
    assert found[0]['effective_permission_verified'] is False
    assert found[0]['source'] == src['arn']


def test_scoped_passrole_deny_blocks_candidate_not_an_unrelated_action():
    target = role('Priv', admin=True, trust=[trust_service('lambda.amazonaws.com')])
    src = role('Operator', [
        allow('iam:PassRole', '*'), allow('lambda:CreateFunction'),
        allow('iam:PassRole', target['arn'], effect='Deny'),
    ])
    graph, _ = scan(roles={'a': target, 'b': src})
    assert not edges(graph, 'iam_lambda_create')
    assert src['p5d_service_delegation_status'] == 'unknown'


def test_permissions_boundary_and_unreadable_policy_fail_closed():
    target = role('Priv', admin=True, trust=[trust_service('lambda.amazonaws.com')])
    src = role('Operator', [allow('iam:PassRole'), allow('lambda:CreateFunction')],
               boundary='arn:aws:iam::123456789012:policy/Limited')
    graph, _ = scan(roles={'a': target, 'b': src})
    assert not edges(graph, 'iam_lambda_create')
    assert graph['collection']['iam'] == 'partial'


def test_ec2_requires_observed_instance_profile():
    target = role('Priv', admin=True, trust=[trust_service('ec2.amazonaws.com')])
    src = role('Operator', [allow('iam:PassRole'), allow('ec2:RunInstances')])
    graph, _ = scan(roles={'a': target, 'b': src})
    assert not edges(graph, 'iam_ec2_create')
    target['instance_profiles'] = {'profile-1': {'arn': 'arn:aws:iam::123456789012:instance-profile/Priv'}}
    graph, _ = scan(roles={'a': target, 'b': src})
    assert len(edges(graph, 'iam_ec2_create')) == 1


def test_ecs_observed_task_definition_role_requires_run_and_passrole():
    target = role('Priv', admin=True, trust=[trust_service('ecs-tasks.amazonaws.com')])
    task_arn = 'arn:aws:ecs:eu-central-1:123456789012:task-definition/priv:12'
    src = role('Operator', [allow('iam:PassRole', target['arn']),
                            allow('ecs:RunTask', task_arn)])
    ecs = {'regions': {'eu-central-1': {'task_definitions': {'t': {
        'task_definition_arn': task_arn, 'task_role_arn': target['arn']}}}}}
    graph, _ = scan(roles={'a': target, 'b': src}, ecs=ecs)
    assert len(edges(graph, 'iam_ecs_run_task')) == 1
    src['inline_policies']['p']['PolicyDocument']['Statement'].append(
        allow('ecs:RunTask', task_arn, effect='Deny'))
    graph, _ = scan(roles={'a': target, 'b': src}, ecs=ecs)
    assert not edges(graph, 'iam_ecs_run_task')


def test_irsa_exact_oidc_audience_subject_only():
    issuer = 'https://oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLE'
    provider = 'arn:aws:iam::123456789012:oidc-provider/' + issuer[8:]
    role_arn = 'arn:aws:iam::123456789012:role/Priv'
    target = role('Priv', admin=True, trust=[{
        'Effect': 'Allow', 'Principal': {'Federated': provider},
        'Action': 'sts:AssumeRoleWithWebIdentity',
        'Condition': {'StringEquals': {
            issuer[8:] + ':aud': 'sts.amazonaws.com',
            issuer[8:] + ':sub': 'system:serviceaccount:team:api'}}}])
    cluster = {'cluster_arn': 'arn:aws:eks:eu-central-1:123456789012:cluster/test',
               'oidc_issuer': issuer, 'pod_identity_inventory_status': 'complete',
               'pod_identity_associations': {}}
    eks = {'regions': {'eu-central-1': {'clusters': {'test': cluster}}}}
    graph, _ = scan(roles={'priv': target}, eks=eks)
    assert len(edges(graph, 'eks_irsa_role')) == 1
    assert target['p5d_eks_identity_status'] == 'candidate'
    assert edges(graph, 'eks_irsa_role')[0]['target'] == role_arn
    target['assume_role_policy']['PolicyDocument']['Statement'][0][
        'Condition']['StringEquals'][issuer[8:] + ':aud'] = 'not-sts'
    graph, _ = scan(roles={'priv': target}, eks=eks)
    assert not edges(graph, 'eks_irsa_role')


def test_pod_identity_association_and_trust_and_missing_inventory():
    target = role('Priv', admin=True, trust=[
        trust_service('pods.eks.amazonaws.com', ['sts:AssumeRole', 'sts:TagSession'])])
    cluster = {'cluster_arn': 'arn:aws:eks:eu-central-1:123456789012:cluster/test',
               'oidc_issuer': 'https://oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLE',
               'pod_identity_inventory_status': 'complete',
               'pod_identity_associations': {'pa': {'namespace': 'team',
                  'service_account': 'api', 'role_arn': target['arn']}}}
    eks = {'regions': {'eu-central-1': {'clusters': {'test': cluster}}}}
    graph, _ = scan(roles={'p': target}, eks=eks)
    assert len(edges(graph, 'eks_pod_identity')) == 1
    cluster['pod_identity_inventory_status'] = 'partial'
    graph, _ = scan(roles={'p': target}, eks=eks)
    assert not edges(graph, 'eks_pod_identity')


def test_s3_named_external_principal_action_resource_and_explicit_deny():
    external = f'arn:aws:iam::{OTHER}:role/Reader'
    policy = {'Statement': [
        {'Effect': 'Allow', 'Principal': {'AWS': external},
         'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::audit/*'}]}
    bucket = {'name': 'audit', 'policy_collection_status': 'success',
              'policy': policy, 'policy_is_public': False,
              'public_access_block_configuration': {'RestrictPublicBuckets': True}}
    graph, _ = scan(s3={'buckets': {'audit': bucket}})
    assert len(edges(graph, 's3_cross_account_resource_policy')) == 1
    policy['Statement'].append({'Effect': 'Deny', 'Principal': {'AWS': external},
                                'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::audit/*'})
    graph, _ = scan(s3={'buckets': {'audit': bucket}})
    assert not edges(graph, 's3_cross_account_resource_policy')
    assert _resource_permission(policy, external, 's3:GetObject',
                                'arn:aws:s3:::audit/P5DObjectWitness') == 'no'


def test_s3_accessdenied_or_unknown_condition_cannot_be_candidate():
    external = f'arn:aws:iam::{OTHER}:role/Reader'
    policy = {'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': external},
              'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::audit/*',
              'Condition': {'StringEquals': {'aws:SourceVpce': 'vpce-123'}}}]}
    bucket = {'name': 'audit', 'policy_collection_status': 'failed', 'policy': policy}
    graph, _ = scan(s3={'buckets': {'audit': bucket}})
    assert not edges(graph, 's3_cross_account_resource_policy')
    bucket['policy_collection_status'] = 'success'
    graph, _ = scan(s3={'buckets': {'audit': bucket}})
    assert not edges(graph, 's3_cross_account_resource_policy')


def test_kms_external_key_policy_and_unconstrained_grant():
    external = f'arn:aws:iam::{OTHER}:role/Reader'
    arn = f'arn:aws:kms:eu-central-1:{ACCOUNT}:key/uuid'
    key = {'arn': arn, 'key_enabled': True, 'key_manager': 'CUSTOMER',
           'policy': {'Statement': [{'Effect': 'Allow',
               'Principal': {'AWS': external}, 'Action': 'kms:Decrypt',
               'Resource': '*'}]},
           'grants': {}}
    kms = {'regions': {'eu-central-1': {'keys': {'k': key}}}}
    graph, _ = scan(kms=kms)
    assert len(edges(graph, 'kms_cross_account_key_policy')) == 1
    key['policy'] = None
    key['grants'] = {'grant-id': {'grantee_principal': external,
        'operations': ['Decrypt'], 'constraints': {}}}
    graph, _ = scan(kms=kms)
    assert len(edges(graph, 'kms_cross_account_grant')) == 1
    key['grants']['grant-id']['constraints'] = {'EncryptionContextEquals': {'purpose': 'data'}}
    graph, _ = scan(kms=kms)
    assert not edges(graph, 'kms_cross_account_grant')


def test_external_lambda_invoke_is_review_not_privilege_escalation():
    external = f'arn:aws:iam::{OTHER}:role/Invoker'
    arn = f'arn:aws:lambda:eu-central-1:{ACCOUNT}:function:priv'
    fn = {'arn': arn, 'role_arn': f'arn:aws:iam::{ACCOUNT}:role/Admin',
          'access_policy': {'Statement': [{
              'Effect': 'Allow', 'Principal': {'AWS': external},
              'Action': 'lambda:InvokeFunction', 'Resource': arn}]}}
    services = {'regions': {'eu-central-1': {'functions': {'fn': fn}}}}
    graph, _ = scan(awslambda=services)
    edge = edges(graph, 'lambda_external_invoke_review')
    assert len(edge) == 1 and edge[0]['verification'] == 'REVIEW'
    assert edge[0]['execution_verified'] is False


def test_p5d_versioned_evidence_never_converts_unknown_to_pass():
    rule = SimpleNamespace(evidence_policy='p5d-iam-delegation-v1',
                           filename='iam-p5d-role-workload-delegation.json',
                           path='iam.roles.id')
    services = {'iam': {'roles': {'r': {'p5d_service_delegation_status': 'unknown'}}}}
    result = evaluate_rule_evidence(rule, services)
    assert result['counts']['unknown'] == 1
    assert result['assessment_status'] == 'incomplete'
    services['iam']['roles']['r']['p5d_service_delegation_status'] = 'candidate'
    result = evaluate_rule_evidence(rule, services)
    assert result['counts']['insecure'] == 1


def test_pod_identity_pagination_access_denied_fail_closed():
    class Client:
        def list_pod_identity_associations(self, **kwargs):
            raise PermissionError('AccessDenied')
    with patch('ScoutSuite.providers.aws.facade.eks_public.AWSFacadeUtils.get_client',
               return_value=Client()):
        facade = EKSPublicFacade(SimpleNamespace(), ACCOUNT)
        result = asyncio.run(facade.get_pod_identity_associations('eu-central-1', 'test'))
    assert result['status'] == 'partial'
    assert result['associations'] == []
