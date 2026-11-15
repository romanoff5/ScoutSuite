"""P5 cross-phase precision audit: regression contracts on actual deployed code.

Synthetic policy and inventory data only; no cloud calls or exploit assertions.
"""
import json
from types import SimpleNamespace

from ScoutSuite.core.finding_cards import build_resource_cards, build_observation_checks
from ScoutSuite.core.finding_confidence import build_finding_confidence
from ScoutSuite.core.semantic_replay import ADAPTERS, export_semantic_facts, replay_semantic_facts
from ScoutSuite.providers.aws.resources.iam.relationship_graph import build_relationship_graph
from tests.test_p5d_attack_paths import (
    ACCOUNT, allow, edges, role, scan, trust_service,
)
from tests.test_p5c_adversarial_replay import CASES, KEY, _source


def test_separate_admin_allows_create_a_real_candidate_without_deny():
    admin = role('Admin', [
        allow('iam:CreateRole'), allow('ec2:RunInstances'), allow('s3:DeleteObject'),
    ], trust=[trust_service('ecs-tasks.amazonaws.com')], admin=False)
    roles = {'admin': admin}
    build_relationship_graph(roles, {})
    assert admin['p4b_admin_policy_status'] == 'admin_policy_candidate'
    admin['inline_policies']['p']['PolicyDocument']['Statement'].append(
        allow('iam:CreateRole', effect='Deny'))
    build_relationship_graph(roles, {})
    assert admin['p4b_admin_policy_status'] == 'unknown'


def test_partition_aware_admin_hint_govcloud_s3_deny_is_respected():
    admin = role('GovRole', [allow('iam:CreateRole'), allow('ec2:RunInstances'),
                            allow('s3:DeleteObject')], admin=False)
    admin['arn'] = admin['arn'].replace('arn:aws:', 'arn:aws-us-gov:')
    roles = {'gov': admin}
    build_relationship_graph(roles, {})
    assert admin['p4b_admin_policy_status'] == 'admin_policy_candidate'
    admin['inline_policies']['p']['PolicyDocument']['Statement'].append(
        allow('s3:DeleteObject', 'arn:aws-us-gov:s3:::p5a-iam-review/*',
              effect='Deny'))
    build_relationship_graph(roles, {})
    assert admin['p4b_admin_policy_status'] == 'unknown'


def test_ecs_execution_role_is_review_only_not_container_privilege_path():
    target = role('Priv', admin=True, trust=[trust_service('ecs-tasks.amazonaws.com')])
    task_arn = f'arn:aws:ecs:eu-central-1:{ACCOUNT}:task-definition/synthetic:1'
    source = role('Builder', [allow('iam:PassRole', target['arn']),
                              allow('ecs:RunTask', task_arn)])
    ecs = {'regions': {'eu-central-1': {'task_definitions': {'t': {
        'task_definition_arn': task_arn, 'execution_role_arn': target['arn'],
        'task_role_arn': f'arn:aws:iam::{ACCOUNT}:role/Other'}}}}}
    graph, services = scan(roles={'admin': target, 'source': source}, ecs=ecs)
    assert not edges(graph, 'iam_ecs_run_task')
    review = edges(graph, 'iam_ecs_execution_role_review')
    assert len(review) == 1
    assert review[0]['verification'] == 'REVIEW'
    assert review[0]['confidence'] == 'LOW'
    assert review[0]['execution_verified'] is False
    assert source['p5d_service_delegation_status'] == 'unknown'
    assert source['p5d_ecs_execution_review_status'] == 'review'
    assert review[0]['id'] in {item['id'] for item in source['p5d_attack_path_details']}
    source['inline_policies']['p']['PolicyDocument']['Statement'].append(
        allow('ecs:RunTask', task_arn, effect='Deny'))
    denied, _ = scan(roles={'admin': target, 'source': source}, ecs=ecs)
    assert not edges(denied, 'iam_ecs_execution_role_review')


def test_ecs_task_role_candidate_is_distinct_from_execution_role_review():
    target = role('Priv', admin=True, trust=[trust_service('ecs-tasks.amazonaws.com')])
    task_arn = f'arn:aws:ecs:eu-central-1:{ACCOUNT}:task-definition/synthetic:1'
    source = role('Builder', [allow('iam:PassRole', target['arn']),
                              allow('ecs:RunTask', task_arn)])
    ecs = {'regions': {'eu-central-1': {'task_definitions': {'t': {
        'task_definition_arn': task_arn, 'task_role_arn': target['arn']}}}}}
    graph, _ = scan(roles={'admin': target, 'source': source}, ecs=ecs)
    assert len(edges(graph, 'iam_ecs_run_task')) == 1
    assert not edges(graph, 'iam_ecs_execution_role_review')
    assert source['p5d_service_delegation_status'] == 'candidate'


def test_p5d_regional_inventory_truncation_is_not_complete(monkeypatch):
    from ScoutSuite.providers.aws.resources.iam import attack_paths_p5d
    monkeypatch.setattr(attack_paths_p5d, 'MAX_RESOURCES', 1)
    ecs = {'regions': {'eu-central-1': {'task_definitions': {
        'one': {}, 'two': {}}}}}
    graph, _ = scan(ecs=ecs)
    assert graph['status'] == 'partial'
    assert graph['collection']['ecs_inventory'] == 'partial'
    assert graph['collection']['lambda_ecs_ec2'] == 'partial'


def test_p5d_selected_incomplete_and_malformed_inventories_fail_closed():
    graph, _ = scan(s3={'buckets': {'audit': {
        'name': 'audit', 'policy_collection_status': 'failed'}}})
    assert graph['status'] == 'partial'
    assert graph['collection']['s3_inventory'] == 'partial'
    graph, _ = scan(kms={'regions': {'eu-west-1': {'keys': {
        'bad': 'not-a-key'}}}})
    assert graph['status'] == 'partial'
    assert graph['collection']['kms_inventory'] == 'partial'


def test_govcloud_s3_bucket_graph_targets_real_partition_and_b2_evidence():
    principal = 'arn:aws-us-gov:iam::999999999999:role/Reader'
    name = 'audit-logs'
    prefix = 'arn:aws-us-gov:s3:::audit-logs/reports/*'
    policy = {'Statement': [{
        'Effect': 'Allow', 'Action': 's3:GetObject',
        'Principal': {'AWS': principal}, 'Resource': prefix,
    }]}
    bucket = {'name': name, 'arn': 'arn:aws-us-gov:s3:::audit-logs/*',
              'policy': policy, 'policy_collection_status': 'success',
              'policy_is_public': False, 'public_access_block_configuration': {}}
    graph, services = scan(s3={'buckets': {'audit': bucket}})
    scoped = edges(graph, 's3_cross_account_resource_policy')
    assert len(scoped) == 1
    assert scoped[0]['target'] == 'arn:aws-us-gov:s3:::audit-logs'
    checks = build_observation_checks(
        'p5d-cross-account-v1', bucket, services, 's3.buckets.audit', 'insecure')
    assert len([c for c in checks if c['state'] == 'CONFIRMED' and c['required']]) == 2
    # A relevant Deny on the same prefix takes precedence regardless of order.
    policy['Statement'].insert(0, {
        'Effect': 'Deny', 'Action': 's3:GetObject',
        'Principal': {'AWS': principal}, 'Resource': prefix,
    })
    denied, _ = scan(s3={'buckets': {'audit': bucket}})
    assert not edges(denied, 's3_cross_account_resource_policy')


def test_p5b_mismatched_counts_cannot_claim_medium_or_high_confidence():
    rule = SimpleNamespace(evidence_policy='p5d-iam-delegation-v1')
    finding = {'flagged_items': 2, 'assessment_status': 'evaluated',
               'evaluation_summary': {'counts': {
                   'insecure': 1, 'secure': 0, 'unknown': 0,
                   'not_applicable': 0}}}
    result = build_finding_confidence(rule, finding)
    assert result['verification_status'] == 'UNKNOWN'
    assert result['confidence'] == 'UNKNOWN'
    assert result['evidence_quality'] == 'PARTIAL'
    assert 'RULE_EVIDENCE_COUNT_DIFFERENCE' in result['reason_codes']


def test_p5b2_per_resource_card_downgrades_mismatched_findings():
    finding = {'level': 'danger', 'flagged_items': 2,
               'assessment_status': 'evaluated',
               'confidence_assessment': {'claim_type': 'POTENTIAL_ATTACK_PATH'},
               'evaluation_summary': {'counts': {
                   'insecure': 1, 'secure': 0, 'unknown': 0,
                   'not_applicable': 0},
                   'observations': [{
                       'outcome': 'insecure', 'resource_path': 'iam.roles.example',
                       'resource_identity': {'resource_id': 'example'},
                       'predicate_checks': [{'label': 'state',
                           'state': 'CONFIRMED', 'detail': 'candidate',
                           'source': 'iam.roles.example.p5d_status',
                           'required': True}]}]}}
    card = build_resource_cards(finding)[0]
    assert card['confidence'] == 'UNKNOWN'
    assert card['verification_status'] == 'UNKNOWN'
    assert card['collection'] == 'PARTIAL'
    assert 'RULE_AND_EVIDENCE_COUNT_DIFFERENCE' in card['reason_codes']


def test_p5c_27_adapters_do_not_export_p5d_raw_arns_or_policies():
    source = _source(CASES[0])
    source['services']['iam'] = {
        'attack_paths_p5d': {'edges': {'secret': {
            'source': 'arn:aws:iam::123456789012:role/Secret',
            'target': 'CLIENT_NEVER_EXPORT_POLICY_BODY'}},
        }}
    snapshot = export_semantic_facts(source, KEY)
    serialized = json.dumps(snapshot)
    assert 'CLIENT_NEVER_EXPORT_POLICY_BODY' not in serialized
    assert 'arn:aws:iam::123456789012:role/Secret' not in serialized
    assert len(snapshot['rules']) == len(ADAPTERS) == 27
    result = replay_semantic_facts(snapshot, KEY)
    assert result['raw_resource_identifiers_available'] is False
    assert result['effective_permission_verified'] is False
