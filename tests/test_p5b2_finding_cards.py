"""P5-B2: offline-only per-resource criteria and honest uncertainty."""
import json
from pathlib import Path
from types import SimpleNamespace

from ScoutSuite.core.finding_cards import build_resource_cards, build_observation_checks
from ScoutSuite.core.finding_confidence import build_finding_confidence
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence


def assess(policy, path, services, hits=1, status=None, level='danger'):
    rule = SimpleNamespace(evidence_policy=policy, path=path, filename='synthetic.json')
    summary = evaluate_rule_evidence(rule, services)
    finding = {'level': level, 'flagged_items': hits,
               'assessment_status': status or summary['assessment_status'],
               'evaluation_summary': summary}
    finding['confidence_assessment'] = build_finding_confidence(rule, finding)
    return finding, build_resource_cards(finding)


EC2_PATH = 'ec2.regions.id.vpcs.id.instances.id'


def ec2_services(cidr='0.0.0.0/0', ip='198.51.100.17', state='running',
                 status='exposed', name='Example EC2'):
    instance = {
        'id': 'i-0abc123', 'name': name,
        'arn': 'arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123',
        'State': {'Name': state}, 'public_https_status': status,
        'network_interfaces': {'eni-0abc': {
            'Association': {'PublicIp': ip} if ip else {},
            'Ipv6Addresses': [], 'Groups': [{'GroupId': 'sg-0abc'}],
        }},
        'password': 'do-not-copy',
    }
    sg = {'rules': {'ingress': {'protocols': {
        'TCP': {'ports': {'443': {'cidrs': [{'CIDR': cidr}]}}}
    }}}}
    return {'ec2': {'regions': {'eu-west-1': {'vpcs': {'vpc-0abc': {
        'instances': {'i-0abc123': instance},
        'security_groups': {'sg-0abc': sg},
    }}}}}}


def test_ec2_direct_card_is_potential_with_exact_witnesses():
    _, cards = assess('ec2-direct-public-https-v1', EC2_PATH, ec2_services())
    card = cards[0]
    assert card['severity'] == 'HIGH'
    assert card['confidence'] == 'MEDIUM'
    assert card['collection'] == 'COMPLETE'
    assert card['reachability'] == 'NOT_VERIFIED'
    assert card['verification_status'] == 'POTENTIAL'
    assert card['confirmed_required_conditions'] == card['required_conditions'] == 4
    assert card['resource_arn'].endswith('instance/i-0abc123')
    evidence = json.dumps(card)
    assert all(value in evidence for value in ('198.51.100.17', 'sg-0abc', '0.0.0.0/0'))
    assert 'password' not in evidence
    assert any(item['state'] == 'NOT_VERIFIED' for item in card['supporting_evidence'])


def test_ec2_contradictory_sg_is_not_confirmed():
    _, cards = assess('ec2-direct-public-https-v1', EC2_PATH,
                      ec2_services(cidr='192.0.2.0/24'))
    assert cards[0]['confidence'] == 'UNKNOWN'
    assert 'PREDICATE_CONTRADICTION' in cards[0]['reason_codes']


def test_ec2_missing_sg_is_unknown_not_pass():
    services = ec2_services()
    del services['ec2']['regions']['eu-west-1']['vpcs']['vpc-0abc']['security_groups']
    _, cards = assess('ec2-direct-public-https-v1', EC2_PATH, services)
    assert cards[0]['confidence'] == 'UNKNOWN'
    assert cards[0]['collection'] == 'PARTIAL'


def test_two_resources_have_separate_confidence_and_scope():
    services = ec2_services()
    instances = services['ec2']['regions']['eu-west-1']['vpcs']['vpc-0abc']['instances']
    instances['i-unknown'] = {'id': 'i-unknown', 'public_https_status': 'unknown'}
    finding, cards = assess('ec2-direct-public-https-v1', EC2_PATH,
                            services, status='incomplete')
    assert finding['evaluation_summary']['counts']['unknown'] == 1
    assert len(cards) == 2
    by_id = {card['resource_id']: card for card in cards}
    assert by_id['i-0abc123']['confidence'] == 'MEDIUM'
    assert by_id['i-0abc123']['collection'] == 'PARTIAL'
    assert by_id['i-unknown']['confidence'] == 'UNKNOWN'


def test_iam_candidate_retains_real_arn_not_secret():
    arn = 'arn:aws:iam::123456789012:user/Builder'
    services = {'iam': {'users': {'AIDA123': {
        'id': 'AIDA123', 'name': 'Builder', 'arn': arn,
        'p4b2_user_passrole_status': 'candidate', 'access_token': 'NEVER-RENDER'
    }}}}
    _, cards = assess('iam-p4b2-user-passrole-v1', 'iam.users.id', services)
    assert cards[0]['resource_arn'] == arn
    assert cards[0]['confidence'] == 'MEDIUM'
    assert any(c['label'] == 'Effective IAM authorization' and c['state'] == 'NOT_VERIFIED'
               for c in cards[0]['supporting_evidence'])
    assert 'NEVER-RENDER' not in json.dumps(cards)


def test_cloudwatch_complete_local_gap_is_not_delivery_proof():
    services = {'cloudwatch': {'regions': {'eu-west-1': {
        'security_metric_alerting_status': 'missing',
        'metric_filters_collection_status': 'complete',
        'metric_alarms_collection_status': 'complete',
    }}}}
    _, cards = assess('cloudwatch-security-metric-alerting-v1', 'cloudwatch.regions.id', services)
    assert cards[0]['confidence'] == 'HIGH'
    assert cards[0]['collection'] == 'COMPLETE'
    assert any(c['state'] == 'NOT_VERIFIED' and 'SIEM' in c['label']
               for c in cards[0]['supporting_evidence'])


def test_backup_does_not_assert_rpo_rto():
    services = {'backup': {'regions': {'eu-west-1': {'latest_restore_job_status': 'failed'}}}}
    _, cards = assess('backup-latest-restore-failure-v1', 'backup.regions.id', services)
    assert cards[0]['confidence'] == 'MEDIUM'
    assert cards[0]['verification_status'] == 'OBSERVED_PARTIAL_SCOPE'
    assert any('RPO or RTO' in c['detail'] for c in cards[0]['supporting_evidence'])


def test_alb_bypass_preserves_instance_sg_target_and_arn():
    services = {'elbv2': {'regions': {'eu-west-1': {'vpcs': {'vpc-0abc': {
        'lbs': {'lb': {
            'id': 'lb',
            'arn': 'arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/example/abc',
            'backend_bypass_status': 'potential_bypass',
            'backend_bypass_evidence': [{'instance_id': 'i-0abc123',
                'security_group_id': 'sg-0abc',
                'target_group_arn': 'arn:aws:elasticloadbalancing:eu-west-1:123456789012:targetgroup/tg/abc',
                'target_port': 443, 'target_health': 'healthy'}],
        }},
    }}}}}}
    _, cards = assess('p3b-alb-backend-bypass-v1',
                      'elbv2.regions.id.vpcs.id.lbs.id', services)
    assert cards[0]['confidence'] == 'MEDIUM'
    assert cards[0]['collection'] == 'COMPLETE'
    assert all(value in json.dumps(cards) for value in ('targetgroup/tg/abc', 'sg-0abc'))
    assert cards[0]['reachability'] == 'NOT_VERIFIED'


def test_json_roundtrip_and_old_report_without_cards():
    assert build_resource_cards({'flagged_items': 1}) == []
    finding, cards = assess('ec2-direct-public-https-v1', EC2_PATH, ec2_services())
    finding['finding_cards'] = cards
    decoded = json.loads(json.dumps(finding))
    assert decoded['finding_cards'][0]['resource_id'] == 'i-0abc123'
    assert decoded['evaluation_summary']['observations'][0]['resource_identity']['resource_id'] == 'i-0abc123'


def test_html_template_escapes_hostile_names_and_evidence_text():
    html = (Path(__file__).resolve().parents[1] /
            'ScoutSuite/output/data/html/partials/dashboard.html').read_text()
    for marker in ('{{resource_name}}', '{{resource_arn}}', '{{resource_id}}',
                   '{{confidence}}', '{{collection}}', '{{reachability}}',
                   '{{detail}}', '{{source}}'):
        assert marker in html
    assert '{{{' not in html
    _, cards = assess('ec2-direct-public-https-v1', EC2_PATH,
                      ec2_services(name='<img src=x onerror=alert(1)>'))
    assert cards[0]['resource_name'].startswith('<img')


def test_uncollected_or_malformed_classifier_never_means_contradicted_or_leaks():
    path = 'iam.users.user-1'
    for status in (None, 'unknown', 'unavailable', 'incomplete',
                   {'secret_token': 'NEVER_RENDER_RAW'}):
        checks = build_observation_checks(
            'iam-p4b2-user-passrole-v1',
            {'p4b2_user_passrole_status': status},
            {}, path, 'unknown')
        assert checks[0]['state'] == 'UNKNOWN'
        assert 'NEVER_RENDER_RAW' not in json.dumps(checks)
    checks = build_observation_checks(
        'iam-p4b2-user-passrole-v1',
        {'p4b2_user_passrole_status': 'not_applicable'},
        {}, path, 'secure')
    assert checks[0]['state'] == 'CONTRADICTED'


def test_p5d_iam_candidate_requires_correlated_edge_evidence_for_confidence():
    resource = {'p5d_service_delegation_status': 'candidate',
                'p5d_service_delegation_edges': [],
                'arn': 'arn:aws:iam::123456789012:role/Builder'}
    services = {'iam': {'roles': {'builder': resource}}}
    _, cards = assess('p5d-iam-delegation-v1', 'iam.roles.id', services)
    assert cards[0]['confidence'] == 'UNKNOWN'
    assert cards[0]['collection'] == 'PARTIAL'
    assert 'REQUIRED_PREDICATE_UNVERIFIED' in cards[0]['reason_codes']
    resource['p5d_service_delegation_edges'] = ['f' * 24]
    _, cards = assess('p5d-iam-delegation-v1', 'iam.roles.id', services)
    assert cards[0]['confidence'] == 'MEDIUM'
    assert cards[0]['claim_type'] == 'POTENTIAL_ATTACK_PATH'
    assert cards[0]['collection'] == 'COMPLETE'
    assert cards[0]['verification_status'] == 'POTENTIAL'
    assert any(c['label'] == 'Effective IAM authorization'
               and c['state'] == 'NOT_VERIFIED' for c in cards[0]['supporting_evidence'])


def test_p5d_cross_account_bucket_scoped_edge_card_requires_edge_id():
    bucket = {'p5d_cross_account_status': 'candidate',
              'p5d_cross_account_edges': []}
    _, cards = assess('p5d-cross-account-v1', 's3.buckets.id',
                      {'s3': {'buckets': {'audit': bucket}}})
    assert cards[0]['confidence'] == 'UNKNOWN'
    bucket['p5d_cross_account_edges'] = ['0' * 24]
    _, cards = assess('p5d-cross-account-v1', 's3.buckets.id',
                      {'s3': {'buckets': {'audit': bucket}}})
    assert cards[0]['confidence'] == 'MEDIUM'
    assert cards[0]['verification_status'] == 'POTENTIAL'
