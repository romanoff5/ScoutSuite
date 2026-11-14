"""Metamorphic / adversarial AWS regression tests.

Each scenario starts with a synthetic AWS inventory, changes exactly one
input field, reruns the production classifier/correlator, and evaluates the
real published JSON rule. Nothing reaches a customer AWS account.

Crucial contract: API denial or incomplete inventory must not be reported
as a verified secure/clean finding. N/A is distinct from PASS.
"""
import asyncio
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.core.utils import recurse
from ScoutSuite.providers.aws.facade.cloudwatch import CloudWatch as CloudWatchFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.cloudwatch.base import CloudWatch
from ScoutSuite.providers.aws.resources.ec2.direct_https import classify_direct_public_https
from ScoutSuite.providers.aws.resources.elbv2.p3b_correlation import correlate_p3b
from ScoutSuite.providers.aws.resources.elbv2.p3d_health import annotate_alb_health
from ScoutSuite.providers.aws.resources.rds.proxy_health import classify_proxy_targets

REGION = 'eu-central-1'
LB_DNS = 'web-123.eu-central-1.elb.amazonaws.com'
CERT = 'arn:aws:acm:eu-central-1:111111111111:certificate/synthetic'
TG = 'arn:aws:elasticloadbalancing:eu-central-1:111111111111:targetgroup/synthetic'
RULES = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules/findings'
SELECTED = ('elbv2', 'ec2', 'acm', 'route53')


def diff_count(left, right):
    """Count differing leaves; length changes count as one list mutation."""
    if type(left) is not type(right):
        return 1
    if isinstance(left, dict):
        common = left.keys() & right.keys()
        return (len(left.keys() ^ right.keys()) +
                sum(diff_count(left[k], right[k]) for k in common))
    if isinstance(left, list):
        if len(left) != len(right):
            return 1
        return sum(diff_count(a, b) for a, b in zip(left, right))
    return int(left != right)


def mutate_one(seed, path, new_value):
    """Return an isolated fixture with EXACTLY one input-field mutation."""
    old = deepcopy(seed)
    changed = deepcopy(seed)
    cursor = changed
    for part in path[:-1]:
        cursor = cursor[part]
    last = path[-1]
    assert last in cursor, 'Mutation path must reference an existing input'
    cursor[last] = deepcopy(new_value)
    assert diff_count(seed, changed) == 1, 'Exactly one input field may change'
    assert seed == old, 'Mutations must never leak back into the baseline fixture'
    return changed


def evaluate(filename, services, expected):
    """Execute both rule traversal and policy evidence, not only a helper."""
    doc = json.loads((RULES / filename).read_text(encoding='utf-8'))
    rule = SimpleNamespace(filename=filename, path=doc['path'],
                           conditions=doc['conditions'],
                           id_suffix=doc.get('id_suffix'),
                           evidence_policy=doc['evidence_policy'],
                           checked_items=0)
    hits = recurse(services, services, rule.path.split('.'), [], rule, True)
    summary = evaluate_rule_evidence(rule, services)
    counts = summary['counts']
    assert counts[expected] == 1, (filename, expected, counts)
    assert sum(counts.values()) == 1, (filename, counts)
    assert len(hits) == int(expected == 'insecure'), (filename, expected, hits)
    if expected == 'unknown':
        assert counts['secure'] == 0
        assert summary['assessment_status'] == 'incomplete'
    return hits, summary


def ec2_fixture():
    return {'ec2': {'regions': {REGION: {'vpcs': {'vpc-1': {
        'instances': {'i-1': {
            'State': {'Name': 'running'},
            'network_interfaces': {'eni-1': {
                'Association': {'PublicIp': '203.0.113.12'},
                'Ipv6Addresses': [],
                'Groups': [{'GroupId': 'sg-1'}]}}
        }},
        'security_groups': {'sg-1': {'rules': {'ingress': {'protocols': {
            'TCP': {'ports': {'443': {'cidrs': [{'CIDR': '0.0.0.0/0'}]}}}
        }}}}}
    }}}}}}


def eval_ec2(source, expected):
    services = deepcopy(source)
    vpc = services['ec2']['regions'][REGION]['vpcs']['vpc-1']
    instance = vpc['instances']['i-1']
    instance['public_https_status'] = classify_direct_public_https(
        instance, vpc['security_groups'])
    evaluate('ec2-public-instance-https-open-to-world.json', services, expected)
    return instance['public_https_status']


@pytest.mark.parametrize('suffix,value,status,evidence', [
    (('instances', 'i-1', 'State', 'Name'), 'stopped',
     'not_applicable', 'not_applicable'),
    (('instances', 'i-1', 'State', 'Name'), None,
     'unknown', 'unknown'),
    (('instances', 'i-1', 'network_interfaces', 'eni-1', 'Association',
      'PublicIp'), None, 'not_exposed', 'secure'),
    (('security_groups', 'sg-1', 'rules', 'ingress', 'protocols', 'TCP',
      'ports', '443', 'cidrs', 0, 'CIDR'), '10.0.0.0/8',
     'not_exposed', 'secure'),
    (('instances', 'i-1', 'network_interfaces', 'eni-1', 'Groups', 0,
      'GroupId'), 'sg-not-collected', 'unknown', 'unknown'),
])
def test_ec2_running_to_stopped_and_missing_eni_sg_evidence(
        suffix, value, status, evidence):
    baseline = ec2_fixture()
    assert eval_ec2(baseline, 'insecure') == 'exposed'
    mutated = mutate_one(
        baseline, ('ec2', 'regions', REGION, 'vpcs', 'vpc-1') + suffix, value)
    assert eval_ec2(mutated, evidence) == status
    assert eval_ec2(baseline, 'insecure') == 'exposed'


def alb_fixture():
    source = ec2_fixture()
    ec2_vpc = source['ec2']['regions'][REGION]['vpcs']['vpc-1']
    # Backend target uses HTTP/8080; the public HTTPS rule is independent.
    ec2_vpc['security_groups']['sg-1']['rules']['ingress']['protocols'][
        'TCP']['ports']['8080'] = {'cidrs': [{'CIDR': '0.0.0.0/0'}]}
    lb = {
        'Type': 'application', 'Scheme': 'internet-facing',
        'DNSName': LB_DNS, 'waf_protection_status': 'aws_waf',
        'listeners': {443: {
            'Protocol': 'HTTPS', 'certificate_inventory_status': 'complete',
            'certificate_arns': [CERT]}},
        'target_group_inventory_status': 'complete',
        'target_groups': [{
            'arn': TG, 'name': 'synthetic-backend', 'protocol': 'HTTP',
            'target_type': 'instance', 'port': 8080,
            'health_check': {'HealthCheckPath': '/health',
                             'Matcher': {'HttpCode': '200'}},
            'registered_targets': [{
                'id': 'i-1', 'port': 8080, 'health_state': 'healthy',
                'health_reason': None}]
        }]
    }
    source['elbv2'] = {'regions': {REGION: {
        'vpcs': {'vpc-1': {'lbs': {'web': lb}}}}}}
    source['acm'] = {'regions': {REGION: {'certificates': {
        'cert-1': {'arn': CERT, 'SubjectAlternativeNames': ['web.example.net']}
    }}}}
    source['route53'] = {'regions': {'global': {'hosted_zones': {
        'zone-1': {'config': {'PrivateZone': False},
                   'resource_record_sets': [{
                       'Name': 'web.example.net.', 'Type': 'A',
                       'AliasTarget': {'DNSName': 'dualstack.' + LB_DNS + '.'}}]}
    }}}}
    return source


def annotate_alb(source):
    services = deepcopy(source)
    correlate_p3b(services, SELECTED)
    annotate_alb_health(services)
    lb = services['elbv2']['regions'][REGION]['vpcs']['vpc-1']['lbs']['web']
    return services, lb


LB_BASE = ('elbv2', 'regions', REGION, 'vpcs', 'vpc-1',
           'lbs', 'web')
TG_BASE = LB_BASE + ('target_groups', 0)
CERT_BASE = ('acm', 'regions', REGION, 'certificates', 'cert-1')


@pytest.mark.parametrize('path,value,expected_status,evidence', [
    (TG_BASE + ('registered_targets',), [],
     'not_applicable', 'not_applicable'),
    (LB_BASE + ('target_group_inventory_status',), 'partial',
     'unknown', 'unknown'),
    (('ec2', 'regions', REGION, 'vpcs', 'vpc-1',
      'instances', 'i-1', 'network_interfaces', 'eni-1',
      'Association', 'PublicIp'), None,
     'no_direct_backend_path', 'secure'),
    (('ec2', 'regions', REGION, 'vpcs', 'vpc-1',
      'instances', 'i-1', 'network_interfaces', 'eni-1',
      'Groups', 0, 'GroupId'), 'not-collected',
     'unknown', 'unknown'),
])
def test_alb_registered_target_removal_and_unknown_network_inventory(
        path, value, expected_status, evidence):
    original = alb_fixture()
    services, lb = annotate_alb(original)
    assert lb['backend_bypass_status'] == 'potential_bypass'
    evaluate('elbv2-waf-backend-public-bypass-candidate.json',
             services, 'insecure')
    mutant = mutate_one(original, path, value)
    services, lb = annotate_alb(mutant)
    assert lb['backend_bypass_status'] == expected_status
    evaluate('elbv2-waf-backend-public-bypass-candidate.json',
             services, evidence)


@pytest.mark.parametrize('path,value,raw_status,evidence', [
    (CERT_BASE + ('SubjectAlternativeNames', 0),
     'other.example.net', 'mismatch', 'insecure'),
    (CERT_BASE + ('SubjectAlternativeNames',),
     None, 'unknown', 'unknown'),
    (LB_BASE + ('listeners', 443, 'certificate_inventory_status'),
     'partial', 'unknown', 'unknown'),
    (('route53', 'regions', 'global', 'hosted_zones', 'zone-1',
      'resource_record_sets'), [], 'unknown', 'unknown'),
])
def test_certificate_san_change_and_incomplete_sni_or_dns_inventory(
        path, value, raw_status, evidence):
    original = alb_fixture()
    services, lb = annotate_alb(original)
    assert lb['https_hostname_coverage_status'] == 'covered'
    evaluate('elbv2-https-hostname-not-in-listener-certificate.json',
             services, 'secure')
    mutant = mutate_one(original, path, value)
    services, lb = annotate_alb(mutant)
    assert lb['https_hostname_coverage_status'] == raw_status
    evaluate('elbv2-https-hostname-not-in-listener-certificate.json',
             services, evidence)


def health_mismatch_fixture():
    base = alb_fixture()
    row = (base['elbv2']['regions'][REGION]['vpcs']['vpc-1']['lbs']['web']
           ['target_groups'][0]['registered_targets'][0])
    row['health_state'] = 'unhealthy'
    row['health_reason'] = 'Target.ResponseCodeMismatch'
    return base


@pytest.mark.parametrize('path,value,status,evidence', [
    (TG_BASE + ('registered_targets',), [],
     'not_applicable', 'not_applicable'),
    (LB_BASE + ('target_group_inventory_status',), 'partial',
     'unknown', 'unknown'),
    (TG_BASE + ('registered_targets', 0, 'health_state'),
     'healthy', 'not_observed', 'secure'),
])
def test_alb_health_mismatch_transition_with_single_change(
        path, value, status, evidence):
    baseline = health_mismatch_fixture()
    before, lb_before = annotate_alb(baseline)
    assert lb_before['p3d_health_mismatch_status'] == 'response_mismatch'
    assert len(lb_before['p3d_health_mismatch_evidence']) == 1
    evaluate('elbv2-alb-health-check-response-mismatch.json',
             before, 'insecure')
    mutant = mutate_one(baseline, path, value)
    after, lb = annotate_alb(mutant)
    assert lb['p3d_health_mismatch_status'] == status
    assert lb['p3d_health_mismatch_evidence'] == []
    evaluate('elbv2-alb-health-check-response-mismatch.json',
             after, evidence)


def test_reprocessing_same_alb_does_not_retain_stale_mismatch_evidence():
    services, lb = annotate_alb(health_mismatch_fixture())
    assert len(lb['p3d_health_mismatch_evidence']) == 1
    # This is a single raw-input mutation on the same resource object, without
    # constructing another service snapshot.
    lb['target_groups'][0]['registered_targets'] = []
    annotate_alb_health(services)
    assert lb['p3d_health_mismatch_status'] == 'not_applicable'
    assert lb['p3d_health_mismatch_evidence'] == []
    evaluate('elbv2-alb-health-check-response-mismatch.json',
             services, 'not_applicable')


def proxy_fixture():
    return {'proxy_status': 'available',
            'collection': {'status': 'complete', 'targets': [
                {'TargetArn': 'arn:aws:rds:eu-central-1:111:db:synthetic',
                 'TargetHealth': {'State': 'AVAILABLE'}}]}}


def eval_proxy(source, rule, expected):
    raw_state = classify_proxy_targets(
        source['proxy_status'], source['collection'], None)
    proxy = {'target_health_status': raw_state}
    services = {'rds': {'regions': {REGION: {'proxies': {'proxy': proxy}}}}}
    evaluate(rule, services, expected)
    return raw_state


@pytest.mark.parametrize('path,value,raw_status,evidence,rule', [
    (('collection', 'targets'), [], 'no_targets', 'insecure',
     'rds-proxy-no-registered-targets.json'),
    (('collection', 'status'), 'partial', 'unknown', 'unknown',
     'rds-proxy-no-registered-targets.json'),
    (('collection', 'targets', 0, 'TargetHealth', 'State'),
     'UNAVAILABLE', 'all_unavailable', 'insecure',
     'rds-proxy-all-targets-unavailable.json'),
    (('proxy_status',), 'creating', 'unknown', 'unknown',
     'rds-proxy-no-registered-targets.json'),
])
def test_rds_proxy_targets_loss_and_partial_collection(
        path, value, raw_status, evidence, rule):
    baseline = proxy_fixture()
    assert eval_proxy(baseline, 'rds-proxy-no-registered-targets.json',
                      'secure') == 'healthy'
    mutant = mutate_one(baseline, path, value)
    assert eval_proxy(mutant, rule, evidence) == raw_status


def cloudwatch_snapshot(access):
    """Run actual facade and resource finalizer; use no real AWS clients."""
    client = Mock()

    def paginator(operation):
        if access[operation] == 'denied':
            raise PermissionError('Synthetic AccessDenied')
        p = Mock()
        name = {'describe_metric_filters': 'metricFilters',
                'describe_alarms': 'MetricAlarms'}[operation]
        p.paginate.return_value = iter([{name: []}])
        return p

    client.get_paginator.side_effect = paginator
    facade = CloudWatchFacade(object())

    async def collect():
        with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
            await facade.get_metric_filters(REGION)
            await facade.get_alarms(REGION)

    asyncio.run(collect())
    resource = CloudWatch.__new__(CloudWatch)
    resource.facade = SimpleNamespace(cloudwatch=facade)
    resource['regions'] = {REGION: {'metric_filters': {}, 'alarms': {}}}
    asyncio.run(resource.finalize())
    services = {'cloudwatch': {'regions': resource['regions']}}
    return services, resource['regions'][REGION]


@pytest.mark.parametrize('api', ['describe_metric_filters', 'describe_alarms'])
def test_access_revocation_never_transforms_missing_alert_into_pass(api):
    baseline = {'describe_metric_filters': 'allowed',
                'describe_alarms': 'allowed'}
    before, region = cloudwatch_snapshot(baseline)
    assert region['security_metric_alerting_status'] == 'missing'
    evaluate('cloudwatch-security-metric-alerting-missing.json',
             before, 'insecure')

    mutant = mutate_one(baseline, (api,), 'denied')
    after, region = cloudwatch_snapshot(mutant)
    assert region['security_metric_alerting_status'] == 'unknown'
    assert region['metric_filters_collection_status'] == (
        'unknown' if api == 'describe_metric_filters' else 'complete')
    assert region['metric_alarms_collection_status'] == (
        'unknown' if api == 'describe_alarms' else 'complete')
    evaluate('cloudwatch-security-metric-alerting-missing.json',
             after, 'unknown')


def test_mutation_harness_detects_multiple_field_edits():
    seed = {'instance_state': 'running', 'permission': 'allowed'}
    changed = deepcopy(seed)
    changed.update(instance_state='stopped', permission='denied')
    assert diff_count(seed, changed) == 2
    with pytest.raises(AssertionError, match='Exactly one input field'):
        mutate_one(seed, ('instance_state',), 'running')
