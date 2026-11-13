"""P0 integration: actual JSON rule traversal, precomputed resource evidence, and statuses.

These checks verify that rule conditions *flag resources*, not merely that
classifier helper functions return an expected string.
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from ScoutSuite.core.utils import recurse
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.providers.aws.resources.ec2.direct_https import classify_direct_public_https
from ScoutSuite.providers.aws.resources.acm.certificates import Certificates
from ScoutSuite.providers.aws.resources.cloudwatch.base import CloudWatch


FINDINGS = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules/findings'
REGION = 'eu-central-1'


def _run(rule_name, services):
    definition = json.loads((FINDINGS / rule_name).read_text(encoding='utf-8'))
    config = SimpleNamespace(
        conditions=definition['conditions'], path=definition['path'],
        id_suffix=definition.get('id_suffix'),
        evidence_policy=definition.get('evidence_policy'),
        filename=rule_name, checked_items=0)
    matches = recurse(services, services, config.path.split('.'), [], config, True)
    evidence = evaluate_rule_evidence(config, services)
    return matches, evidence


def test_ec2_live_public_https_flags_and_stopped_does_not():
    instance = {'State': {'Name': 'running'}, 'network_interfaces': {
        'eni': {'Association': {'PublicIp': '203.0.113.42'},
                'Groups': [{'GroupId': 'sg1'}], 'Ipv6Addresses': []}}}
    group = {'rules': {'ingress': {'protocols': {'TCP': {'ports': {
        '443': {'cidrs': [{'CIDR': '0.0.0.0/0'}]}}}}}}}
    instance['public_https_status'] = classify_direct_public_https(instance, {'sg1': group})
    services = {'ec2': {'regions': {REGION: {'vpcs': {'vpc1': {'instances': {'i1': instance}}}}}}}
    matches, evidence = _run('ec2-public-instance-https-open-to-world.json', services)
    assert len(matches) == 1 and 'i1' in matches[0]
    assert evidence['counts']['insecure'] == 1
    instance['State'] = {'Name': 'stopped'}
    instance['public_https_status'] = classify_direct_public_https(instance, {'sg1': group})
    matches, evidence = _run('ec2-public-instance-https-open-to-world.json', services)
    assert matches == []
    assert evidence['counts']['not_applicable'] == 1


def test_acm_two_certificates_same_domain_produce_independent_findings():
    obj = Certificates.__new__(Certificates)
    now = datetime.now(timezone.utc)
    certs = {}
    for suffix, days in (('soon', 34), ('later', 90)):
        arn = f'arn:aws:acm:eu-central-1:123:certificate/{suffix}'
        key, certificate = obj._parse_certificate({
            'DomainName': '*.example.org', 'CertificateArn': arn,
            'Type': 'IMPORTED',
            'InUseBy': ['arn:aws:elasticloadbalancing:eu-central-1:123:loadbalancer/app/test'],
            'NotAfter': now + timedelta(days=days)})
        certs[key] = certificate
    assert len(certs) == 2
    services = {'acm': {'regions': {REGION: {'certificates': certs}}}}
    expiring, evidence1 = _run('acm-certificate-with-close-expiration-date.json', services)
    imported, evidence2 = _run('acm-imported-certificate-renewal-review.json', services)
    assert len(expiring) == 1 and evidence1['counts']['insecure'] == 1
    assert len(imported) == 2 and evidence2['counts']['insecure'] == 2


def test_cloudwatch_empty_complete_alarms_and_filters_are_reported():
    service = CloudWatch.__new__(CloudWatch)
    service.facade = SimpleNamespace(cloudwatch=SimpleNamespace(
        metric_filter_collection_status={REGION: 'complete'},
        alarm_collection_status={REGION: 'complete'}))
    service['regions'] = {REGION: {'metric_filters': {}, 'alarms': {}}}
    asyncio.run(service.finalize())
    services = {'cloudwatch': service}
    matches, evidence = _run('cloudwatch-security-metric-alerting-missing.json', services)
    assert len(matches) == 1
    assert evidence['counts']['insecure'] == 1
    service['regions'][REGION]['metric_filters_collection_status'] = 'unknown'
    service['regions'][REGION]['security_metric_alerting_status'] = 'unknown'
    matches, evidence = _run('cloudwatch-security-metric-alerting-missing.json', services)
    assert matches == []
    assert evidence['counts']['unknown'] == 1
    assert evidence['assessment_status'] == 'incomplete'
