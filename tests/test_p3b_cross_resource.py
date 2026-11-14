"""P3-B offline regression: cross-resource candidates, SNI coverage and Object Lock.

Only synthetic AWS inventory and mocked read-only clients are used.
"""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.core.utils import recurse
from ScoutSuite.providers.aws.facade.elbv2 import ELBv2Facade
from ScoutSuite.providers.aws.facade.s3 import S3Facade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.elbv2.p3b_correlation import (
    _san_covers, correlate_p3b)

REGION = 'eu-central-1'
LB_DNS = 'web-123.eu-central-1.elb.amazonaws.com'
CERT = 'arn:aws:acm:eu-central-1:123456789012:certificate/test'
TG = 'arn:aws:elasticloadbalancing:eu-central-1:123456789012:targetgroup/app/abc'
ROOT = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules'


def actual_rule(filename, services):
    data = json.loads((ROOT / 'findings' / filename).read_text(encoding='utf-8'))
    rule = SimpleNamespace(filename=filename, path=data['path'],
                           conditions=data['conditions'], id_suffix=data['id_suffix'],
                           evidence_policy=data['evidence_policy'], checked_items=0)
    items = recurse(services, services, rule.path.split('.'), [], rule, True)
    summary = evaluate_rule_evidence(rule, services)
    return items, summary['counts']


def inventory(public=True, sg_world=True, waf='aws_waf'):
    instance = {
        'State': {'Name': 'running'},
        'network_interfaces': {'eni-01': {
            'Association': {'PublicIp': '203.0.113.44'} if public else {},
            'Ipv6Addresses': [],
            'Groups': [{'GroupId': 'sg-backend'}]}}
    }
    source = '0.0.0.0/0' if sg_world else '10.0.0.0/8'
    group = {'rules': {'ingress': {'protocols': {
        'TCP': {'ports': {'8000-9000': {'cidrs': [{'CIDR': source}]}}}
    }}}}
    lb = {
        'name': 'web', 'Type': 'application', 'Scheme': 'internet-facing',
        'DNSName': LB_DNS, 'waf_protection_status': waf,
        'listeners': {443: {'Protocol': 'HTTPS', 'certificate_inventory_status': 'complete',
                            'certificate_arns': [CERT]}},
        'target_group_inventory_status': 'complete',
        'target_groups': [{'arn': TG, 'target_type': 'instance', 'port': 8080,
                           'registered_targets': [{'id': 'i-123', 'port': 8080,
                                                   'health_state': 'healthy'}]}]
    }
    services = {
        'elbv2': {'regions': {REGION: {'vpcs': {'vpc-1': {'lbs': {'web': lb}}}}}},
        'ec2': {'regions': {REGION: {'vpcs': {'vpc-1': {
            'instances': {'i-123': instance}, 'security_groups': {'sg-backend': group}
        }}}}},
        'acm': {'regions': {REGION: {'certificates': {'cert-1': {
            'arn': CERT, 'DomainName': 'web.example.net',
            'SubjectAlternativeNames': ['web.example.net', '*.example.org']
        }}}}},
        'route53': {'regions': {'global': {'hosted_zones': {'zone-1': {
            'config': {'PrivateZone': False},
            'resource_record_sets': [{
                'Name': 'web.example.net.', 'Type': 'A',
                'AliasTarget': {'DNSName': 'dualstack.' + LB_DNS + '.'}
            }]
        }}}}}
    }
    return services, lb, instance


def test_p3b_backend_protected_alb_direct_port_bypass_candidate():
    services, lb, _ = inventory()
    correlate_p3b(services, ('elbv2', 'ec2', 'acm', 'route53'))
    assert lb['backend_bypass_status'] == 'potential_bypass'
    assert lb['backend_bypass_evidence'][0]['target_port'] == 8080
    assert lb['https_hostname_coverage_status'] == 'covered'
    bad, evidence = actual_rule('elbv2-waf-backend-public-bypass-candidate.json', services)
    assert len(bad) == 1 and evidence['insecure'] == 1
    bad, evidence = actual_rule('elbv2-https-hostname-not-in-listener-certificate.json', services)
    assert bad == [] and evidence['secure'] == 1


@pytest.mark.parametrize('public,world', [(False, True), (True, False)])
def test_no_direct_backend_path_without_public_ip_or_world_ingress(public, world):
    services, lb, _ = inventory(public=public, sg_world=world)
    correlate_p3b(services, ('elbv2', 'ec2', 'acm', 'route53'))
    assert lb['backend_bypass_status'] == 'no_direct_backend_path'
    bad, evidence = actual_rule('elbv2-waf-backend-public-bypass-candidate.json', services)
    assert not bad and evidence['secure'] == 1


def test_partial_api_unsupported_target_and_unscanned_ec2_are_unknown():
    services, lb, _ = inventory()
    lb['target_group_inventory_status'] = 'unknown'
    correlate_p3b(services, ('elbv2', 'ec2', 'acm', 'route53'))
    assert lb['backend_bypass_status'] == 'unknown'
    lb['target_group_inventory_status'] = 'complete'
    lb['target_groups'][0]['target_type'] = 'ip'
    correlate_p3b(services, ('elbv2', 'ec2', 'acm', 'route53'))
    assert lb['backend_bypass_status'] == 'unknown'
    lb['target_groups'][0]['target_type'] = 'instance'
    correlate_p3b(services, ('elbv2', 'acm', 'route53'))
    assert lb['backend_bypass_status'] == 'unknown'


def test_existing_waf_is_required_for_bypass_label():
    services, lb, _ = inventory(waf='open_without_waf')
    correlate_p3b(services, ('elbv2', 'ec2', 'acm', 'route53'))
    assert lb['backend_bypass_status'] == 'not_applicable'


def test_hostname_mismatch_when_public_alias_and_all_sni_certs_are_known():
    services, lb, _ = inventory()
    acm = services['acm']['regions'][REGION]['certificates']['cert-1']
    acm['SubjectAlternativeNames'] = ['irrelevant.example.org']
    correlate_p3b(services, ('elbv2', 'ec2', 'acm', 'route53'))
    assert lb['https_hostname_coverage_status'] == 'mismatch'
    assert lb['https_hostname_mismatches'] == ['web.example.net']
    flagged, counts = actual_rule('elbv2-https-hostname-not-in-listener-certificate.json', services)
    assert len(flagged) == 1 and counts['insecure'] == 1


def test_missing_listener_certificates_or_route53_scope_yields_unknown():
    services, lb, _ = inventory()
    lb['listeners'][443]['certificate_inventory_status'] = 'unknown'
    correlate_p3b(services, ('elbv2', 'ec2', 'acm', 'route53'))
    assert lb['https_hostname_coverage_status'] == 'unknown'
    lb['listeners'][443]['certificate_inventory_status'] = 'complete'
    correlate_p3b(services, ('elbv2', 'ec2', 'acm'))
    assert lb['https_hostname_coverage_status'] == 'unknown'


def test_private_zone_not_used_and_wildcard_matches_one_label_only():
    assert _san_covers('*.example.org', 'web.example.org')
    assert not _san_covers('*.example.org', 'a.b.example.org')
    assert not _san_covers('*.example.org', 'example.org')
    services, lb, _ = inventory()
    zone = services['route53']['regions']['global']['hosted_zones']['zone-1']
    zone['config']['PrivateZone'] = True
    correlate_p3b(services, ('elbv2', 'ec2', 'acm', 'route53'))
    assert lb['https_hostname_coverage_status'] == 'unknown'


def test_sni_list_handles_duplicate_default_and_pagination():
    client = SimpleNamespace()
    attempts = []
    def pages(**args):
        attempts.append(dict(args))
        if 'Marker' in args:
            return {'Certificates': [
                {'CertificateArn': CERT, 'IsDefault': False},
                {'CertificateArn': CERT + '-sni', 'IsDefault': False}]}
        return {'Certificates': [{'CertificateArn': CERT, 'IsDefault': True}],
                'NextMarker': 'next'}
    client.describe_listener_certificates = pages
    facade = ELBv2Facade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
        status, certificates = asyncio.run(
            facade.get_listener_certificate_inventory(REGION, 'arn:listener'))
    assert status == 'complete'
    assert certificates == [CERT, CERT + '-sni']
    assert len(attempts) == 2


def test_target_group_api_denial_does_not_look_like_empty():
    client = SimpleNamespace(describe_target_groups=lambda **kw: (_ for _ in ()).throw(
        PermissionError('denied')))
    facade = ELBv2Facade(object())
    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
        status, records = asyncio.run(facade.get_target_group_inventory(REGION, 'arn:alb'))
    assert (status, records) == ('unknown', [])


def _bucket():
    return {'Name': 'critical-logs', 'region': REGION}


def test_object_lock_required_but_absent_is_a_finding():
    bucket = _bucket()
    facade = S3Facade(object())
    cli = SimpleNamespace(
        get_bucket_tagging=lambda **kwargs: {'TagSet': [
            {'Key': 'ObjectLockRequired', 'Value': 'true'}]},
        get_object_lock_configuration=lambda **kwargs: (_ for _ in ()).throw(
            ClientError({'Error': {'Code': 'ObjectLockConfigurationNotFoundError',
                                   'Message': 'not found'}}, 'GetObjectLockConfiguration')))
    async def collect():
        with patch.object(AWSFacadeUtils, 'get_client', return_value=cli):
            await facade._get_and_set_s3_bucket_tags(bucket)
            await facade._get_and_set_s3_bucket_object_lock(bucket)
    asyncio.run(collect())
    assert bucket['object_lock_requirement'] == 'required'
    assert bucket['object_lock_status'] == 'absent'
    services = {'s3': {'buckets': {'critical-logs': bucket}}}
    hits, counts = actual_rule('s3-critical-bucket-object-lock-absent.json', services)
    assert len(hits) == 1 and counts['insecure'] == 1


def test_object_lock_retention_rule_and_unmarked_bucket_n_a():
    tagged = _bucket()
    unmarked = {'Name': 'ordinary', 'region': REGION}
    facade = S3Facade(object())
    cli = SimpleNamespace(
        get_bucket_tagging=lambda **args: {'TagSet': [
            {'Key': 'security:object-lock-required', 'Value': 'true'}]
            if args['Bucket'] == 'critical-logs' else []},
        get_object_lock_configuration=lambda **kwargs: {
            'ObjectLockConfiguration': {'ObjectLockEnabled': 'Enabled'}})
    async def collect():
        with patch.object(AWSFacadeUtils, 'get_client', return_value=cli):
            for bucket in (tagged, unmarked):
                await facade._get_and_set_s3_bucket_tags(bucket)
                await facade._get_and_set_s3_bucket_object_lock(bucket)
    asyncio.run(collect())
    assert tagged['object_lock_default_retention_status'] == 'missing'
    assert unmarked['object_lock_status'] == 'not_applicable'
    services = {'s3': {'buckets': {'critical': tagged, 'normal': unmarked}}}
    hits, counts = actual_rule('s3-critical-bucket-default-retention-missing.json', services)
    assert len(hits) == 1 and counts['not_applicable'] == 1


def test_object_lock_configured_and_tag_denial_unknown():
    tagged = _bucket()
    denied = {'Name': 'denied-tags', 'region': REGION}
    facade = S3Facade(object())
    def get_tags(**kw):
        if kw['Bucket'] == 'denied-tags':
            raise PermissionError('denied')
        return {'TagSet': [{'Key': 'ObjectLockRequired', 'Value': 'yes'}]}
    cli = SimpleNamespace(
        get_bucket_tagging=get_tags,
        get_object_lock_configuration=lambda **kw: {'ObjectLockConfiguration': {
            'ObjectLockEnabled': 'Enabled',
            'Rule': {'DefaultRetention': {'Mode': 'COMPLIANCE', 'Days': 30}}}})
    async def collect():
        with patch.object(AWSFacadeUtils, 'get_client', return_value=cli):
            for bucket in (tagged, denied):
                await facade._get_and_set_s3_bucket_tags(bucket)
                await facade._get_and_set_s3_bucket_object_lock(bucket)
    asyncio.run(collect())
    assert tagged['object_lock_default_retention_status'] == 'configured'
    assert denied['object_lock_requirement'] == 'unknown'
    assert denied['object_lock_status'] == 'unknown'


def test_rules_enabled_and_manifest_has_all_four():
    profile = json.loads((ROOT / 'rulesets/default.json').read_text())['rules']
    expected = (
        'elbv2-waf-backend-public-bypass-candidate.json',
        'elbv2-https-hostname-not-in-listener-certificate.json',
        's3-critical-bucket-object-lock-absent.json',
        's3-critical-bucket-default-retention-missing.json')
    manifest = json.loads((Path(__file__).resolve().parent /
                           'data/rule-fixtures.json').read_text())
    for name in expected:
        assert profile[name][0]['enabled'] is True
        assert name in manifest['untested']['aws']
