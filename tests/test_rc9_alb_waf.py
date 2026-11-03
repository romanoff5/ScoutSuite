"""RC9: internet-facing ALB WAF protection and CDN/WAF origin range refresh.

Synthetic identifiers only. CDN range refresh uses an injected fetcher; the
offline guard fails the session on any real network attempt.
"""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

import boto3
import pytest
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_alb_waf_protection
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.elbv2 import ELBv2Facade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.ec2.securitygroups import SecurityGroups
from ScoutSuite.providers.aws.resources.elbv2 import cdn_ranges
from ScoutSuite.providers.aws.resources.elbv2.waf_exposure import classify_load_balancer

REGION = 'eu-central-1'
ALB_ARN = 'arn:aws:elasticloadbalancing:eu-central-1:000000000000:loadbalancer/app/web/0123456789abcdef'
ACL_ARN = 'arn:aws:wafv2:eu-central-1:000000000000:regional/webacl/web/11111111-2222-3333-4444-555555555555'
CF_PREFIX = 'pl-0aaaaaaaaaaaaaaaa'


def client(service):
    return boto3.client(service, region_name=REGION, aws_access_key_id='synthetic',
                        aws_secret_access_key='synthetic')


def in_context(scenario):
    async def wrapper():
        ctx = RunContext('aws').setup()
        try:
            return await scenario(), list(ctx.collection_issues)
        finally:
            await ctx.aclose()
    return asyncio.run(wrapper())


def waf_lookup(add):
    async def scenario():
        waf = client('wafv2')
        try:
            with Stubber(waf) as stub:
                add(stub)
                with patch.object(AWSFacadeUtils, 'get_client', return_value=waf):
                    result = await ELBv2Facade(object()).get_web_acl_for_load_balancer(REGION, ALB_ARN)
                stub.assert_no_pending_responses()
        finally:
            waf.close()
        return result
    return in_context(scenario)


def test_web_acl_lookup_states():
    params = {'ResourceArn': ALB_ARN}
    acl = {'Name': 'web', 'Id': '11111111-2222-3333-4444-555555555555', 'ARN': ACL_ARN,
           'DefaultAction': {'Allow': {}}, 'VisibilityConfig': {
               'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True, 'MetricName': 'web'}}
    (status, summary), issues = waf_lookup(lambda s: s.add_response('get_web_acl_for_resource', {'WebACL': acl}, params))
    assert status == 'associated' and summary['arn'] == ACL_ARN and issues == []
    assert waf_lookup(lambda s: s.add_response('get_web_acl_for_resource', {}, params))[0] == ('none', None)
    result, issues = waf_lookup(lambda s: s.add_client_error(
        'get_web_acl_for_resource', service_error_code='AccessDeniedException', http_status_code=400,
        expected_params=params))
    assert result == ('unknown', None)
    assert issues == [{'status': 'denied', 'scope': 'elbv2', 'reason_code': 'GetWebACLForResourceAccessDeniedException'}]


def test_prefix_list_names_are_resolved_once_per_region():
    async def scenario():
        ec2 = client('ec2')
        facade = ELBv2Facade(object())
        try:
            with Stubber(ec2) as stub:
                stub.add_response('describe_managed_prefix_lists', {'PrefixLists': [
                    {'PrefixListId': CF_PREFIX, 'PrefixListName': 'com.amazonaws.global.cloudfront.origin-facing'}]},
                    {'Filters': [{'Name': 'prefix-list-name',
                                  'Values': ['com.amazonaws.global.cloudfront.origin-facing']}]})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=ec2):
                    first = await facade.get_prefix_list_names(REGION, ['com.amazonaws.global.cloudfront.origin-facing'])
                    second = await facade.get_prefix_list_names(REGION, ['com.amazonaws.global.cloudfront.origin-facing'])
                stub.assert_no_pending_responses()
        finally:
            ec2.close()
        return first, second
    (first, second), issues = in_context(scenario)
    assert first == second == {CF_PREFIX: 'com.amazonaws.global.cloudfront.origin-facing'} and issues == []


def security_group(group_id, *permissions):
    raw = {'GroupName': group_id, 'GroupId': group_id, 'Description': 'synthetic', 'OwnerId': '000000000000',
           'IpPermissions': list(permissions), 'IpPermissionsEgress': []}
    resources = SecurityGroups.__new__(SecurityGroups)
    resources.partition, resources.service, resources.region, resources.resource_type = (
        'aws', 'ec2', REGION, 'security-group')
    return resources._parse_security_group(raw)[1]


def permission(port, cidrs=(), v6=(), prefixes=(), groups=(), protocol='tcp'):
    rule = {'IpProtocol': protocol, 'IpRanges': [{'CidrIp': c} for c in cidrs],
            'Ipv6Ranges': [{'CidrIpv6': c} for c in v6], 'PrefixListIds': [{'PrefixListId': p} for p in prefixes],
            'UserIdGroupPairs': [{'GroupId': g} for g in groups]}
    if port is not None:
        rule.update(FromPort=port, ToPort=port)
    return rule


def test_security_group_keeps_prefix_lists_without_changing_rule_count():
    group = security_group('sg-1', permission(443, cidrs=['10.0.0.0/8'], prefixes=[CF_PREFIX]))
    assert group['rules']['ingress']['protocols']['TCP']['ports']['443']['prefix_lists'] == [
        {'PrefixListId': CF_PREFIX, 'Description': None}]
    assert group['rules']['ingress']['count'] == 1


def alb(*groups, waf='none', scheme='internet-facing', kind='application', prefixes=None, listeners=(443,)):
    return {'Type': kind, 'Scheme': scheme, 'listeners': {port: {'Protocol': 'HTTPS'} for port in listeners},
            'security_groups': list(groups), 'waf_web_acl_status': waf,
            'cdn_prefix_lists': {CF_PREFIX: 'com.amazonaws.global.cloudfront.origin-facing'}
            if prefixes is None else prefixes}


def status(lb):
    return classify_load_balancer(lb)['waf_protection_status']


def test_alb_classification_matrix():
    world = security_group('sg-w', permission(443, cidrs=['0.0.0.0/0']))
    world6 = security_group('sg-6', permission(443, v6=['::/0']))
    all_ports = security_group('sg-a', permission(None, cidrs=['0.0.0.0/0'], protocol='-1'))
    ssh_only = security_group('sg-s', permission(22, cidrs=['0.0.0.0/0']), permission(443, cidrs=['10.0.0.0/8']))
    cloudfront = security_group('sg-cf', permission(443, prefixes=[CF_PREFIX]))
    cloudflare = security_group('sg-cl', permission(443, cidrs=['173.245.48.0/20', '104.16.0.0/13'],
                                                    v6=['2606:4700::/32']))
    mixed = security_group('sg-m', permission(443, cidrs=['173.245.48.0/20', '198.51.100.0/24']))
    assert status(alb(world)) == 'open_without_waf'
    assert status(alb(world6)) == 'open_without_waf'
    assert status(alb(all_ports)) == 'open_without_waf'
    assert status(alb(world, waf='associated')) == 'aws_waf'
    assert status(alb(ssh_only)) == 'restricted_origin'  # World-open port is not a listener port.
    lb = classify_load_balancer(alb(cloudfront))
    assert lb['waf_protection_status'] == 'external_waf_likely' and lb['origin_cdn_providers'] == ['CloudFront']
    lb = classify_load_balancer(alb(cloudflare))
    assert lb['waf_protection_status'] == 'external_waf_likely' and lb['origin_cdn_providers'] == ['Cloudflare']
    assert status(alb(mixed)) == 'restricted_origin'
    assert status(alb(security_group('sg-e'))) == 'restricted_origin' and \
        classify_load_balancer(alb(security_group('sg-e')))['origin_exposure'] == 'no_ingress'
    assert status(alb({'GroupId': 'sg-unresolved'})) == 'unknown'
    assert status(alb(world, waf='unknown')) == 'unknown'
    assert status(alb(cloudfront, prefixes=None)) == 'external_waf_likely'
    unresolved_prefixes = alb(cloudfront)
    unresolved_prefixes['cdn_prefix_lists'] = None
    assert status(unresolved_prefixes) == 'unknown'
    assert status(alb(world, scheme='internal')) == 'not_internet_facing'
    assert status(alb(world, kind='network')) == 'not_applicable'
    assert status(alb(world, listeners=())) == 'not_applicable'
    verdicts = {name: classify_alb_waf_protection({'waf_protection_status': name}) for name in (
        'open_without_waf', 'aws_waf', 'external_waf_likely', 'restricted_origin', 'not_internet_facing', 'unknown')}
    assert verdicts == {'open_without_waf': 'insecure', 'aws_waf': 'secure', 'external_waf_likely': 'secure',
                        'restricted_origin': 'secure', 'not_internet_facing': 'not_applicable', 'unknown': 'unknown'}


def test_rule_flags_only_open_albs_without_waf(tmp_path):
    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps({'about': 'Synthetic RC9', 'rules': {
        'elbv2-internet-facing-alb-without-waf.json': [{'enabled': True, 'level': 'warning'}]}}), encoding='utf-8')
    world = security_group('sg-w', permission(443, cidrs=['0.0.0.0/0']))
    lbs = {'open': classify_load_balancer(alb(world)),
           'waf': classify_load_balancer(alb(world, waf='associated')),
           'denied': classify_load_balancer(alb(world, waf='unknown')),
           'internal': classify_load_balancer(alb(world, scheme='internal'))}
    provider = SimpleNamespace(services={'elbv2': {'regions': {REGION: {'vpcs': {'vpc-1': {'lbs': lbs}}}}}},
                               service_list=['elbv2'])
    context = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(rules))).run(provider)
    finally:
        context.cleanup()
    finding = provider.services['elbv2']['findings']['elbv2-internet-facing-alb-without-waf']
    assert finding['items'] == ['elbv2.regions.%s.vpcs.vpc-1.lbs.open.waf_protection_status' % REGION]
    assert finding['evaluation_summary']['counts'] == {'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 1}
    assert finding['assessment_status'] == 'incomplete'


def fake_fetch(overrides=None):
    document = cdn_ranges.bundled_document()
    payloads = {}
    for provider in document['providers'].values():
        for source in provider['sources']:
            if source['format'] == 'lines':
                payloads[source['url']] = b'198.51.100.0/24\n# comment\n2001:db8::/32\n'
            else:
                payloads[source['url']] = json.dumps(
                    {key: ['203.0.113.0/24'] for key in source['keys']}).encode()
    payloads.update(overrides or {})
    calls = []

    def fetch(url, timeout, max_bytes):
        calls.append((url, timeout, max_bytes))
        value = payloads[url]
        if isinstance(value, Exception):
            raise value
        return value
    return fetch, calls


def test_refresh_uses_live_lists_and_falls_back_per_provider():
    document = cdn_ranges.bundled_document()
    akamai_v4 = document['providers']['Akamai']['sources'][0]['url']
    gcore = document['providers']['Gcore']['sources'][0]['url']
    imperva = document['providers']['Imperva']['sources'][0]['url']
    fetch, calls = fake_fetch({akamai_v4: OSError('synthetic offline'), gcore: TimeoutError('synthetic timeout'),
                               imperva: json.dumps({'ipRanges': ['0.0.0.0/1'], 'ipv6Ranges': []}).encode()})
    with patch.object(cdn_ranges, 'print_warning') as warn:
        catalog = cdn_ranges.refresh_cdn_catalog(fetch=fetch)
    providers = catalog['summary']['providers']
    assert providers['Cloudflare']['source'] == 'live' and providers['Cloudflare']['count'] == 2
    assert providers['Fastly']['source'] == 'live'
    assert providers['Akamai'] == {'source': 'bundled', 'reason': 'OSError', 'count': 9}
    assert providers['Imperva']['source'] == 'bundled' and providers['Imperva']['reason'] == 'ValueError'
    assert providers['Gcore'] == {'source': 'unavailable', 'reason': 'TimeoutError', 'count': 0}
    assert all(url.startswith('https://') and timeout == 5 and size == 1048576 for url, timeout, size in calls)
    warnings = [call.args[0] for call in warn.call_args_list]
    assert len(warnings) == 3 and any(w.startswith('CDN range update for Akamai failed (OSError') for w in warnings)
    assert any('Gcore' in w and 'will not be recognised' in w for w in warnings)
    networks = {(name, str(network)) for name, network in catalog['ranges']}
    assert ('Cloudflare', '198.51.100.0/24') in networks and ('Akamai', '23.0.0.0/12') in networks
    assert ('Cloudflare', '173.245.48.0/20') not in networks  # Live list replaces the bundled one.


def test_run_scoped_catalog_drives_classification():
    fetch, _ = fake_fetch()
    origin = security_group('sg-x', permission(443, cidrs=['198.51.100.0/24']))

    async def scenario():
        ctx = RunContext('aws').setup()
        try:
            before = status(alb(origin))
            ctx.cdn_catalog = cdn_ranges.refresh_cdn_catalog(fetch=fetch)
            lb = classify_load_balancer(alb(origin))
            return before, lb
        finally:
            await ctx.aclose()
    before, lb = asyncio.run(scenario())
    assert before == 'restricted_origin'
    assert lb['waf_protection_status'] == 'external_waf_likely'
    assert lb['cdn_catalog_sources']['Cloudflare'] == 'live'
    assert status(alb(origin)) == 'restricted_origin'  # No leakage once the run context is closed.


def test_fetch_rejects_non_https_and_disabled_catalog_is_labelled():
    with pytest.raises(ValueError):
        cdn_ranges.https_get('http://example.invalid/list', 1, 10)
    summary = cdn_ranges.disabled_catalog()['summary']
    assert {row['reason'] for row in summary['providers'].values()} == {'update_disabled'}
    with pytest.raises(ValueError):
        cdn_ranges.validate_entries(['::/8'], cdn_ranges.bundled_document()['limits'])


def test_cli_flag_disables_update():
    from ScoutSuite import __main__ as main
    from ScoutSuite.core.cli_parser import ScoutSuiteArgumentParser
    with patch('sys.argv', ['scout', 'aws', '--no-browser']):
        assert ScoutSuiteArgumentParser().parse_args().cdn_ranges_update is True
    with patch('sys.argv', ['scout', 'aws', '--no-browser', '--no-cdn-range-update']):
        args = ScoutSuiteArgumentParser().parse_args()
    assert args.cdn_ranges_update is False and main._extract_run_args(vars(args))['cdn_ranges_update'] is False
