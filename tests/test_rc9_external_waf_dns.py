"""RC9: opt-in public DNS check of the account's domains for an external WAF/CDN.

The resolver is injected; no real DNS query is made (the offline guard would fail
the session). Domains use reserved example names and documentation addresses.
"""
import json
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ScoutSuite.providers.aws.provider import AWSProvider
from ScoutSuite.providers.aws.resources.elbv2 import dns_front_door
from ScoutSuite.providers.aws.resources.elbv2.dns_front_door import (annotate_load_balancers, check_domains,
                                                                     collect_domains, disabled_result)
from ScoutSuite.providers.base.provider import BaseProvider

ROOT = Path(__file__).resolve().parents[1]
ALB_DNS = 'web-123456789.eu-central-1.elb.amazonaws.com'


def services(*domains):
    certificates = {str(i): {'DomainName': d[0], 'SubjectAlternativeNames': list(d[1:])} for i, d in enumerate(domains)}
    lb = {'name': 'web', 'Scheme': 'internet-facing', 'Type': 'application', 'DNSName': 'dualstack.' + ALB_DNS}
    internal = {'name': 'int', 'Scheme': 'internal', 'Type': 'application', 'DNSName': 'internal-x.elb.amazonaws.com'}
    return {'acm': {'regions': {'eu-central-1': {'certificates': certificates}}},
            'elbv2': {'regions': {'eu-central-1': {'vpcs': {'vpc-1': {'lbs': {'web': lb, 'int': internal}}}}}}}


def test_domains_come_from_acm_names_sans_and_cli():
    found = collect_domains(services(('*.shop.example.com', 'shop.example.com', 'API.Example.com.'),
                                     ('not a domain',)), ['extra.example.org', '-bad.example'])
    assert found == {'shop.example.com': ['acm:eu-central-1'], 'api.example.com': ['acm:eu-central-1'],
                     'extra.example.org': ['cli']}


ANSWERS = {
    'cdn.example.com': (['d111111abcdef8.cloudfront.net'], ['192.0.2.10']),
    'akamai.example.com': (['akamai.example.com.edgekey.net', 'e1.a.akamaiedge.net'], ['192.0.2.11']),
    'cname-alb.example.com': ([ALB_DNS], ['198.51.100.7']),
    'alias-alb.example.com': ([], ['198.51.100.7']),
    'other-elb.example.com': (['other-1.us-east-1.elb.amazonaws.com'], ['198.51.100.99']),
    'proxied.example.com': ([], ['104.16.1.1']),
    'origin.example.com': ([], ['203.0.113.50']),
    ALB_DNS: ([], ['198.51.100.7', '2001:db8::7']),
}


def fake_resolver(name):
    if name == 'missing.example.com':
        raise socket.gaierror('synthetic NXDOMAIN')
    if name == 'broken.example.com':
        raise UnicodeError('synthetic')
    return ANSWERS[name]


def test_classification_of_each_domain():
    names = [n for n in ANSWERS if n != ALB_DNS] + ['missing.example.com', 'broken.example.com']
    data = services(*[(n,) for n in names])
    result = check_domains(data, resolver=fake_resolver)
    by_name = {r['name']: r for r in result['dns_domains'].values()}
    expect = {
        'cdn.example.com': ('cdn_waf_fronted', 'CloudFront', 'cname'),
        'akamai.example.com': ('cdn_waf_fronted', 'Akamai', 'cname'),
        'proxied.example.com': ('cdn_waf_fronted', 'Cloudflare', 'address'),
        'cname-alb.example.com': ('direct_to_alb', None, None),
        'alias-alb.example.com': ('direct_to_alb', None, None),
        'other-elb.example.com': ('direct_to_alb', None, None),
        'origin.example.com': ('direct_other', None, None),
        'missing.example.com': ('not_resolved', None, None),
        'broken.example.com': ('not_resolved', None, None),
    }
    for name, (classification, provider, method) in expect.items():
        row = by_name[name]
        assert (row['classification'], row['front_door_provider'], row['match_method']) == \
            (classification, provider, method), name
    assert by_name['cname-alb.example.com']['alb_name'] == 'web'
    assert by_name['alias-alb.example.com']['alb_dns_name'] == ALB_DNS  # Matched by address.
    assert by_name['other-elb.example.com']['alb_name'] is None
    assert by_name['missing.example.com']['resolution_status'] == 'unresolved'
    assert by_name['broken.example.com']['error_type'] == 'UnicodeError'
    summary = result['external_waf_dns']
    assert summary['enabled'] is True and summary['domains_checked'] == 9 and summary['truncated'] is False
    assert summary['classification_counts'] == {'cdn_waf_fronted': 3, 'direct_to_alb': 3, 'direct_other': 1,
                                                'not_resolved': 2}
    annotate_load_balancers(dict(data, elbv2=dict(data['elbv2'], **result)))
    lb = data['elbv2']['regions']['eu-central-1']['vpcs']['vpc-1']['lbs']['web']
    assert sorted(d['name'] for d in lb['dns_domains']) == ['alias-alb.example.com', 'cname-alb.example.com']
    assert 'dns_domains' not in data['elbv2']['regions']['eu-central-1']['vpcs']['vpc-1']['lbs']['int']


def test_hung_lookup_is_reported_as_timeout_and_limit_as_truncated():
    release = threading.Event()

    def slow(name):
        if name == 'slow.example.com':
            release.wait(5)
        return [], ['198.51.100.7' if name.endswith('.elb.amazonaws.com') else '203.0.113.1']
    try:
        result = check_domains(services(('slow.example.com',), ('fast.example.com',)), resolver=slow, timeout=0.3)
    finally:
        release.set()
    rows = {r['name']: r for r in result['dns_domains'].values()}
    assert rows['slow.example.com']['resolution_status'] == 'timeout'
    assert rows['fast.example.com']['classification'] == 'direct_other'
    with patch.object(dns_front_door, 'MAX_DOMAINS', 1):
        result = check_domains(services(('a.example.com',), ('b.example.com',)), resolver=slow)
    assert result['external_waf_dns']['truncated'] is True and result['dns_domains_count'] == 1


def test_disabled_by_default_and_not_counted_as_inventory():
    from ScoutSuite import __main__ as main
    from ScoutSuite.core.cli_parser import ScoutSuiteArgumentParser
    with patch('sys.argv', ['scout', 'aws', '--no-browser']):
        args = ScoutSuiteArgumentParser().parse_args()
    assert args.external_waf_dns is False and args.waf_domains is None
    with patch('sys.argv', ['scout', 'aws', '--no-browser', '--external-waf-dns', '--waf-domains', 'a.example.com']):
        run_args = main._extract_run_args(vars(ScoutSuiteArgumentParser().parse_args()))
    assert run_args['external_waf_dns'] is True and run_args['waf_domains'] == ['a.example.com']
    assert disabled_result()['external_waf_dns']['enabled'] is False
    provider = SimpleNamespace(
        services={'elbv2': {'regions': {}, 'lbs_count': 0, 'dns_domains_count': 4}}, collection_status={'issues': []},
        COLLECTION_SCOPE_ALIASES={}, NON_INVENTORY_COUNT_KEYS=AWSProvider.NON_INVENTORY_COUNT_KEYS)
    BaseProvider._update_last_run(provider, datetime(2026, 11, 3, tzinfo=timezone.utc),
                                  SimpleNamespace(name='synthetic', about='synthetic'), {})
    assert provider.last_run['summary']['elbv2']['resources_count'] == 0


def test_report_lists_checked_domains_with_escaped_template():
    metadata = json.loads((ROOT / 'ScoutSuite/providers/aws/metadata.json').read_text(encoding='utf-8'))
    assert metadata['compute']['elbv2']['resources']['dns_domains']['path'] == 'services.elbv2.dns_domains'
    text = (ROOT / 'ScoutSuite/output/data/html/partials/aws/services.elbv2.dns_domains.html').read_text(
        encoding='utf-8')
    assert '{{{' not in text and 'onclick' not in text and '<samp>{{classification}}</samp>' in text
    assert 'Handlebars.registerPartial("services.elbv2.dns_domains"' in text
