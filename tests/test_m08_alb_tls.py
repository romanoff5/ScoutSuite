"""M08 ALB TLS 1.2 protocol floor and unknown/inapplicable listener evidence."""
import json
from types import SimpleNamespace

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_alb_listener_tls
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from tests.fixtures import ROOT


CATALOG = ROOT / 'ScoutSuite/providers/aws/rules/catalogs/alb-tls-2026-11.json'


def test_alb_tls_catalog_version_and_policy_sets():
    data = json.loads(CATALOG.read_text(encoding='utf-8'))
    assert data['schema_version'] == 1
    assert data['catalog_version'] == '2026.11.0'
    assert data['review_date'] == '2026-11-01'
    assert data['owner']
    assert all(link.startswith('https://') for link in data['reference_urls'])
    current = set(data['allows_tls_1_2_or_newer_only'])
    legacy = set(data['allows_tls_before_1_2'])
    assert current.isdisjoint(legacy)
    assert 'ELBSecurityPolicy-TLS13-1-3-2021-06' in current
    assert 'ELBSecurityPolicy-TLS13-1-2-PQ-2025-09' in current
    assert 'ELBSecurityPolicy-2016-08' in legacy
    assert 'ELBSecurityPolicy-TLS13-1-0-2021-06' in legacy
    assert 'ELBSecurityPolicy-TLS13-1-1-2021-06' in legacy


def test_alb_protocol_floor_classifies_all_four_states():
    assert classify_alb_listener_tls({
        'Protocol': 'HTTPS',
        'SslPolicy': 'ELBSecurityPolicy-TLS13-1-3-2021-06'
    }) == 'secure'
    assert classify_alb_listener_tls({
        'Protocol': 'HTTPS',
        'SslPolicy': 'ELBSecurityPolicy-TLS13-1-0-2021-06'
    }) == 'insecure'
    assert classify_alb_listener_tls({
        'Protocol': 'HTTPS',
        'SslPolicy': 'ELBSecurityPolicy-TLS13-NEWER-2027-01'
    }) == 'unknown'
    assert classify_alb_listener_tls({'Protocol': 'HTTPS'}) == 'unknown'
    assert classify_alb_listener_tls({'Protocol': 'HTTP'}) == 'not_applicable'
    assert classify_alb_listener_tls({'Protocol': None}) == 'unknown'


def test_elbv2_legacy_rule_id_and_checked_counts_with_unknown_tls(tmp_path):
    selected = {
        'about': 'Synthetic M08 ALB TLS only',
        'rules': {'elbv2-older-ssl-policy.json': [
            {'enabled': True, 'level': 'warning'}
        ]}
    }
    filename = tmp_path / 'rule.json'
    filename.write_text(json.dumps(selected), encoding='utf-8')
    listeners = {
        'modern': {'Protocol': 'HTTPS',
                   'SslPolicy': 'ELBSecurityPolicy-TLS13-1-2-2021-06'},
        'legacy': {'Protocol': 'HTTPS', 'SslPolicy': 'ELBSecurityPolicy-2016-08'},
        'unknown': {'Protocol': 'HTTPS', 'SslPolicy': 'ELBSecurityPolicy-TLS13-NEXT'},
        'denied': {'Protocol': 'HTTPS', 'SslPolicy': None},
        'plaintext': {'Protocol': 'HTTP'},
    }
    provider = SimpleNamespace(
        services={'elbv2': {'regions': {'us-east-1': {
            'vpcs': {'vpc-1': {'lbs': {'lb-1': {'listeners': listeners}}}}
        }}}},
        service_list=['elbv2']
    )
    context = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(filename))).run(provider)
        finding = provider.services['elbv2']['findings']['elbv2-older-ssl-policy']
        assert finding['items'] == [
            'elbv2.regions.us-east-1.vpcs.vpc-1.lbs.lb-1.listeners.legacy.SslPolicy'
        ]
        assert finding['flagged_items'] == 1
        assert finding['level'] == 'warning'
        assert finding['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 1, 'unknown': 2, 'not_applicable': 1
        }
        assert finding['assessment_status'] == 'incomplete'
        assert finding['evaluation_summary']['unknown_resources'] == [
            'elbv2.regions.us-east-1.vpcs.vpc-1.lbs.lb-1.listeners.unknown',
            'elbv2.regions.us-east-1.vpcs.vpc-1.lbs.lb-1.listeners.denied'
        ]
        assert context.collection_issues == [{
            'status': 'partial', 'scope': 'elbv2',
            'reason_code': 'RuleEvidenceUnknown'
        }]
    finally:
        context.cleanup()
