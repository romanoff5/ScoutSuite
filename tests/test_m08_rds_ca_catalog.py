"""M08 RDS certificate-identifier lifecycle, without region expiry assumptions."""
import json
from types import SimpleNamespace

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_rds_ca_lifecycle
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from tests.fixtures import ROOT


CATALOG = (ROOT / 'ScoutSuite/providers/aws/rules/catalogs'
           / 'rds-ca-2026-11.json')


def test_rds_ca_catalog_is_versioned_and_has_real_provenance():
    data = json.loads(CATALOG.read_text(encoding='utf-8'))
    assert data['catalog_version'] == '2026.11.0'
    assert data['schema_version'] == 1
    assert data['owner']
    assert data['review_date'] == '2026-11-01'
    assert len(data['reference_urls']) >= 2
    assert all(url.startswith('https://') for url in data['reference_urls'])
    assert set(data['current_ca']) == {
        'rds-ca-rsa2048-g1', 'rds-ca-rsa4096-g1', 'rds-ca-ecc384-g1'
    }
    assert {'rds-ca-2019', 'rds-ca-2015'} == set(data['deprecated_ca'])
    assert not set(data['current_ca']) & set(data['deprecated_ca'])


def test_known_legacy_current_and_unrecognized_ca_never_conflated():
    assert classify_rds_ca_lifecycle({'CACertificateIdentifier': 'rds-ca-2015'}) == 'insecure'
    assert classify_rds_ca_lifecycle({'CACertificateIdentifier': 'rds-ca-2019'}) == 'insecure'
    for current in ('rds-ca-rsa2048-g1', 'rds-ca-rsa4096-g1', 'rds-ca-ecc384-g1'):
        assert classify_rds_ca_lifecycle({'CACertificateIdentifier': current}) == 'secure'
    assert classify_rds_ca_lifecycle({'CACertificateIdentifier': None}) == 'unknown'
    assert classify_rds_ca_lifecycle({}) == 'unknown'
    assert classify_rds_ca_lifecycle({'CACertificateIdentifier': 'rds-ca-new-9999'}) == 'unknown'


def test_rds_ca_finding_paths_and_severity_stable(tmp_path):
    source = {
        'about': 'Synthetic M08 RDS-only ruleset',
        'rules': {'rds-instance-ca-certificate-deprecated.json': [
            {'enabled': True, 'level': 'warning'}
        ]}
    }
    path = tmp_path / 'rds-ca-only.json'
    path.write_text(json.dumps(source), encoding='utf-8')
    context = RunContext('aws').setup()
    try:
        dbs = {
            'legacy-2015': {'CACertificateIdentifier': 'rds-ca-2015'},
            'legacy-2019': {'CACertificateIdentifier': 'rds-ca-2019'},
            'current': {'CACertificateIdentifier': 'rds-ca-rsa2048-g1'},
            'missing': {'CACertificateIdentifier': None},
            'unknown': {'CACertificateIdentifier': 'rds-ca-new-9999'},
        }
        provider = SimpleNamespace(
            services={'rds': {'regions': {
                'us-east-1': {'vpcs': {'vpc-1': {'instances': dbs}}}
            }}},
            service_list=['rds']
        )
        ProcessingEngine(Ruleset('aws', filename=str(path))).run(provider)
        finding = provider.services['rds']['findings'][
            'rds-instance-ca-certificate-deprecated'
        ]
        assert finding['items'] == [
            'rds.regions.us-east-1.vpcs.vpc-1.instances.legacy-2015.CACertificateIdentifier',
            'rds.regions.us-east-1.vpcs.vpc-1.instances.legacy-2019.CACertificateIdentifier',
        ]
        assert finding['checked_items'] == 5
        assert finding['flagged_items'] == 2
        assert finding['level'] == 'warning'
        assert finding['assessment_status'] == 'incomplete'
        assert finding['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 2, 'unknown': 2, 'not_applicable': 0
        }
        assert finding['evaluation_summary']['unknown_resources'] == [
            'rds.regions.us-east-1.vpcs.vpc-1.instances.missing',
            'rds.regions.us-east-1.vpcs.vpc-1.instances.unknown',
        ]
        assert context.collection_issues == [{
            'status': 'partial', 'scope': 'rds', 'reason_code': 'RuleEvidenceUnknown'
        }]
    finally:
        context.cleanup()
