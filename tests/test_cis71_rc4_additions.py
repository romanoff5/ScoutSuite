"""CIS Foundations v7.1.0 candidate rules: real rule engine + synthetic evidence."""
import json
from types import SimpleNamespace

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import (
    classify_efs_encryption, classify_rds_deletion_protection,
)
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.resources.rds.instances import RDSInstances


def test_rds_deletion_protection_collected_from_existing_instance_response():
    instance = RDSInstances.__new__(RDSInstances)
    name, record = instance._parse_instance({
        'DBInstanceIdentifier': 'synthetic-db',
        'DeletionProtection': False,
        'StorageEncrypted': True,
    })
    assert name
    assert record['DeletionProtection'] is False
    assert record['StorageEncrypted'] is True
    _, missing = instance._parse_instance({
        'DBInstanceIdentifier': 'synthetic-unknown',
    })
    assert missing['DeletionProtection'] is None


def test_missing_or_invalid_evidence_never_means_secure():
    assert classify_rds_deletion_protection({'DeletionProtection': True}) == 'secure'
    assert classify_rds_deletion_protection({'DeletionProtection': False}) == 'insecure'
    assert classify_rds_deletion_protection({'DeletionProtection': None}) == 'unknown'
    assert classify_rds_deletion_protection({'DeletionProtection': 'false'}) == 'unknown'
    assert classify_efs_encryption({'Encrypted': True}) == 'secure'
    assert classify_efs_encryption({'Encrypted': False}) == 'insecure'
    assert classify_efs_encryption({}) == 'unknown'
    assert classify_efs_encryption({'Encrypted': 'False'}) == 'unknown'


def test_cis71_rules_run_normally_and_unknown_blocks_compliance_pass(tmp_path):
    name_rds = 'rds-instance-deletion-protection-disabled.json'
    name_efs = 'efs-filesystem-not-encrypted.json'
    data = {
        'about': 'Synthetic candidate regression only',
        'rules': {
            name_rds: [{'enabled': True, 'level': 'warning'}],
            name_efs: [{'enabled': True, 'level': 'danger'}],
        },
    }
    file = tmp_path / 'cis71-two-rules.json'
    file.write_text(json.dumps(data), encoding='utf-8')
    ruleset = Ruleset('aws', filename=str(file))
    provider = SimpleNamespace(
        service_list=['rds', 'efs'],
        services={
            'rds': {'regions': {'eu-west-1': {'vpcs': {'vpc': {'instances': {
                'protected': {'DeletionProtection': True},
                'unprotected': {'DeletionProtection': False},
                'incomplete': {'DeletionProtection': None},
            }}}}}},
            'efs': {'regions': {'eu-west-1': {'filesystems': {
                'encrypted': {'Encrypted': True},
                'plain': {'Encrypted': False},
                'undetermined': {},
            }}}},
        })
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(ruleset).run(provider)
        for service, key, policy in (
                ('rds', name_rds.removesuffix('.json'), 'cis71-rds-deletion-protection-v1'),
                ('efs', name_efs.removesuffix('.json'), 'cis71-efs-encryption-v1')):
            finding = provider.services[service]['findings'][key]
            assert finding['flagged_items'] == 1
            assert finding['checked_items'] == 3
            assert finding['evaluation_summary']['policy'] == policy
            assert finding['evaluation_summary']['counts'] == {
                'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
            assert finding['assessment_status'] == 'incomplete'
            assert finding['evaluation_summary']['compliance_verified'] is False
        assert any(item['reason_code'] == 'RuleEvidenceUnknown'
                   for item in ctx.collection_issues)
    finally:
        ctx.cleanup()


def test_new_rules_are_enabled_in_default_and_detailed_without_legacy_mutation():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    base = root / 'ScoutSuite/providers/aws/rules/rulesets'
    for filename in ('default.json', 'detailed.json'):
        data = json.loads((base / filename).read_text(encoding='utf-8'))
        for rule in ('rds-instance-deletion-protection-disabled.json',
                     'efs-filesystem-not-encrypted.json'):
            assert data['rules'][rule][0]['enabled'] is True
    legacy = json.loads((base / 'cis-1.2.0.json').read_text(encoding='utf-8'))
    assert legacy.get('benchmark', {}).get('version') != '7.1.0'
