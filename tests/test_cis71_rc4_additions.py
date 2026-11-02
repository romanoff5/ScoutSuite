"""CIS Foundations v7.1.0 candidate rules: real rule engine + synthetic evidence."""
import json
from types import SimpleNamespace

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import (
    classify_efs_encryption, classify_rds_deletion_protection,
    classify_rds_cluster_deletion_protection,
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
    assert record['is_cluster_member'] is False
    _, missing = instance._parse_instance({
        'DBInstanceIdentifier': 'synthetic-unknown',
    })
    assert missing['DeletionProtection'] is None
    assert missing['is_cluster_member'] is False
    _, aurora = instance._parse_instance({
        'DBInstanceIdentifier': 'synthetic-aurora-member',
        'DBClusterIdentifier': 'synthetic-cluster', 'DeletionProtection': False})
    assert aurora['is_cluster_member'] is True
    assert aurora['DBClusterIdentifier'] == 'synthetic-cluster'


def test_missing_or_invalid_evidence_never_means_secure():
    assert classify_rds_deletion_protection({'is_cluster_member': False, 'DeletionProtection': True}) == 'secure'
    assert classify_rds_deletion_protection({'is_cluster_member': False, 'DeletionProtection': False}) == 'insecure'
    assert classify_rds_deletion_protection({'is_cluster_member': False, 'DeletionProtection': None}) == 'unknown'
    assert classify_rds_deletion_protection({'is_cluster_member': False, 'DeletionProtection': 'false'}) == 'unknown'
    assert classify_rds_deletion_protection({'is_cluster_member': True, 'DeletionProtection': False}) == 'not_applicable'
    assert classify_rds_deletion_protection({'DeletionProtection': False}) == 'unknown'
    assert classify_rds_cluster_deletion_protection({'DeletionProtection': False}) == 'insecure'
    assert classify_rds_cluster_deletion_protection({'DeletionProtection': True}) == 'secure'
    assert classify_rds_cluster_deletion_protection({}) == 'unknown'
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
                'protected': {'is_cluster_member': False, 'DeletionProtection': True},
                'unprotected': {'is_cluster_member': False, 'DeletionProtection': False},
                'incomplete': {'is_cluster_member': False, 'DeletionProtection': None},
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
                     'rds-cluster-deletion-protection-disabled.json',
                     'efs-filesystem-not-encrypted.json'):
            assert data['rules'][rule][0]['enabled'] is True
    legacy = json.loads((base / 'cis-1.2.0.json').read_text(encoding='utf-8'))
    assert legacy.get('benchmark', {}).get('version') != '7.1.0'


def test_s3_effective_bpa_and_securityhub_state_fail_closed():
    import asyncio
    from unittest.mock import Mock, patch
    from botocore.exceptions import ClientError
    from ScoutSuite.core.rule_evidence import (
        classify_s3_block_public_access, classify_securityhub_subscription)
    from ScoutSuite.providers.aws.resources.s3.base import S3
    from ScoutSuite.providers.aws.facade.securityhub import SecurityHubPublicFacade
    from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils

    flags = ('BlockPublicAcls', 'IgnorePublicAcls',
             'BlockPublicPolicy', 'RestrictPublicBuckets')
    all_true = {k: True for k in flags}
    partial = dict(all_true, RestrictPublicBuckets=False)
    source = SimpleNamespace(s3=Mock(), owner_id='000000000000')
    s3 = S3(source)
    s3['public_access_block_configuration'] = all_true
    s3['buckets'] = {
        'safe': {'public_access_block_configuration': partial},
        'bad': {'public_access_block_configuration': {k: False for k in flags}},
        'unknown': {'public_access_block_configuration': None},
    }
    asyncio.run(s3.finalize())
    # Account-level explicit blocks protect safe even if bucket-level options differ.
    assert s3['buckets']['safe']['effective_bpa_review'] == 'complete'
    assert s3['buckets']['bad']['effective_bpa_review'] == 'complete'
    assert s3['buckets']['unknown']['effective_bpa_review'] == 'complete'
    for bucket in s3['buckets'].values():
        assert classify_s3_block_public_access(bucket) == 'secure'

    s3['public_access_block_configuration'] = {k: False for k in flags}
    # Restore the distinct bucket settings; finalize() intentionally keeps
    # effective results, so a second synthetic pass must supply fresh evidence.
    s3['buckets']['bad']['public_access_block_configuration'] = {k: False for k in flags}
    s3['buckets']['unknown']['public_access_block_configuration'] = None
    asyncio.run(s3.finalize())
    assert s3['buckets']['bad']['effective_bpa_review'] == 'missing'
    assert classify_s3_block_public_access(s3['buckets']['bad']) == 'insecure'
    assert s3['buckets']['unknown']['effective_bpa_review'] == 'unknown'
    assert classify_s3_block_public_access(s3['buckets']['unknown']) == 'unknown'

    assert classify_securityhub_subscription({'hub_subscription_status': 'enabled'}) == 'secure'
    assert classify_securityhub_subscription({'hub_subscription_status': 'not_subscribed'}) == 'insecure'
    assert classify_securityhub_subscription({'hub_subscription_status': 'unknown'}) == 'unknown'

    facade = SecurityHubPublicFacade.__new__(SecurityHubPublicFacade)
    facade.session = object()
    denied = Mock()
    denied.describe_hub.side_effect = ClientError(
        {'Error': {'Code': 'AccessDeniedException', 'Message': 'synthetic'}},
        'DescribeHub')
    unsubscribed = Mock()
    unsubscribed.describe_hub.side_effect = ClientError(
        {'Error': {'Code': 'ResourceNotFoundException', 'Message': 'synthetic'}},
        'DescribeHub')

    async def scenario():
        with patch.object(AWSFacadeUtils, 'get_client', side_effect=[denied, unsubscribed]):
            assert await facade.get_hub('eu-west-1') is None
            assert await facade.get_hub('eu-west-2') is None
    asyncio.run(scenario())
    assert facade.hub_states['eu-west-1'] == 'unknown'
    assert facade.hub_states['eu-west-2'] == 'not_subscribed'


def test_cis71_s3_and_securityhub_findings_do_not_promote_unknown_to_pass(tmp_path):
    rules = {'about': 'Synthetic only', 'rules': {
        's3-bucket-public-access-block-incomplete.json': [
            {'enabled': True, 'level': 'warning'}],
        'securityhub-region-not-subscribed.json': [
            {'enabled': True, 'level': 'warning'}],
    }}
    target = tmp_path / 'synthetic-cis71.json'
    target.write_text(json.dumps(rules), encoding='utf-8')
    provider = SimpleNamespace(
        service_list=['s3', 'securityhub'],
        services={
            's3': {'buckets': {
                'ok': {'effective_bpa_review': 'complete'},
                'bad': {'effective_bpa_review': 'missing'},
                'unknown': {'effective_bpa_review': 'unknown'},
            }},
            'securityhub': {'regions': {
                'eu-west-1': {'hub_subscription_status': 'enabled'},
                'eu-west-2': {'hub_subscription_status': 'not_subscribed'},
                'eu-central-1': {'hub_subscription_status': 'unknown'},
            }},
        })
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(target))).run(provider)
        for service, key in (
                ('s3', 's3-bucket-public-access-block-incomplete'),
                ('securityhub', 'securityhub-region-not-subscribed')):
            finding = provider.services[service]['findings'][key]
            assert finding['flagged_items'] == 1
            assert finding['evaluation_summary']['counts'] == {
                'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
            assert finding['assessment_status'] == 'incomplete'
            assert finding['evaluation_summary']['compliance_verified'] is False
    finally:
        ctx.cleanup()
