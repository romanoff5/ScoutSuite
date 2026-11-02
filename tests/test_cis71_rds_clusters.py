"""Guard Aurora DB cluster deletion protection against member-level false positives."""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.rds.clusters import RDSClusters


def test_rds_clusters_readonly_inventory_deduplicates_members_and_preserves_evidence():
    facade = SimpleNamespace(session=object())
    result = [
        {'DBClusterIdentifier': 'synthetic-aurora-a',
         'DBClusterArn': 'arn:aws:rds:eu-west-1:000000000000:cluster:synthetic-aurora-a',
         'Engine': 'aurora-postgresql', 'DeletionProtection': False,
         'DBClusterMembers': [
             {'DBInstanceIdentifier': 'member-a'},
             {'DBInstanceIdentifier': 'member-b'}]},
        {'DBClusterIdentifier': 'synthetic-aurora-b',
         'Engine': 'aurora-postgresql', 'DeletionProtection': True,
         'DBClusterMembers': []},
    ]
    with patch.object(AWSFacadeUtils, 'get_all_pages', new_callable=AsyncMock,
                      return_value=result) as api:
        resources = RDSClusters(facade, 'eu-west-1')
        asyncio.run(resources.fetch_all())
        assert len(resources) == 2
        api.assert_awaited_once_with('rds', 'eu-west-1', facade.session,
                                     'describe_db_clusters', 'DBClusters')
    a = next(row for row in resources.values() if row['name'] == 'synthetic-aurora-a')
    assert a['DeletionProtection'] is False
    assert a['DBClusterMembers'] == ['member-a', 'member-b']
    b = next(row for row in resources.values() if row['name'] == 'synthetic-aurora-b')
    assert b['DeletionProtection'] is True


def test_rds_cluster_api_denial_creates_partial_issue_not_false_clean():
    facade = SimpleNamespace(session=object())
    ctx = RunContext('aws').setup()
    try:
        with patch.object(AWSFacadeUtils, 'get_all_pages', new_callable=AsyncMock,
                          side_effect=PermissionError('synthetic permission denial')):
            resources = RDSClusters(facade, 'eu-west-1')
            asyncio.run(resources.fetch_all())
        assert not resources
        assert any(x['reason_code'] == 'DescribeDBClustersIncomplete' and
                   x['scope'] == 'rds' for x in ctx.collection_issues)
    finally:
        ctx.cleanup()


def test_cluster_member_false_does_not_produce_four_duplicate_instance_findings(tmp_path):
    names = ('rds-instance-deletion-protection-disabled.json',
             'rds-cluster-deletion-protection-disabled.json')
    profile = {'about': 'Synthetic Aurora cluster only',
               'rules': {name: [{'enabled': True, 'level': 'warning'}]
                         for name in names}}
    ruleset_path = tmp_path / 'synthetic-rds-cluster.json'
    ruleset_path.write_text(json.dumps(profile), encoding='utf-8')
    provider = SimpleNamespace(service_list=['rds'], services={'rds': {'regions': {
        'eu-west-1': {
            'clusters': {
                'cluster-a': {'DeletionProtection': False},
                'cluster-b': {'DeletionProtection': False},
                'cluster-unknown': {'DeletionProtection': None},
            },
            'vpcs': {'vpc-synthetic': {'instances': {
                'aurora-member-a': {'is_cluster_member': True, 'DeletionProtection': False},
                'aurora-member-b': {'is_cluster_member': True, 'DeletionProtection': False},
                'aurora-member-c': {'is_cluster_member': True, 'DeletionProtection': False},
                'aurora-member-d': {'is_cluster_member': True, 'DeletionProtection': False},
                'standalone': {'is_cluster_member': False, 'DeletionProtection': False},
                'membership-unknown': {'is_cluster_member': None, 'DeletionProtection': False},
            }}},
        },
    }}})
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(ruleset_path))).run(provider)
        findings = provider.services['rds']['findings']
        instance = findings['rds-instance-deletion-protection-disabled']
        cluster = findings['rds-cluster-deletion-protection-disabled']
        assert instance['flagged_items'] == 1
        assert instance['evaluation_summary']['counts'] == {
            'secure': 0, 'insecure': 1, 'unknown': 1, 'not_applicable': 4}
        assert cluster['flagged_items'] == 2
        assert cluster['evaluation_summary']['counts'] == {
            'secure': 0, 'insecure': 2, 'unknown': 1, 'not_applicable': 0}
        assert instance['assessment_status'] == cluster['assessment_status'] == 'incomplete'
        assert cluster['evaluation_summary']['compliance_verified'] is False
        assert any(x['reason_code'] == 'RuleEvidenceUnknown' for x in ctx.collection_issues)
    finally:
        ctx.cleanup()
