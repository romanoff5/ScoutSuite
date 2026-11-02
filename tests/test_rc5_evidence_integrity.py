"""RC5 regression checks for confirmed evidence-integrity defects; no external AWS calls."""
import asyncio
from unittest.mock import AsyncMock, Mock, patch

from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.securityhub import SecurityHubPublicFacade
from ScoutSuite.providers.aws.facade.rds import RDSFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.facade.operational_evidence import collect_waf_traffic
from ScoutSuite.providers.aws.resources.rds.instances import RDSInstances


def test_securityhub_confirmed_not_subscribed_is_negative_evidence_not_invalid_collection_issue():
    async def scenario():
        ctx = RunContext('aws').setup()
        try:
            client = Mock()
            client.describe_hub.side_effect = ClientError(
                {'Error': {'Code': 'ResourceNotFoundException', 'Message': 'synthetic'}}, 'DescribeHub')
            facade = SecurityHubPublicFacade(object())
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                assert await facade.get_hub('eu-west-1') is None
            assert facade.hub_states['eu-west-1'] == 'not_subscribed'
            assert ctx.collection_issues == []
        finally:
            await ctx.aclose()
    asyncio.run(scenario())


def test_rds_unexpected_instance_and_snapshot_failures_are_partial_not_empty_success():
    async def scenario():
        ctx = RunContext('aws').setup()
        try:
            facade = RDSFacade(Mock())
            with patch.object(facade, '_cache_instances', new_callable=AsyncMock,
                              side_effect=ValueError('synthetic malformed response')), \
                 patch.object(facade, '_cache_snapshots', new_callable=AsyncMock,
                              side_effect=ValueError('synthetic malformed response')):
                assert await facade.get_instances('eu-west-1', 'vpc-a') == []
                assert await facade.get_snapshots('eu-west-1', 'vpc-a') == []
            codes = {row['reason_code'] for row in ctx.collection_issues}
            assert {'DescribeDBInstancesIncomplete', 'DescribeDBSnapshotsIncomplete'} <= codes
            assert ctx.collection_summary()['complete'] is False
        finally:
            await ctx.aclose()
    asyncio.run(scenario())


def test_failed_rds_enrichment_does_not_poison_cache_or_skip_retry():
    async def scenario():
        facade = RDSFacade(Mock())
        raw = [{'DBInstanceIdentifier': 'synthetic-db', 'DBSubnetGroup': {'VpcId': 'vpc-a'}}]
        with patch.object(AWSFacadeUtils, 'get_all_pages', new_callable=AsyncMock,
                          return_value=raw) as api, \
             patch('ScoutSuite.providers.aws.facade.rds.get_and_set_concurrently',
                   new_callable=AsyncMock, side_effect=[RuntimeError('synthetic'), None]):
            try:
                await facade._cache_instances('eu-west-1')
            except RuntimeError:
                pass
            else:
                raise AssertionError('First enrichment error was unexpectedly swallowed')
            assert 'eu-west-1' not in facade._instances_cache
            await facade._cache_instances('eu-west-1')
            assert len(facade._instances_cache['eu-west-1']) == 1
            assert api.await_count == 2
    asyncio.run(scenario())


def test_rds_snapshot_cache_enriches_before_publishing_and_reuses_result():
    async def scenario():
        facade = RDSFacade(Mock())
        db_snapshot = {'DBSnapshotIdentifier': 'synthetic-db-snapshot', 'VpcId': 'vpc-a'}
        cluster_snapshot = {'DBClusterSnapshotIdentifier': 'synthetic-cluster-snapshot', 'VpcId': 'vpc-a'}

        async def pages(_service, _region, _session, operation, _key):
            if operation == 'describe_db_snapshots':
                return [db_snapshot]
            if operation == 'describe_db_cluster_snapshots':
                return [cluster_snapshot]
            raise AssertionError(f'Unexpected operation: {operation}')

        async def enrich(sources, rows, region):
            assert region == 'eu-central-1'
            assert len(sources) == 1
            for row in rows:
                row['Attributes'] = {'verified': True}

        with patch.object(AWSFacadeUtils, 'get_all_pages', new_callable=AsyncMock,
                          side_effect=pages) as api, \
             patch('ScoutSuite.providers.aws.facade.rds.get_and_set_concurrently',
                   new_callable=AsyncMock, side_effect=enrich) as enrichment:
            first = await facade.get_snapshots('eu-central-1', 'vpc-a')
            assert first == [db_snapshot, cluster_snapshot]
            assert all(row['Attributes'] == {'verified': True} for row in first)
            assert api.await_count == 2
            assert enrichment.await_count == 2
            assert await facade.get_snapshots('eu-central-1', 'vpc-a') == first
            assert api.await_count == 2

    asyncio.run(scenario())


def test_malformed_rds_cluster_membership_is_unknown_not_standalone():
    parser = RDSInstances.__new__(RDSInstances)
    for malformed in ('', '   ', 42, {}):
        _, row = parser._parse_instance({
            'DBInstanceIdentifier': 'synthetic-db', 'DBClusterIdentifier': malformed,
            'DeletionProtection': False})
        assert row['is_cluster_member'] is None
    _, standalone = parser._parse_instance({
        'DBInstanceIdentifier': 'synthetic-standalone', 'DeletionProtection': False})
    assert standalone['is_cluster_member'] is False


def test_waf_nonfinite_metric_cannot_verify_processed_requests():
    async def immediate(fn):
        return fn()

    class Facade:
        session = object()
        def __init__(self):
            self.issues = []
        def issue(self, *args):
            self.issues.append(args)

    def query():
        return {'MetricDataResults': [
            {'Id': 'm' + str(i), 'StatusCode': 'Complete',
             'Values': [float('inf') if i == 0 else 0.0]}
            for i in range(5)]}
    async def scenario():
        facade = Facade()
        client = Mock()
        client.get_metric_data.side_effect = lambda **kwargs: query()
        with patch.object(AWSFacadeUtils, 'get_client', return_value=client), \
             patch('ScoutSuite.providers.aws.facade.operational_evidence.run_concurrently', immediate):
            result = await collect_waf_traffic(facade, 'eu-west-1', {
                'scope': 'REGIONAL',
                'visibility_config': {'CloudWatchMetricsEnabled': True, 'MetricName': 'synthetic'}})
        assert result['completeness'] == 'partial'
        assert result['requests_observed'] is False
        assert result['status'] == 'unknown'
        assert any(row[1] == 'WAFMetricSeriesIncomplete' for row in facade.issues)
    asyncio.run(scenario())
