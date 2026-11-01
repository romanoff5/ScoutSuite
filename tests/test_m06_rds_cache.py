"""M06-A RDS account/loop cache isolation and cluster optional fields."""
import asyncio
from unittest import TestCase
from unittest.mock import AsyncMock, Mock, patch

from ScoutSuite.providers.aws.facade.rds import RDSFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils


class TestRDSIsolation(TestCase):
    def test_same_region_different_accounts_do_not_share_cached_instances(self):
        async def scenario():
            a = RDSFacade(Mock(name='account-A'))
            b = RDSFacade(Mock(name='account-B'))
            response_a = [{
                'DBInstanceIdentifier': 'a', 'DBSubnetGroup': {'VpcId': 'vpc-a'},
            }]
            response_b = [{
                'DBInstanceIdentifier': 'b', 'DBSubnetGroup': {'VpcId': 'vpc-b'},
            }]

            async def retrieve(_service, _region, session, _operation, _key):
                return response_a if session is a.session else response_b

            with patch.object(AWSFacadeUtils, 'get_all_pages',
                              new_callable=AsyncMock, side_effect=retrieve) as api, \
                 patch.object(RDSFacade, '_get_and_set_instance_clusters',
                              new_callable=AsyncMock), \
                 patch.object(RDSFacade, '_get_and_set_instance_tags',
                              new_callable=AsyncMock):
                first, second = await asyncio.gather(
                    a.get_instances('us-east-1', 'vpc-a'),
                    b.get_instances('us-east-1', 'vpc-b')
                )
                self.assertEqual([x['DBInstanceIdentifier'] for x in first], ['a'])
                self.assertEqual([x['DBInstanceIdentifier'] for x in second], ['b'])
                self.assertIsNot(a._instances_cache, b._instances_cache)
                self.assertEqual(api.await_count, 2)
                self.assertEqual(await a.get_instances('us-east-1', 'vpc-a'), first)
                self.assertEqual(api.await_count, 2)

        asyncio.run(scenario())

    def test_snapshot_and_subnet_caches_are_per_instance_not_global(self):
        a, b = RDSFacade(Mock()), RDSFacade(Mock())
        for name in ('_instances_cache', '_snapshots_cache', '_subnet_groups_cache',
                     '_regional_instances_cache_locks', '_regional_snapshots_cache_locks',
                     '_regional_subnet_groups_cache_locks'):
            self.assertIsNot(getattr(a, name), getattr(b, name))
            getattr(a, name)['eu-central-1'] = ['account-a']
            self.assertNotIn('eu-central-1', getattr(b, name))

    def test_missing_aurora_multiaz_does_not_erase_original(self):
        async def scenario():
            facade = RDSFacade(Mock())
            instance = {'DBInstanceIdentifier': 'db', 'DBClusterIdentifier': 'cluster',
                        'MultiAZ': True}
            client = Mock()
            client.describe_db_clusters.return_value = {
                'DBClusters': [{'DBClusterIdentifier': 'cluster'}]
            }
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                await facade._get_and_set_instance_clusters(instance, 'us-east-1')
            self.assertTrue(instance['MultiAZ'])
            self.assertEqual(client.describe_db_clusters.call_args.kwargs,
                             {'DBClusterIdentifier': 'cluster'})

        asyncio.run(scenario())

    def test_tag_listing_does_not_issue_extra_sts_call(self):
        async def scenario():
            session = Mock()
            facade = RDSFacade(session)
            instance = {'DBInstanceIdentifier': 'db',
                        'DBInstanceArn': 'arn:aws:rds:us-east-1:123:db:db'}
            client = Mock()
            client.list_tags_for_resource.return_value = {
                'TagList': [{'Key': 'team', 'Value': 'security'}]
            }
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                await facade._get_and_set_instance_tags(instance, 'us-east-1')
            self.assertEqual(instance['Tags'], {'team': 'security'})
            session.client.assert_not_called()

        asyncio.run(scenario())
