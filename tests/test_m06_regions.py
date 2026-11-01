"""M06 partition-aware region selection and fail-visible opt-in states."""
import asyncio
from unittest import TestCase
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.base import AWSFacade


class TestRegionPartitions(TestCase):
    def test_partition_specific_probes_and_filters(self):
        async def scenario(partition, expected):
            client = Mock()
            client.describe_regions.return_value = {
                'Regions': [{'RegionName': expected[1]}]}
            session = Mock(region_name=expected[0])
            session.client.return_value = client
            sdk = Mock()
            sdk.get_available_services.return_value = ['ec2']
            sdk.get_available_regions.return_value = expected[2]
            facade = AWSFacade.__new__(AWSFacade)
            facade.session = session
            with patch('ScoutSuite.providers.aws.facade.base.Session',
                       return_value=sdk) as constructor:
                regions = await facade.build_region_list(
                    'ec2', partition_name=partition)
            constructor.assert_called_once_with(region_name=expected[0])
            self.assertEqual(session.client.call_args.kwargs,
                             {'region_name': expected[0]})
            self.assertEqual(regions, [region for region in expected[2]
                                       if region != expected[1]])
        for partition, data in [
            ('aws', ('us-east-1', 'ap-east-1',
                     ['us-east-1', 'ap-east-1'])),
            ('aws-us-gov', ('us-gov-west-1', 'us-gov-east-1',
                            ['us-gov-west-1', 'us-gov-east-1'])),
            ('aws-cn', ('cn-north-1', 'cn-northwest-1',
                         ['cn-north-1', 'cn-northwest-1']))
        ]:
            with self.subTest(partition=partition):
                asyncio.run(scenario(partition, data))

    def test_opt_in_denied_does_not_misreport_all_regions_disabled(self):
        async def scenario():
            context = RunContext('aws').setup()
            facade = AWSFacade.__new__(AWSFacade)
            session = Mock(region_name='eu-central-1')
            session.client.return_value.describe_regions.side_effect = ClientError(
                {'Error': {'Code': 'AccessDenied', 'Message': 'synthetic'}},
                'DescribeRegions')
            facade.session = session
            sdk = Mock()
            sdk.get_available_services.return_value = ['ec2']
            sdk.get_available_regions.return_value = [
                'eu-central-1', 'eu-west-1', 'us-east-1']
            try:
                with patch('ScoutSuite.providers.aws.facade.base.Session',
                           return_value=sdk):
                    output = await facade.build_region_list(
                        'ec2', chosen_regions=['eu-central-1', 'eu-west-1'],
                        excluded_regions=['eu-west-1'])
                self.assertEqual(output, ['eu-central-1'])
                self.assertIn('RegionOptInUnverified', [
                    x['reason_code'] for x in context.collection_issues])
            finally:
                await context.aclose()
        asyncio.run(scenario())

    def test_empty_region_metadata_does_not_invent_commercial_eks_regions(self):
        async def scenario():
            context = RunContext('aws').setup()
            facade = AWSFacade.__new__(AWSFacade)
            facade.session = Mock(region_name='cn-north-1')
            sdk = Mock()
            sdk.get_available_services.return_value = ['eks']
            sdk.get_available_regions.return_value = []
            try:
                with patch('ScoutSuite.providers.aws.facade.base.Session',
                           return_value=sdk):
                    output = await facade.build_region_list(
                        'eks', partition_name='aws-cn')
                self.assertEqual(output, [])
                self.assertEqual(context.collection_issues[0]['reason_code'],
                                 'RegionModelUnavailable')
            finally:
                await context.aclose()
        asyncio.run(scenario())
