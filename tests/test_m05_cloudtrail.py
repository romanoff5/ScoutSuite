"""M05-D CloudTrail selectors, home regions and UTC freshness (offline)."""
import asyncio
from datetime import datetime, timedelta, timezone
from unittest import TestCase
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from botocore.session import get_session

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.cloudtrail import CloudTrailFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.cloudtrail.trails import Trails


class TestCloudTrailSelectors(TestCase):
    def test_model_has_both_selector_families(self):
        op = get_session().get_service_model('cloudtrail').operation_model(
            'GetEventSelectors'
        )
        self.assertIn('TrailName', op.input_shape.members)
        self.assertTrue({'EventSelectors', 'AdvancedEventSelectors'} <=
                        set(op.output_shape.members))

    def test_reads_home_region_and_preserves_advanced(self):
        async def scenario():
            facade = CloudTrailFacade.__new__(CloudTrailFacade)
            facade.session = Mock()
            client = Mock()
            client.get_event_selectors.return_value = {
                'AdvancedEventSelectors': [{
                    'Name': 'all-data',
                    'FieldSelectors': [
                        {'Field': 'eventCategory', 'Equals': ['Data']},
                        {'Field': 'resources.type', 'Equals': ['AWS::S3::Object']}
                    ]
                }]
            }
            trail = {
                'TrailARN': 'arn:aws:cloudtrail:us-east-1:123:trail/test',
                'HomeRegion': 'us-east-1', 'IsOrganizationTrail': True
            }
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client) as get_client:
                await facade._get_and_set_selectors(trail, 'eu-west-1')
            self.assertEqual(get_client.call_args.args[2], 'us-east-1')
            self.assertEqual(client.get_event_selectors.call_args.kwargs['TrailName'],
                             trail['TrailARN'])
            self.assertEqual(trail['EventSelectors'], [])
            self.assertEqual(len(trail['AdvancedEventSelectors']), 1)
            self.assertEqual(trail['selector_collection_status'], 'success')
        asyncio.run(scenario())

    def test_multiple_basic_selectors_are_or_aggregated(self):
        trails = Trails.__new__(Trails)
        trails.region = 'us-east-1'
        now = datetime.now(timezone.utc)
        raw = {
            'Name': 'trail1', 'S3BucketName': 'logs-bucket',
            'TrailARN': 'arn:aws:cloudtrail:us-east-1:123:trail/trail1',
            'HomeRegion': 'us-east-1', 'IsLogging': True,
            'LatestCloudWatchLogsDeliveryTime': now - timedelta(hours=1),
            'EventSelectors': [
                {'IncludeManagementEvents': True, 'DataResources': []},
                {'IncludeManagementEvents': False, 'DataResources': [{
                    'Type': 'AWS::S3::Object', 'Values': ['arn:aws:s3']
                }]}
            ]
        }
        _key, result = trails._parse_trail(raw)
        self.assertTrue(result['ManagementEventsEnabled'])
        self.assertTrue(result['DataEventsEnabled'])
        self.assertTrue(result['wildcard_data_logging'])

    def test_advanced_data_selectors_preserved_in_resource(self):
        trails = Trails.__new__(Trails)
        trails.region = 'us-east-1'
        raw = {
            'Name': 'trail2', 'S3BucketName': 'logs',
            'IsLogging': True,
            'TrailARN': 'arn:aws:cloudtrail:us-east-1:123:trail/trail2',
            'HomeRegion': 'us-east-1',
            'LatestCloudWatchLogsDeliveryTime': datetime.now(timezone.utc),
            'AdvancedEventSelectors': [{
                'FieldSelectors': [
                    {'Field': 'eventCategory', 'Equals': ['Data']},
                    {'Field': 'resources.type', 'Equals': ['AWS::S3::Object']}
                ]
            }]
        }
        _key, result = trails._parse_trail(raw)
        self.assertTrue(result['DataEventsEnabled'])
        self.assertFalse(result['ManagementEventsEnabled'])
        self.assertTrue(result['wildcard_data_logging'])
        self.assertEqual(len(result['AdvancedEventSelectors']), 1)

    def test_org_trail_denied_marks_unknown_not_false(self):
        async def scenario():
            ctx = RunContext('aws').setup()
            facade = CloudTrailFacade.__new__(CloudTrailFacade)
            facade.session = Mock()
            client = Mock()
            client.get_event_selectors.side_effect = ClientError(
                {'Error': {'Code': 'AccessDeniedException', 'Message': 'synthetic'}},
                'GetEventSelectors'
            )
            trail = {
                'TrailARN': 'arn:aws:cloudtrail:us-east-1:123:trail/org',
                'HomeRegion': 'us-east-1', 'IsOrganizationTrail': True
            }
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    await facade._get_and_set_selectors(trail, 'us-west-2')
                self.assertEqual(trail['selector_collection_status'], 'failed')
                self.assertEqual(ctx.collection_issues[0]['status'], 'denied')
                trails = Trails.__new__(Trails)
                trails.region = 'us-east-1'
                trail['Name'] = 'org'
                trail['S3BucketName'] = 'logs'
                _key, parsed = trails._parse_trail(trail)
                self.assertIsNone(parsed['DataEventsEnabled'])
                self.assertIsNone(parsed['wildcard_data_logging'])
            finally:
                await ctx.aclose()
        asyncio.run(scenario())

    def test_24_hour_boundary_is_utc_and_windows_portable(self):
        now = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
        self.assertTrue(Trails.is_fresh({
            'LatestCloudWatchLogsDeliveryTime': now - timedelta(hours=24)
        }, now=now))
        self.assertFalse(Trails.is_fresh({
            'LatestCloudWatchLogsDeliveryTime': now - timedelta(hours=24, seconds=1)
        }, now=now))
        self.assertFalse(Trails.is_fresh({
            'LatestCloudWatchLogsDeliveryTime': now + timedelta(seconds=1)
        }, now=now))
