"""M06 Config: pagination, recorder variants, missing status and denied listing."""
import asyncio
from unittest import TestCase
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from botocore.session import get_session

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.config import ConfigFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.config.recorders import Recorders


class TestConfigRecorders(TestCase):
    def test_model_contract(self):
        service = get_session().get_service_model('config')
        listing = service.operation_model('ListConfigurationRecorders')
        self.assertTrue({'MaxResults', 'NextToken'} <= set(listing.input_shape.members))
        self.assertIn('ConfigurationRecorderSummaries', listing.output_shape.members)
        for name in ('DescribeConfigurationRecorders', 'DescribeConfigurationRecorderStatus'):
            self.assertIn('Arn', service.operation_model(name).input_shape.members)

    def test_customer_and_service_linked_across_two_pages(self):
        async def scenario():
            facade = ConfigFacade(Mock())
            client = Mock()
            arns = ['arn:aws:config:us-east-1:1:recorder/default',
                    'arn:aws:config:us-east-1:1:recorder/service']
            client.list_configuration_recorders.side_effect = [
                {'ConfigurationRecorderSummaries': [{'arn': arns[0]}],
                 'NextToken': 'more'},
                {'ConfigurationRecorderSummaries': [{'arn': arns[1]}]}
            ]
            client.describe_configuration_recorders.side_effect = [
                {'ConfigurationRecorders': [{'name': 'default', 'arn': arns[0],
                    'roleARN': 'arn:aws:iam::1:role/a', 'recordingGroup': {}}]},
                {'ConfigurationRecorders': [{'name': 'linked', 'arn': arns[1],
                    'servicePrincipal': 'securityhub.amazonaws.com',
                    'recordingScope': 'INTERNAL'}]}
            ]
            client.describe_configuration_recorder_status.side_effect = [
                {'ConfigurationRecordersStatus': [{'arn': arns[0], 'recording': True}]},
                {'ConfigurationRecordersStatus': [{'arn': arns[1], 'recording': False}]}
            ]
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                recorders = await facade.get_recorders('us-east-1')
            self.assertEqual(len(recorders), 2)
            self.assertEqual(client.list_configuration_recorders.call_args_list[0].kwargs,
                             {'MaxResults': 20})
            self.assertEqual(client.list_configuration_recorders.call_args_list[1].kwargs,
                             {'MaxResults': 20, 'NextToken': 'more'})
            self.assertEqual(client.describe_configuration_recorder_status.call_args_list[1].kwargs,
                             {'Arn': arns[1]})
            normalized = Recorders.__new__(Recorders)
            normalized.region = 'us-east-1'
            key, item = normalized._parse_recorder(recorders[1])
            self.assertEqual(item['name'], 'linked')
            self.assertEqual(item['recording_scope'], 'INTERNAL')
            self.assertFalse(item['enabled'])
            self.assertIsNone(item['role_ARN'])
            self.assertTrue(key.startswith('scoutid-'))
        asyncio.run(scenario())

    def test_denied_listing_keeps_customer_but_is_incomplete(self):
        async def scenario():
            context = RunContext('aws').setup()
            client = Mock()
            client.list_configuration_recorders.side_effect = ClientError(
                {'Error': {'Code': 'AccessDenied', 'Message': 'synthetic'}},
                'ListConfigurationRecorders')
            client.describe_configuration_recorders.return_value = {
                'ConfigurationRecorders': [{'name': 'default', 'recordingGroup': {}}]}
            client.describe_configuration_recorder_status.return_value = {
                'ConfigurationRecordersStatus': [{'name': 'default', 'recording': True}]}
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    value = await ConfigFacade(Mock()).get_recorders('us-east-1')
                self.assertEqual(len(value), 1)
                self.assertEqual(context.collection_summary()['status'], 'partial')
            finally:
                await context.aclose()
        asyncio.run(scenario())

    def test_legacy_status_name_matches_without_arn_field(self):
        async def scenario():
            facade = ConfigFacade(Mock())
            client = Mock()
            client.describe_configuration_recorder_status.return_value = {
                'ConfigurationRecordersStatus': [{
                    'name': 'default', 'recording': True
                }]
            }
            rows = await facade._attach_statuses(client, [
                {'name': 'default', 'arn': 'arn:aws:config:us-east-1:1:default'}
            ])
            self.assertTrue(rows[0]['ConfigurationRecordersStatus']['recording'])
        asyncio.run(scenario())

    def test_missing_status_is_unknown(self):
        async def scenario():
            context = RunContext('aws').setup()
            client = Mock()
            client.describe_configuration_recorder_status.return_value = {
                'ConfigurationRecordersStatus': []}
            try:
                rows = await ConfigFacade(Mock())._attach_statuses(client, [
                    {'name': 'linked', 'arn': 'arn:aws:config:us-east-1:1:linked'}
                ])
                parser = Recorders.__new__(Recorders)
                parser.region = 'us-east-1'
                _key, item = parser._parse_recorder(rows[0])
                self.assertIsNone(item['enabled'])
                self.assertFalse(item['status_complete'])
                self.assertTrue(context.collection_issues)
            finally:
                await context.aclose()
        asyncio.run(scenario())
