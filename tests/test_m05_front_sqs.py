"""M05-B CloudFront and SQS strict offline pagination contracts."""
import asyncio
from unittest import TestCase
from unittest.mock import AsyncMock, Mock, patch

from botocore.exceptions import ClientError
from botocore.session import get_session

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.cloudfront import CloudFront
from ScoutSuite.providers.aws.facade.sqs import SQSFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils


class TestCloudFrontPagination(TestCase):
    def test_botocore_model(self):
        model = get_session().get_service_model('cloudfront').operation_model(
            'ListDistributions'
        )
        self.assertTrue({'Marker', 'MaxItems'} <= set(model.input_shape.members))
        self.assertIn('DistributionList', model.output_shape.members)

    def test_multiple_and_empty_pages(self):
        async def scenario():
            client = Mock()
            client.list_distributions.side_effect = [
                {'DistributionList': {
                    'IsTruncated': True, 'NextMarker': 'marker-1',
                    'Items': [{'Id': 'A'}]}},
                {'DistributionList': {'IsTruncated': False, 'Items': [{'Id': 'B'}]}}
            ]
            facade = CloudFront.__new__(CloudFront)
            facade.session = Mock()
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                result = await facade.get_distributions()
            self.assertEqual([entry['Id'] for entry in result], ['A', 'B'])
            self.assertEqual(client.list_distributions.call_args_list[0].kwargs,
                             {'MaxItems': '100'})
            self.assertEqual(client.list_distributions.call_args_list[1].kwargs,
                             {'MaxItems': '100', 'Marker': 'marker-1'})
            client.list_distributions.reset_mock(side_effect=True)
            client.list_distributions.return_value = {
                'DistributionList': {'IsTruncated': False}
            }
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                self.assertEqual(await facade.get_distributions(), [])
        asyncio.run(scenario())

    def test_missing_next_marker_is_incomplete_not_silent_empty(self):
        async def scenario():
            context = RunContext('aws').setup()
            facade = CloudFront.__new__(CloudFront)
            facade.session = Mock()
            client = Mock()
            client.list_distributions.return_value = {
                'DistributionList': {
                    'IsTruncated': True, 'Items': [{'Id': 'A'}]
                }
            }
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    self.assertEqual(await facade.get_distributions(), [])
                self.assertEqual(context.collection_issues[0]['scope'], 'cloudfront')
                self.assertEqual(context.collection_issues[0]['reason_code'],
                                 'MissingContinuationToken')
            finally:
                await context.aclose()
        asyncio.run(scenario())


class TestSQSPagination(TestCase):
    def test_botocore_model(self):
        op = get_session().get_service_model('sqs').operation_model('ListQueues')
        self.assertTrue({'NextToken', 'MaxResults'} <= set(op.input_shape.members))
        self.assertTrue({'QueueUrls', 'NextToken'} <= set(op.output_shape.members))

    def test_two_page_queue_discovery_with_attributes(self):
        async def scenario():
            facade = SQSFacade.__new__(SQSFacade)
            facade.session = Mock()
            client = Mock()
            client.list_queues.side_effect = [
                {'QueueUrls': ['https://sqs.test/a'], 'NextToken': 'next'},
                {'QueueUrls': ['https://sqs.test/b']}
            ]
            async def attributes(queue_url, region, attribute_names):
                return queue_url, {'QueueArn': 'arn:aws:sqs:eu-west-1:1:' + queue_url[-1]}
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client), \
                 patch.object(facade, '_get_queue_attributes', side_effect=attributes):
                result = await facade.get_queues('eu-west-1', ['QueueArn'])
            self.assertEqual({r[0] for r in result},
                             {'https://sqs.test/a', 'https://sqs.test/b'})
            self.assertEqual(client.list_queues.call_args_list[0].kwargs,
                             {'MaxResults': 1000})
            self.assertEqual(client.list_queues.call_args_list[1].kwargs,
                             {'MaxResults': 1000, 'NextToken': 'next'})
        asyncio.run(scenario())

    def test_deleted_queue_does_not_crash_and_marks_incomplete(self):
        async def scenario():
            context = RunContext('aws').setup()
            facade = SQSFacade.__new__(SQSFacade)
            facade.session = Mock()
            client = Mock()
            client.get_queue_attributes.side_effect = ClientError(
                {'Error': {'Code': 'AWS.SimpleQueueService.NonExistentQueue',
                           'Message': 'synthetic'}}, 'GetQueueAttributes'
            )
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    result = await facade._get_queue_attributes(
                        'https://sqs.test/missing', 'eu-west-1', ['QueueArn']
                    )
                self.assertIsNone(result)
                self.assertEqual(context.collection_issues[0]['reason_code'],
                                 'QueueDeleted')
            finally:
                await context.aclose()
        asyncio.run(scenario())
