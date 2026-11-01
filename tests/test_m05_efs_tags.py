"""M05-C EFS ListTagsForResource migration and pagination (offline)."""
import asyncio
from unittest import TestCase
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from botocore.session import get_session

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.efs import EFSFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils


class TestEFSTagListing(TestCase):
    def test_botocore_operation_model(self):
        model = get_session().get_service_model('efs').operation_model(
            'ListTagsForResource'
        )
        self.assertEqual(set(model.input_shape.members) &
                         {'ResourceId', 'MaxResults', 'NextToken'},
                         {'ResourceId', 'MaxResults', 'NextToken'})
        self.assertTrue({'Tags', 'NextToken'} <= set(model.output_shape.members))

    def test_two_page_tags_preserve_legacy_shape(self):
        async def scenario():
            facade = EFSFacade.__new__(EFSFacade)
            facade.session = Mock()
            client = Mock()
            client.list_tags_for_resource.side_effect = [
                {'Tags': [{'Key': 'one', 'Value': 'v1'}], 'NextToken': 'next'},
                {'Tags': [{'Key': 'two', 'Value': 'v2'}]}
            ]
            system = {'FileSystemId': 'fs-12345678'}
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                await facade._get_and_set_tags(system, 'us-east-1')
            self.assertEqual(system['Tags'], [
                {'Key': 'one', 'Value': 'v1'}, {'Key': 'two', 'Value': 'v2'}
            ])
            self.assertEqual(client.list_tags_for_resource.call_args_list[0].kwargs,
                             {'ResourceId': 'fs-12345678', 'MaxResults': 100})
            self.assertEqual(client.list_tags_for_resource.call_args_list[1].kwargs,
                             {'ResourceId': 'fs-12345678', 'MaxResults': 100,
                              'NextToken': 'next'})
            client.describe_tags.assert_not_called()
        asyncio.run(scenario())

    def test_denied_after_first_page_preserves_partial_and_status(self):
        async def scenario():
            context = RunContext('aws').setup()
            facade = EFSFacade.__new__(EFSFacade)
            facade.session = Mock()
            client = Mock()
            client.list_tags_for_resource.side_effect = [
                {'Tags': [{'Key': 'one', 'Value': 'v1'}], 'NextToken': 'next'},
                ClientError(
                    {'Error': {'Code': 'AccessDenied', 'Message': 'synthetic'}},
                    'ListTagsForResource'
                )
            ]
            try:
                system = {'FileSystemId': 'fs-12345678'}
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    await facade._get_and_set_tags(system, 'us-east-1')
                self.assertEqual(len(system['Tags']), 1)
                self.assertEqual(context.collection_issues[0], {
                    'scope': 'efs', 'status': 'partial', 'reason_code': 'AccessDenied'
                })
            finally:
                await context.aclose()
        asyncio.run(scenario())

    def test_no_tags_successful_empty(self):
        async def scenario():
            facade = EFSFacade.__new__(EFSFacade)
            facade.session = Mock()
            client = Mock()
            client.list_tags_for_resource.return_value = {}
            system = {'FileSystemId': 'fs-12345678'}
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                await facade._get_and_set_tags(system, 'us-west-2')
            self.assertEqual(system['Tags'], [])
        asyncio.run(scenario())
