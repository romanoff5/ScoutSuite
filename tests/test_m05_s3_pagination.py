"""M05-A AWS S3 pagination, retention and model contracts (offline only)."""
import asyncio
from unittest import TestCase
from unittest.mock import AsyncMock, Mock, patch

from botocore.session import get_session

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.pagination import PaginationError
from ScoutSuite.providers.aws.facade.s3 import S3Facade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils


class TestS3Pagination(TestCase):
    def test_sdk_request_and_response_contract(self):
        operation = get_session().get_service_model('s3').operation_model('ListBuckets')
        self.assertTrue({'MaxBuckets', 'ContinuationToken'} <=
                        set(operation.input_shape.members))
        self.assertTrue({'Buckets', 'ContinuationToken'} <=
                        set(operation.output_shape.members))

    def test_multiple_pages_and_exact_tokens(self):
        async def scenario():
            client = Mock()
            client.list_buckets.side_effect = [
                {'Buckets': [{'Name': 'first'}], 'ContinuationToken': 'next'},
                {'Buckets': [{'Name': 'second'}]},
            ]
            result = await S3Facade._list_bucket_pages(client)
            self.assertEqual([x['Name'] for x in result], ['first', 'second'])
            self.assertEqual(client.list_buckets.call_args_list[0].kwargs,
                             {'MaxBuckets': 1000})
            self.assertEqual(client.list_buckets.call_args_list[1].kwargs,
                             {'MaxBuckets': 1000, 'ContinuationToken': 'next'})
        asyncio.run(scenario())

    def test_empty_and_single_page_results(self):
        async def scenario():
            client = Mock()
            client.list_buckets.return_value = {'Buckets': []}
            self.assertEqual(await S3Facade._list_bucket_pages(client), [])
            client.list_buckets.return_value = {'Buckets': [{'Name': 'one'}]}
            self.assertEqual(len(await S3Facade._list_bucket_pages(client)), 1)
        asyncio.run(scenario())

    def test_failure_after_first_page_keeps_partial_and_marks_status(self):
        async def scenario():
            context = RunContext('aws').setup()
            client = Mock()
            client.list_buckets.side_effect = [
                {'Buckets': [{'Name': 'first'}], 'ContinuationToken': 'duplicate'},
                {'Buckets': [{'Name': 'second'}], 'ContinuationToken': 'duplicate'}
            ]
            try:
                with self.assertRaises(PaginationError) as error:
                    await S3Facade._list_bucket_pages(client)
                self.assertEqual(len(error.exception.items), 1)
                self.assertEqual(context.collection_issues[0], {
                    'status': 'partial', 'scope': 's3',
                    'reason_code': 'RepeatedToken'
                })
            finally:
                await context.aclose()
        asyncio.run(scenario())

    def test_creation_date_fix_uses_all_pages(self):
        async def scenario():
            facade = S3Facade.__new__(S3Facade)
            facade.session = Mock()
            client = Mock()
            client.list_buckets.side_effect = [
                {'Buckets': [{'Name': 'other', 'CreationDate': 'date1'}],
                 'ContinuationToken': 'next'},
                {'Buckets': [{'Name': 'target', 'CreationDate': 'correct'}]}
            ]
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                buckets = [{'Name': 'target', 'CreationDate': 'stale'}]
                await facade._get_and_set_s3_bucket_creationdate(buckets)
            self.assertEqual(buckets[0]['CreationDate'], 'correct')
        asyncio.run(scenario())

    def test_list_buckets_fallback_only_marks_last_region_failure(self):
        async def scenario():
            facade = S3Facade.__new__(S3Facade)
            facade.session = Mock()
            facade.regions = ['bad-region', 'good-region']
            bad = Mock()
            bad.list_buckets.side_effect = RuntimeError('synthetic denied')
            good = Mock()
            good.list_buckets.return_value = {'Buckets': []}
            context = RunContext('aws').setup()
            try:
                with patch.object(AWSFacadeUtils, 'get_client', side_effect=[bad, good]):
                    self.assertEqual(await facade.get_buckets(), [])
                self.assertEqual(context.collection_issues, [])
            finally:
                await context.aclose()
        asyncio.run(scenario())
