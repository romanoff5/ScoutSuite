"""M06 S3 bucket/account access: absent configuration differs from AccessDenied."""
import asyncio
from unittest import TestCase
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from botocore.session import get_session

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.s3 import S3Facade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils


def api_error(code, operation):
    return ClientError({'Error': {'Code': code, 'Message': 'synthetic'}}, operation)


class TestS3OwnershipAndExposure(TestCase):
    def test_api_models_include_read_only_operations(self):
        model = get_session().get_service_model('s3')
        for name in ('GetBucketOwnershipControls', 'GetBucketPolicyStatus',
                     'GetPublicAccessBlock'):
            self.assertIn('Bucket', model.operation_model(name).input_shape.members)

    def test_known_public_access_absence_is_false_but_denied_is_unknown(self):
        async def scenario():
            facade = S3Facade(Mock())
            client = Mock()
            bucket = {'Name': 'a', 'region': 'eu-central-1'}
            client.get_public_access_block.side_effect = api_error(
                'NoSuchPublicAccessBlockConfiguration', 'GetPublicAccessBlock')
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                await facade._get_and_set_s3_bucket_block_public_access(bucket)
            self.assertEqual(bucket['public_access_block_configuration'], {
                'BlockPublicAcls': False, 'IgnorePublicAcls': False,
                'BlockPublicPolicy': False, 'RestrictPublicBuckets': False
            })

            context = RunContext('aws').setup()
            try:
                bucket = {'Name': 'b', 'region': 'eu-central-1'}
                client.get_public_access_block.side_effect = api_error(
                    'AccessDenied', 'GetPublicAccessBlock')
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    await facade._get_and_set_s3_bucket_block_public_access(bucket)
                self.assertIsNone(bucket['public_access_block_configuration'])
                self.assertEqual(context.collection_issues[0]['reason_code'],
                                 'BucketPublicAccessBlock')
            finally:
                await context.aclose()
        asyncio.run(scenario())

    def test_owner_enforced_and_public_policy_are_preserved(self):
        async def scenario():
            facade = S3Facade(Mock())
            client = Mock()
            client.get_bucket_ownership_controls.return_value = {
                'OwnershipControls': {'Rules': [
                    {'ObjectOwnership': 'BucketOwnerEnforced'}]}}
            client.get_bucket_policy_status.return_value = {
                'PolicyStatus': {'IsPublic': True}}
            bucket = {'Name': 'example', 'region': 'eu-central-1'}
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                await facade._get_and_set_s3_bucket_ownership(bucket)
                await facade._get_and_set_s3_bucket_policy_status(bucket)
            self.assertEqual(bucket['object_ownership'], 'BucketOwnerEnforced')
            self.assertTrue(bucket['policy_is_public'])
            client.get_bucket_policy_status.assert_called_once_with(
                Bucket='example')
        asyncio.run(scenario())

    def test_legacy_ownership_absence_not_inferred_from_creation_date(self):
        async def scenario():
            facade = S3Facade(Mock())
            client = Mock()
            client.get_bucket_ownership_controls.side_effect = api_error(
                'OwnershipControlsNotFoundError', 'GetBucketOwnershipControls')
            bucket = {'Name': 'legacy', 'region': 'eu-central-1'}
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                await facade._get_and_set_s3_bucket_ownership(bucket)
            self.assertIsNone(bucket['object_ownership'])
        asyncio.run(scenario())

    def test_account_denied_not_equal_to_absent_for_china_and_gov(self):
        async def scenario():
            for configured, expected in [('cn-northwest-1', 'cn-north-1'),
                                         ('us-gov-east-1', 'us-gov-west-1'),
                                         ('eu-central-1', 'us-east-1')]:
                with self.subTest(region=configured):
                    session = Mock(region_name=configured)
                    facade = S3Facade(session)
                    client = Mock()
                    client.get_public_access_block.side_effect = api_error(
                        'AccessDenied', 'GetPublicAccessBlock')
                    context = RunContext('aws').setup()
                    try:
                        with patch.object(AWSFacadeUtils, 'get_client',
                                          return_value=client) as get_client:
                            self.assertIsNone(facade.get_s3_public_access_block('123'))
                        self.assertEqual(get_client.call_args.args[2], expected)
                        self.assertTrue(context.collection_issues)
                    finally:
                        await context.aclose()
        asyncio.run(scenario())
