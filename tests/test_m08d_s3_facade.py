"""M08-D S3 facade: current default encryption, denied reads, HTTPS proof."""
import asyncio
from unittest import TestCase
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.s3 import S3Facade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.core.rule_evidence import classify_s3_encryption, classify_s3_secure_transport


def client_error(code, operation):
    return ClientError({'Error': {'Code': code, 'Message': 'synthetic'}}, operation)


def bucket():
    return {'Name': 'example', 'region': 'us-east-1'}


class TestM08DS3Facade(TestCase):
    def test_no_config_is_automatic_sse_s3_not_unencrypted(self):
        async def scenario():
            client = Mock()
            client.get_bucket_encryption.side_effect = client_error(
                'ServerSideEncryptionConfigurationNotFoundError',
                'GetBucketEncryption')
            item = bucket()
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                await S3Facade(Mock())._get_and_set_s3_bucket_default_encryption(item)
            self.assertTrue(item['default_encryption_enabled'])
            self.assertEqual(item['default_encryption_algorithm'], 'AES256')
            self.assertEqual(item['encryption_evidence'], 'aws_baseline')
            self.assertEqual(classify_s3_encryption(item), 'secure')
        asyncio.run(scenario())

    def test_kms_and_dual_layer_explicit_configs(self):
        async def scenario(algorithm):
            client = Mock()
            client.get_bucket_encryption.return_value = {
                'ServerSideEncryptionConfiguration': {'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': algorithm, 'KMSMasterKeyID': 'key-1'}
                }]}
            }
            item = bucket()
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                await S3Facade(Mock())._get_and_set_s3_bucket_default_encryption(item)
            self.assertEqual(item['default_encryption_algorithm'], algorithm)
            self.assertEqual(item['default_encryption_key'], 'key-1')
            self.assertEqual(item['encryption_evidence'], 'api')
            self.assertEqual(classify_s3_encryption(item), 'secure')
        for algorithm in ('AES256', 'aws:kms', 'aws:kms:dsse'):
            with self.subTest(algorithm=algorithm):
                asyncio.run(scenario(algorithm))

    def test_encryption_denied_and_malformed_are_incomplete(self):
        async def scenario(response):
            context = RunContext('aws').setup()
            client = Mock()
            if isinstance(response, Exception):
                client.get_bucket_encryption.side_effect = response
            else:
                client.get_bucket_encryption.return_value = response
            try:
                item = bucket()
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    await S3Facade(Mock())._get_and_set_s3_bucket_default_encryption(item)
                self.assertIsNone(item['default_encryption_enabled'])
                self.assertIsNone(item['default_encryption_algorithm'])
                self.assertEqual(item['encryption_evidence'], 'unverified')
                self.assertEqual(classify_s3_encryption(item), 'unknown')
                self.assertIn('BucketEncryption',
                              [issue['reason_code'] for issue in context.collection_issues])
            finally:
                await context.aclose()
        asyncio.run(scenario(client_error('AccessDenied', 'GetBucketEncryption')))
        asyncio.run(scenario({'ServerSideEncryptionConfiguration': {'Rules': []}}))

    def test_acl_and_policy_denials_mark_missing_evidence(self):
        async def scenario():
            context = RunContext('aws').setup()
            client = Mock()
            client.get_bucket_acl.side_effect = client_error(
                'AccessDenied', 'GetBucketAcl')
            client.get_bucket_policy.side_effect = client_error(
                'AccessDenied', 'GetBucketPolicy')
            facade = S3Facade(Mock())
            item = bucket()
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    await facade._get_and_set_s3_acls(item)
                    await facade._get_and_set_s3_bucket_policy(item)
                self.assertEqual(item['acl_collection_status'], 'failed')
                self.assertEqual(item['policy_collection_status'], 'failed')
                self.assertNotIn('policy', item)
                self.assertEqual(item['grantees'], {})
                facade._set_s3_bucket_secure_transport(item)
                self.assertIsNone(item['secure_transport_enabled'])
                self.assertEqual(classify_s3_secure_transport(item), 'unknown')
                self.assertTrue({'BucketACL', 'BucketPolicy', 'SecureTransportEvidence'}
                                <= {x['reason_code'] for x in context.collection_issues})
            finally:
                await context.aclose()
        asyncio.run(scenario())

    def test_https_enforcement_requires_unconditional_deny_on_both_resources(self):
        facade = S3Facade(Mock())
        item = bucket()
        item['policy_collection_status'] = 'success'
        statement = {
            'Effect': 'Deny', 'Principal': '*', 'Action': 's3:*',
            'Resource': ['arn:aws:s3:::example', 'arn:aws:s3:::example/*'],
            'Condition': {'Bool': {
                'aws:SecureTransport': 'false',
                'aws:PrincipalIsAWSService': 'false'
            }}
        }
        item['policy'] = {'Statement': [statement]}
        facade._set_s3_bucket_secure_transport(item)
        self.assertTrue(item['secure_transport_enabled'])

        item['policy'] = {'Statement': [{
            'Effect': 'Allow', 'Principal': '*', 'Action': 's3:*',
            'Resource': '*', 'Condition': {'Bool': {'aws:SecureTransport': 'true'}}
        }]}
        facade._set_s3_bucket_secure_transport(item)
        self.assertFalse(item['secure_transport_enabled'])

        item['policy'] = {'Statement': [{**statement,
            'Resource': ['arn:aws:s3:::example/*']}]}
        facade._set_s3_bucket_secure_transport(item)
        self.assertFalse(item['secure_transport_enabled'])

        item['policy'] = {'Statement': [{**statement,
            'Condition': {'Bool': {'aws:SecureTransport': 'false'},
                          'IpAddress': {'aws:SourceIp': '10.0.0.0/8'}}}]}
        facade._set_s3_bucket_secure_transport(item)
        self.assertFalse(item['secure_transport_enabled'])

        item['policy_collection_status'] = 'absent'
        facade._set_s3_bucket_secure_transport(item)
        self.assertFalse(item['secure_transport_enabled'])
