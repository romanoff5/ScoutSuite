"""M06 KMS key states, rotation eligibility and optional API fields."""
import asyncio
from unittest import TestCase
from unittest.mock import AsyncMock, Mock

from botocore.session import get_session

from ScoutSuite.providers.aws.resources.kms.keys import Keys


class TestKMSRotation(TestCase):
    def test_rotation_response_model(self):
        operation = get_session().get_service_model('kms').operation_model(
            'GetKeyRotationStatus')
        for name in ('KeyRotationEnabled', 'RotationPeriodInDays',
                     'NextRotationDate'):
            self.assertIn(name, operation.output_shape.members)

    def _parse(self, metadata, status=None):
        async def scenario():
            keys = Keys.__new__(Keys)
            keys.region = 'eu-central-1'
            keys.facade = Mock()
            keys.facade.kms.get_key_rotation_status = AsyncMock(
                return_value=status)
            raw = {'KeyId': 'key-123', 'KeyArn': 'arn:aws:kms:eu-central-1:1:key/key-123',
                   'metadata': {'KeyMetadata': metadata}}
            _key, parsed = await keys._parse_key(raw)
            return parsed, keys.facade.kms.get_key_rotation_status
        return asyncio.run(scenario())

    def test_customer_symmetric_reports_real_rotation_period(self):
        key, call = self._parse({
            'KeyState': 'Enabled', 'KeyManager': 'CUSTOMER',
            'Origin': 'AWS_KMS', 'KeySpec': 'SYMMETRIC_DEFAULT',
            'KeyUsage': 'ENCRYPT_DECRYPT'
        }, {'KeyRotationEnabled': True, 'RotationPeriodInDays': 180,
            'NextRotationDate': 'synthetic-date'})
        self.assertTrue(key['rotation_enabled'])
        self.assertEqual(key['rotation_period_days'], 180)
        self.assertEqual(key['rotation_status'], 'enabled')
        call.assert_awaited_once_with('eu-central-1', 'key-123')

    def test_asymmetric_imported_and_hmac_are_not_misclassified_as_rotating(self):
        for changes in (
            {'KeySpec': 'RSA_2048', 'KeyUsage': 'ENCRYPT_DECRYPT'},
            {'KeySpec': 'HMAC_256', 'KeyUsage': 'GENERATE_VERIFY_MAC'},
            {'Origin': 'EXTERNAL', 'KeySpec': 'SYMMETRIC_DEFAULT'}
        ):
            with self.subTest(changes=changes):
                metadata = {
                    'KeyState': 'Enabled', 'KeyManager': 'CUSTOMER',
                    'Origin': 'AWS_KMS', 'KeySpec': 'SYMMETRIC_DEFAULT',
                    'KeyUsage': 'ENCRYPT_DECRYPT'
                }
                metadata.update(changes)
                key, call = self._parse(metadata)
                self.assertIsNone(key['rotation_enabled'])
                self.assertEqual(key['rotation_status'], 'not_supported')
                call.assert_not_awaited()

    def test_aws_managed_symmetric_is_rotated(self):
        key, call = self._parse({
            'KeyState': 'Enabled', 'KeyManager': 'AWS',
            'Origin': 'AWS_KMS', 'KeySpec': 'SYMMETRIC_DEFAULT',
            'KeyUsage': 'ENCRYPT_DECRYPT'
        })
        self.assertTrue(key['rotation_enabled'])
        self.assertEqual(key['rotation_status'], 'aws_managed')
        call.assert_not_awaited()

    def test_unknown_fields_and_denied_rotation_are_unknown(self):
        key, call = self._parse({
            'KeyState': 'PendingImport', 'KeyManager': 'CUSTOMER',
            'Origin': 'AWS_KMS', 'KeySpec': 'SYMMETRIC_DEFAULT',
            'KeyUsage': 'ENCRYPT_DECRYPT'
        })
        self.assertFalse(key['key_enabled'])
        self.assertIsNone(key['rotation_enabled'])
        self.assertEqual(key['rotation_status'], 'unavailable')
        call.assert_awaited_once()
        missing, call = self._parse({})
        self.assertIsNone(missing['key_enabled'])
        self.assertEqual(missing['aliases'], [])
        self.assertIsNone(missing['rotation_enabled'])
        call.assert_not_awaited()
