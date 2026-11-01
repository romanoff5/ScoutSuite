"""M05-E ACM certificate inventory filters (offline pinned botocore model)."""
import asyncio
from unittest import TestCase
from unittest.mock import AsyncMock, Mock, patch

from botocore.session import get_session

from ScoutSuite.providers.aws.facade.acm import AcmFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils


class TestACMFilters(TestCase):
    def test_key_type_and_status_enums_match_model(self):
        op = get_session().get_service_model('acm').operation_model(
            'ListCertificates'
        )
        include_types = set(op.input_shape.members[
            'Includes'].members['keyTypes'].member.metadata['enum'])
        statuses = set(op.input_shape.members[
            'CertificateStatuses'].member.metadata['enum'])
        self.assertEqual(include_types, {
            'RSA_1024', 'RSA_2048', 'RSA_3072', 'RSA_4096',
            'EC_prime256v1', 'EC_secp384r1', 'EC_secp521r1'
        })
        self.assertEqual(statuses, {
            'PENDING_VALIDATION', 'ISSUED', 'INACTIVE', 'EXPIRED',
            'VALIDATION_TIMED_OUT', 'REVOKED', 'FAILED'
        })

    def test_collector_requests_every_model_supported_certificate_type(self):
        async def scenario():
            facade = AcmFacade.__new__(AcmFacade)
            facade.session = Mock()
            certificates = [{
                'CertificateArn': 'arn:aws:acm:eu-central-1:123:certificate/id'
            }]
            with patch.object(AWSFacadeUtils, 'get_all_pages',
                              new_callable=AsyncMock, return_value=certificates) as pages, \
                 patch.object(facade, '_get_certificate',
                              new_callable=AsyncMock, return_value={'DomainName': 'test'}):
                result = await facade.get_certificates('eu-central-1')
            self.assertEqual(result, [{'DomainName': 'test'}])
            args, kwargs = pages.await_args
            self.assertEqual(args[:5], (
                'acm', 'eu-central-1', facade.session,
                'list_certificates', 'CertificateSummaryList'
            ))
            model = get_session().get_service_model('acm').operation_model(
                'ListCertificates'
            )
            self.assertEqual(set(kwargs['Includes']['keyTypes']), set(
                model.input_shape.members['Includes'].members[
                    'keyTypes'].member.metadata['enum']
            ))
            self.assertEqual(set(kwargs['CertificateStatuses']), set(
                model.input_shape.members['CertificateStatuses'].member.metadata['enum']
            ))

        asyncio.run(scenario())

    def test_empty_inventory_does_not_trigger_describe_calls(self):
        async def scenario():
            facade = AcmFacade.__new__(AcmFacade)
            facade.session = Mock()
            with patch.object(AWSFacadeUtils, 'get_all_pages',
                              new_callable=AsyncMock, return_value=[]), \
                 patch.object(facade, '_get_certificate',
                              new_callable=AsyncMock) as describe:
                self.assertEqual(await facade.get_certificates('us-west-2'), [])
            describe.assert_not_awaited()
        asyncio.run(scenario())
