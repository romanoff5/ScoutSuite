"""Guarded end-to-end M04 integrity contracts: no real credentials or cloud API."""
import asyncio
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from botocore.exceptions import ClientError, ReadTimeoutError

from ScoutSuite import __main__ as main
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.output.result_encoder import ScoutResultEncoder
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils


class TestM04ReportSerialization(TestCase):
    def test_structured_incomplete_status_survives_json_encoding(self):
        context = RunContext('aws')
        context.record_collection_issue('denied', 's3', 'AccessDenied')
        provider = SimpleNamespace(
            provider_code='aws', services={'s3': {'buckets': {}}},
            service_list=['s3'], collection_status=context.collection_summary()
        )
        result = ScoutResultEncoder.to_dict(provider)
        self.assertEqual(result['collection_status']['version'], 1)
        self.assertEqual(result['collection_status']['status'], 'partial')
        self.assertFalse(result['collection_status']['complete'])
        self.assertEqual(result['collection_status']['issues'], [
            {'scope': 's3', 'status': 'denied', 'reason_code': 'AccessDenied'}
        ])

    def test_local_replay_with_no_checked_findings_returns_strict_exit_201(self):
        async def scenario():
            provider = MagicMock(provider_code='aws', environment='local', account_id='synthetic')
            provider.get_report_name.return_value = 'synthetic'
            report = MagicMock()
            report.encoder.load_from_file.return_value = {
                'services': {}, 'service_list': [], 'account_id': 'synthetic',
                'partition': 'aws'
            }
            report.save.return_value = 'synthetic-report.html'
            with patch.object(main, 'get_authentication_strategy',
                              side_effect=AssertionError('authentication forbidden')) as auth, \
                 patch.object(main, 'get_provider', return_value=provider), \
                 patch.object(main, 'ScoutReport', return_value=report), \
                 patch.object(main, 'Ruleset'), patch.object(main, 'ProcessingEngine'):
                code = await main.run_async(
                    provider='aws', fetch_local=True, no_browser=True,
                    strict_completeness=True
                )
            self.assertEqual(code, 201)
            self.assertFalse(provider.collection_status['evidence_evaluated'])
            report.save.assert_called_once()
            auth.assert_not_called()

        asyncio.run(scenario())

    def test_strict_mode_accepts_evaluated_result_without_errors(self):
        async def scenario():
            provider = MagicMock(provider_code='aws', environment='test', account_id='synthetic')
            provider.services = {'ec2': {
                'findings': {'evaluated': {'checked_items': 1, 'items': [],
                                           'flagged_items': 0}}
            }}
            provider.service_list = ['ec2']
            provider.fetch = AsyncMock()
            provider.get_report_name.return_value = 'synthetic'
            report = MagicMock()
            report.save.return_value = 'synthetic-report.html'
            with patch.object(main, 'get_authentication_strategy') as auth, \
                 patch.object(main, 'get_provider', return_value=provider), \
                 patch.object(main, 'ScoutReport', return_value=report), \
                 patch.object(main, 'Ruleset'), patch.object(main, 'ProcessingEngine'):
                auth.return_value.authenticate.return_value = object()
                result = await main.run_async(
                    provider='aws', no_browser=True, strict_completeness=True
                )
            self.assertEqual(result, 0)
            self.assertEqual(provider.collection_status['checked_items'], 1)
            self.assertTrue(provider.collection_status['evidence_evaluated'])
            report.save.assert_called_once()

        asyncio.run(scenario())


class TestM04AWSIncompleteResponses(TestCase):
    def test_unsupported_response_is_not_silent_success(self):
        async def scenario():
            context = RunContext('aws').setup()
            client = Mock()

            def unsupported():
                raise ClientError({'Error': {'Code': 'UnsupportedOperation',
                                            'Message': 'synthetic'}}, 'ListThings')
                yield None

            client.get_paginator.return_value.paginate.return_value = unsupported()
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    value = await AWSFacadeUtils.get_multiple_entities_from_all_pages(
                        'ec2', 'us-east-1', Mock(), 'list_things', ['Things']
                    )
                self.assertEqual(value, {'Things': []})
                summary = context.collection_summary()
                self.assertFalse(summary['complete'])
                self.assertEqual(summary['issues'][0]['status'], 'unsupported')
            finally:
                await context.aclose()

        asyncio.run(scenario())

    def test_read_timeout_is_reported_without_performing_network_access(self):
        async def scenario():
            context = RunContext('aws').setup()
            client = Mock()

            def timed_out():
                raise ReadTimeoutError(endpoint_url='https://offline.invalid')
                yield None

            client.get_paginator.return_value.paginate.return_value = timed_out()
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    value = await AWSFacadeUtils.get_multiple_entities_from_all_pages(
                        's3', 'us-east-1', Mock(), 'list_things', ['Things']
                    )
                self.assertEqual(value, {'Things': []})
                summary = context.collection_summary()
                self.assertEqual(summary['issues'][0]['status'], 'failed')
                self.assertEqual(summary['issues'][0]['reason_code'], 'Timeout')
                self.assertNotIn('offline.invalid', str(summary))
            finally:
                await context.aclose()

        asyncio.run(scenario())
