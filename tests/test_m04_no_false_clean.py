"""Regression for early paginator failure and existing report provenance."""
import asyncio
from unittest import TestCase
from unittest.mock import MagicMock, Mock, patch

from ScoutSuite import __main__ as main
from ScoutSuite.core.console import print_exception
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils


class TestM04NoFalseCleanResults(TestCase):
    def test_missing_sdk_client_is_incomplete_instead_of_crashing(self):
        async def scenario():
            context = RunContext('aws').setup()
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=None):
                    result = await AWSFacadeUtils.get_multiple_entities_from_all_pages(
                        's3', 'eu-central-1', Mock(), 'list_objects', ['Objects']
                    )
                self.assertEqual(result, {'Objects': []})
                self.assertEqual(context.collection_summary()['status'], 'partial')
                self.assertEqual(context.collection_issues[0]['reason_code'],
                                 'ClientConstruction')
            finally:
                await context.aclose()
        asyncio.run(scenario())

    def test_paginator_construction_denied_is_incomplete(self):
        from botocore.exceptions import ClientError
        async def scenario():
            context = RunContext('aws').setup()
            client = Mock()
            client.get_paginator.side_effect = ClientError(
                {'Error': {'Code': 'AccessDenied', 'Message': 'synthetic'}},
                'ListObjects'
            )
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    result = await AWSFacadeUtils.get_multiple_entities_from_all_pages(
                        's3', 'eu-central-1', Mock(), 'list_objects', ['Objects']
                    )
                self.assertEqual(result, {'Objects': []})
                self.assertEqual(context.collection_issues[0]['status'], 'denied')
            finally:
                await context.aclose()
        asyncio.run(scenario())

    def test_local_replay_preserves_original_denial_when_new_errors_occur(self):
        async def scenario():
            provider = MagicMock(provider_code='aws', environment='local')
            provider.get_report_name.return_value = 'synthetic'
            saved_issue = {'status': 'denied', 'scope': 's3', 'reason_code': 'AccessDenied'}
            report = MagicMock()
            report.encoder.load_from_file.return_value = {
                'services': {}, 'service_list': [], 'account_id': 'synthetic',
                'partition': 'aws', 'collection_status': {
                    'version': 1, 'status': 'partial', 'complete': False,
                    'checked_items': 0, 'evidence_evaluated': False,
                    'compliance_verified': False, 'issues': [saved_issue]
                }
            }
            report.save.return_value = 'synthetic.html'
            with patch.object(main, 'get_authentication_strategy',
                              side_effect=AssertionError('auth not permitted')), \
                 patch.object(main, 'get_provider', return_value=provider), \
                 patch.object(main, 'ScoutReport', return_value=report), \
                 patch.object(main, 'Ruleset'), patch.object(main, 'ProcessingEngine') as engine:
                engine.return_value.run.side_effect = lambda _provider: print_exception(
                    'synthetic new evaluation failure'
                )
                rc = await main.run_async(
                    provider='aws', fetch_local=True, no_browser=True,
                    strict_completeness=True
                )
            self.assertEqual(rc, 201)
            issues = provider.collection_status['issues']
            self.assertIn(saved_issue, issues)
            self.assertTrue(any(i['reason_code'] == 'UnclassifiedError' for i in issues))
            self.assertFalse(provider.collection_status['complete'])
            report.save.assert_called_once()

        asyncio.run(scenario())
