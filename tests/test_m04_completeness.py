"""Offline M04-B completeness and per-run diagnostic contracts."""
import asyncio
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

from ScoutSuite import ERRORS_LIST
from ScoutSuite.core.console import print_exception
from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils


class TestCollectionIntegrity(TestCase):
    def test_denied_paginator_is_not_a_successful_empty_collection(self):
        async def scenario():
            context = RunContext('aws').setup()
            client = Mock()
            def page_stream():
                raise ClientError({'Error': {'Code': 'AccessDenied', 'Message': 'synthetic'}},
                                  'DescribeItems')
                yield None
            client.get_paginator.return_value.paginate.return_value = page_stream()
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    output = await AWSFacadeUtils.get_multiple_entities_from_all_pages(
                        'ec2', 'us-east-1', Mock(), 'describe_items', ['Items']
                    )
                self.assertEqual(output, {'Items': []})
                summary = context.collection_summary()
                self.assertEqual(summary['status'], 'partial')
                self.assertFalse(summary['complete'])
                self.assertEqual(summary['issues'][0]['status'], 'denied')
                self.assertFalse(summary['evidence_evaluated'])
            finally:
                await context.aclose()
        asyncio.run(scenario())

    def test_malformed_page_is_explicitly_incomplete(self):
        async def scenario():
            context = RunContext('aws').setup()
            client = Mock()
            client.get_paginator.return_value.paginate.return_value = [{'MissingItems': []}]
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    output = await AWSFacadeUtils.get_multiple_entities_from_all_pages(
                        's3', 'us-east-1', Mock(), 'list_items', ['Items']
                    )
                self.assertEqual(output, {'Items': []})
                self.assertEqual(context.collection_summary()['issues'][0]['reason_code'],
                                 'MalformedPage')
            finally:
                await context.aclose()
        asyncio.run(scenario())

    def test_empty_success_is_not_compliance_evidence(self):
        context = RunContext('aws')
        summary = context.collection_summary()
        self.assertEqual(summary['status'], 'success')
        self.assertTrue(summary['complete'])
        self.assertEqual(summary['checked_items'], 0)
        self.assertFalse(summary['evidence_evaluated'])
        self.assertFalse(summary['compliance_verified'])

    def test_parallel_runs_do_not_share_diagnostics(self):
        async def assessment(name):
            context = RunContext('aws').setup()
            try:
                print_exception('synthetic-' + name)
                await asyncio.sleep(0)
                return list(context.errors)
            finally:
                await context.aclose()

        ERRORS_LIST.clear()
        a, b = asyncio.run(asyncio.gather(assessment('a'), assessment('b'))) if False else (
            asyncio.run(self._parallel(assessment))
        )
        self.assertEqual(len(a), 1)
        self.assertEqual(len(b), 1)
        self.assertIn('synthetic-a', a[0]['exception'])
        self.assertIn('synthetic-b', b[0]['exception'])
        self.assertFalse(ERRORS_LIST)

    @staticmethod
    async def _parallel(assessment):
        return await asyncio.gather(assessment('a'), assessment('b'))

    def test_rule_failure_is_marked_incomplete_in_finding(self):
        async def scenario():
            context = RunContext('aws').setup()
            rule = SimpleNamespace(
                enabled=True, path='ec2.instances.id', service='ec2', key='test-rule',
                description='synthetic', filename='synthetic.json',
                dashboard_name='synthetic'
            )
            ruleset = SimpleNamespace(rules={'synthetic.json': [rule]}, rule_type='findings')
            provider = SimpleNamespace(
                services={'ec2': {'instances': {}}}, service_list=['ec2']
            )
            try:
                with patch('ScoutSuite.core.processingengine.recurse',
                           side_effect=ValueError('synthetic broken rule')):
                    ProcessingEngine(ruleset).run(provider)
                finding = provider.services['ec2']['findings']['test-rule']
                self.assertEqual(finding['assessment_status'], 'incomplete')
                self.assertEqual(finding['checked_items'], 0)
                self.assertEqual(finding['items'], [])
                self.assertEqual(context.collection_summary()['status'], 'partial')
            finally:
                await context.aclose()
        asyncio.run(scenario())
