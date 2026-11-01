"""Guarded M04-A tests for AWS SDK client isolation and disposal."""
import asyncio
from unittest import TestCase
from unittest.mock import Mock

from ScoutSuite.core.run_context import RunContext, get_current_run_context
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_function_concurrently


class TestAWSClientIsolation(TestCase):
    def test_two_accounts_same_region_do_not_share_clients(self):
        async def scenario():
            async def assessment(label):
                session = Mock(name=label)
                client = Mock(name=label + '-client')
                session.client.return_value = client
                context = RunContext('aws').setup()
                try:
                    first = AWSFacadeUtils.get_client('ec2', session, 'us-east-1')
                    second = AWSFacadeUtils.get_client('ec2', session, 'us-east-1')
                    self.assertIs(first, second)
                    self.assertEqual(session.client.call_count, 1)
                    self.assertEqual(session.client.call_args.kwargs['region_name'], 'us-east-1')
                    self.assertIs(get_current_run_context(), context)
                    return client, session
                finally:
                    await context.aclose()

            (a, a_session), (b, b_session) = await asyncio.gather(
                assessment('account-a'), assessment('account-b')
            )
            self.assertIsNot(a, b)
            self.assertEqual(a_session.client.call_count, 1)
            self.assertEqual(b_session.client.call_count, 1)
            a.close.assert_called_once_with()
            b.close.assert_called_once_with()

        asyncio.run(scenario())

    def test_different_sessions_in_same_run_are_isolated(self):
        async def scenario():
            context = RunContext('aws').setup()
            first, second = Mock(name='account-a'), Mock(name='account-b')
            try:
                a = AWSFacadeUtils.get_client('s3', first, 'eu-central-1')
                b = AWSFacadeUtils.get_client('s3', second, 'eu-central-1')
                self.assertIsNot(a, b)
                self.assertEqual(first.client.call_count, 1)
                self.assertEqual(second.client.call_count, 1)
                self.assertEqual(len(context._clients), 2)
            finally:
                await context.aclose()
            a.close.assert_called_once_with()
            b.close.assert_called_once_with()

        asyncio.run(scenario())

    def test_thread_executor_preserves_run_context_and_cache(self):
        async def scenario():
            context = RunContext('aws', max_workers=2).setup()
            session = Mock()
            try:
                result = await asyncio.gather(*[
                    run_function_concurrently(
                        lambda: (
                            get_current_run_context(),
                            AWSFacadeUtils.get_client('iam', session, 'us-east-1')
                        )
                    ) for _ in range(5)
                ])
                self.assertTrue(all(context is found for found, _client in result))
                self.assertTrue(all(result[0][1] is client for _found, client in result))
                self.assertEqual(session.client.call_count, 1)
            finally:
                await context.aclose()
            result[0][1].close.assert_called_once_with()

        asyncio.run(scenario())

    def test_no_context_never_reuses_stale_client(self):
        session = Mock()
        a = AWSFacadeUtils.get_client('s3', session, 'us-east-1')
        b = AWSFacadeUtils.get_client('s3', session, 'us-east-1')
        self.assertIs(a, session.client.return_value)
        self.assertEqual(session.client.call_count, 2)
        a.close()
