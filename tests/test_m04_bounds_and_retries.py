"""M03/M04 fake-clock backoff and bounded queue regression (offline only)."""
import asyncio
from unittest import TestCase
from unittest.mock import patch

from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.utils import (
    get_and_set_concurrently, map_concurrently, run_concurrently
)


class TestBoundedCollection(TestCase):
    def test_map_limits_live_and_queued_tasks(self):
        async def scenario():
            context = RunContext('aws', max_workers=3).setup()
            active = peak = 0
            try:
                async def work(item):
                    nonlocal active, peak
                    active += 1
                    peak = max(peak, active)
                    self.assertLessEqual(len(context._children), 3)
                    await asyncio.sleep(0)
                    active -= 1
                    return item
                result = await map_concurrently(work, list(range(40)))
                self.assertEqual(set(result), set(range(40)))
                self.assertLessEqual(peak, 3)
            finally:
                await context.aclose()
        asyncio.run(scenario())

    def test_get_and_set_does_not_create_unbounded_tasks(self):
        async def scenario():
            context = RunContext('aws', max_workers=2).setup()
            observed = []
            async def work(item):
                self.assertLessEqual(len(context._children), 2)
                observed.append(item)
                await asyncio.sleep(0)
            try:
                await get_and_set_concurrently([work, work], list(range(20)))
                self.assertEqual(len(observed), 40)
            finally:
                await context.aclose()
        asyncio.run(scenario())

    def test_failed_child_is_visible_as_incomplete(self):
        async def scenario():
            context = RunContext('aws').setup()
            async def fail(item):
                raise ValueError('synthetic collector error')
            try:
                self.assertEqual(await map_concurrently(fail, [1, 2]), [])
                self.assertEqual(context.collection_summary()['status'], 'partial')
                self.assertEqual(len(context.collection_issues), 1)
                self.assertEqual(context.collection_issues[0]['reason_code'], 'ChildTaskError')
            finally:
                await context.aclose()
        asyncio.run(scenario())


class TestFiniteRetryPolicy(TestCase):
    def test_fake_clock_capped_throttle_retries(self):
        async def scenario():
            calls, sleeps = [], []

            def api():
                calls.append(1)
                raise ClientError({'Error': {'Code': 'Throttling', 'Message': 'synthetic'}},
                                  'DescribeResources')

            async def fake_sleep(seconds):
                sleeps.append(seconds)

            with patch('ScoutSuite.providers.utils.asyncio.sleep', side_effect=fake_sleep), \
                 patch('ScoutSuite.providers.utils.random.uniform', return_value=1.0):
                with self.assertRaises(ClientError):
                    await run_concurrently(api, backoff_seconds=2, max_attempts=3)
            self.assertEqual(len(calls), 3)
            self.assertEqual(sleeps, [2, 4])

        asyncio.run(scenario())

    def test_no_implicit_retry_on_throttling(self):
        async def scenario():
            calls = []
            def api():
                calls.append(1)
                raise ClientError({'Error': {'Code': 'Throttling', 'Message': 'synthetic'}},
                                  'DescribeResources')
            with self.assertRaises(ClientError):
                await run_concurrently(api)
            self.assertEqual(len(calls), 1)

        asyncio.run(scenario())

    def test_cancellation_during_backoff_stops_attempts(self):
        async def scenario():
            context = RunContext('aws').setup()
            sleeping = asyncio.Event()
            calls = []

            def api():
                calls.append(1)
                raise ClientError({'Error': {'Code': 'Throttling', 'Message': 'synthetic'}},
                                  'DescribeResources')

            async def delayed(_seconds):
                sleeping.set()
                await asyncio.Event().wait()

            try:
                with patch('ScoutSuite.providers.utils.asyncio.sleep', side_effect=delayed):
                    task = asyncio.create_task(run_concurrently(api, max_attempts=5))
                    await asyncio.wait_for(sleeping.wait(), timeout=2)
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                self.assertEqual(len(calls), 1)
            finally:
                await context.aclose()
        asyncio.run(scenario())
