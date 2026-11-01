"""Guarded M03 lifecycle and cancellation regression tests; no real cloud access."""
import asyncio
import threading
import unittest

from ScoutSuite.core.run_context import RunContext, get_current_run_context
from ScoutSuite.providers.utils import get_and_set_concurrently, run_function_concurrently


class TestM03LifecycleContracts(unittest.TestCase):
    def test_cancel_only_owned_tasks(self):
        async def scenario():
            loop = asyncio.get_running_loop()
            ctx = RunContext('aws').setup()
            entered = asyncio.Event()
            finalized = asyncio.Event()

            async def owned():
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    finalized.set()

            task = ctx.track_future(asyncio.create_task(owned()))
            unrelated = asyncio.create_task(asyncio.sleep(0.01, result=42))
            await entered.wait()
            await ctx.aclose()
            self.assertTrue(task.cancelled())
            self.assertTrue(finalized.is_set())
            self.assertEqual(await unrelated, 42)
            self.assertIs(loop, asyncio.get_running_loop())
            self.assertFalse(loop.is_closed())
            self.assertIsNone(get_current_run_context())

        asyncio.run(scenario())

    def test_executor_can_finish_via_caller_loop_callback(self):
        async def scenario():
            loop = asyncio.get_running_loop()
            ctx = RunContext('aws', max_workers=1).setup()
            executor = ctx.executor
            started = threading.Event()

            def worker():
                started.set()
                return asyncio.run_coroutine_threadsafe(
                    asyncio.sleep(0, result=42), loop
                ).result(timeout=2)

            future = run_function_concurrently(worker)
            for _ in range(1000):
                if started.is_set():
                    break
                await asyncio.sleep(.001)
            self.assertTrue(started.is_set())
            async with asyncio.timeout(3):
                await ctx.aclose()
            self.assertTrue(executor._shutdown)
            self.assertTrue(future.done())
            self.assertIsNone(get_current_run_context())

        asyncio.run(scenario())

    def test_collection_children_are_cancelled(self):
        async def scenario():
            ctx = RunContext('aws').setup()
            started = asyncio.Event()
            stopped = asyncio.Event()

            async def blocked(item):
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    stopped.set()

            outer = asyncio.create_task(get_and_set_concurrently([blocked], [1]))
            await asyncio.wait_for(started.wait(), timeout=2)
            self.assertTrue(ctx._children)
            outer.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await outer
            async with asyncio.timeout(2):
                await ctx.aclose()
            self.assertTrue(stopped.is_set())

        asyncio.run(scenario())
