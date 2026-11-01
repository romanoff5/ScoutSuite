"""CLI parsing smoke tests never spawn a scanner or discover credentials."""

import io
import unittest
from unittest.mock import AsyncMock, patch

from ScoutSuite import __main__ as main


class TestScoutSuiteClass(unittest.TestCase):
    def test_scout_suite_help(self):
        with patch('sys.argv', ['scout', '--help']), patch('sys.stdout', new_callable=io.StringIO) as output:
            with patch.object(main, 'get_authentication_strategy') as auth:
                with self.assertRaises(SystemExit) as error:
                    main.run_from_cli()
        self.assertEqual(error.exception.code, 0)
        self.assertIn('usage:', output.getvalue())
        for provider in ('aws', 'azure', 'gcp'):
            self.assertIn(provider, output.getvalue())
        auth.assert_not_called()

    def test_scout_suite_default_run(self):
        # The CLI awaits _run_sync, not the legacy public run() wrapper.
        # Mock the actual async boundary to verify parsing without credential discovery.
        with patch('sys.argv', ['scout', 'aws']), \
             patch.object(main, '_run_sync', new_callable=AsyncMock) as run, \
             patch.object(main, 'get_authentication_strategy') as authenticate:
            run.return_value = 0
            self.assertEqual(main.run_from_cli(), 0)
        run.assert_awaited_once()
        authenticate.assert_not_called()
        self.assertEqual(run.await_args.kwargs['provider'], 'aws')
        self.assertIsNone(run.await_args.kwargs['report_dir'])  # Output layer supplies its default directory.
        self.assertFalse(run.await_args.kwargs['programmatic_execution'])
        self.assertFalse(run.await_args.kwargs['fetch_local'])
