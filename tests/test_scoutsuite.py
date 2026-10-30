"""CLI parsing smoke tests never spawn a scanner or discover credentials."""

import io
import unittest
from unittest.mock import patch

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
        # Check actual CLI defaults without invoking the production run/credential chain.
        with patch('sys.argv', ['scout', 'aws']), patch.object(main, 'run', return_value=0) as run:
            self.assertEqual(main.run_from_cli(), 0)
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs['provider'], 'aws')
        self.assertIsNone(run.call_args.kwargs['report_dir'])  # Output layer supplies its default directory.
        self.assertFalse(run.call_args.kwargs['programmatic_execution'])
        self.assertFalse(run.call_args.kwargs['fetch_local'])
