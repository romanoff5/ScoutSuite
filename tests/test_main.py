"""Exercise the synchronous CLI and its real async lifecycle with mocked boundaries."""

import asyncio
import io
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from ScoutSuite import __main__ as main


class TestMainClass(unittest.TestCase):
    def setUp(self):
        # The current scanner owns/closes this loop. Changing that production contract is M03.
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.addCleanup(self.close_loop)
        self.provider = MagicMock(provider_code='aws', environment='default', account_id='000000000000')
        self.provider.get_report_name.return_value = 'aws'
        self.provider.fetch = AsyncMock()
        self.auth = MagicMock()
        self.report = MagicMock()
        self.report.save.return_value = 'synthetic-report.html'
        self.mocks = {}
        for name, value in [('get_authentication_strategy', self.auth), ('get_provider', self.provider),
                            ('ScoutReport', self.report), ('Ruleset', MagicMock()),
                            ('ProcessingEngine', MagicMock())]:
            self.mocks[name] = self.enterContext(patch.object(main, name, return_value=value))
        self.browser = self.enterContext(patch.object(main.webbrowser, 'open'))

    def close_loop(self):
        if not self.loop.is_closed():
            self.loop.close()
        asyncio.set_event_loop(None)

    def call_cli(self, args):
        with patch('sys.argv', ['scout'] + args):
            return main.run_from_cli()

    def assert_successful_provider(self, provider, auth_args):
        self.provider.provider_code = provider
        self.provider.get_report_name.return_value = provider
        code = self.call_cli([provider] + auth_args + ['--no-browser'])
        self.assertEqual(code, 0)
        self.mocks['get_authentication_strategy'].assert_called_once_with(provider)
        self.auth.authenticate.assert_called_once()
        regions = [] if provider == 'aws' else None
        self.provider.fetch.assert_awaited_once_with(regions=regions, excluded_regions=regions)
        ip_ranges, name_key = ([], 'name') if provider == 'aws' else (None, None)
        self.provider.preprocessing.assert_called_once_with(ip_ranges, name_key)
        self.mocks['ScoutReport'].assert_called_once_with(
            provider, provider, None, False, result_format='json')
        self.assertEqual(self.mocks['ProcessingEngine'].return_value.run.call_count, 2)
        self.provider.postprocessing.assert_called_once()
        self.report.save.assert_called_once()
        self.browser.assert_not_called()

    def test_empty(self):
        with patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit) as error:
            self.call_cli([])
        self.assertEqual(error.exception.code, 2)
        self.auth.authenticate.assert_not_called()
        self.provider.fetch.assert_not_awaited()

    def test_aws_provider(self):
        self.assert_successful_provider('aws', [])

    def test_gcp_provider(self):
        self.assert_successful_provider('gcp', ['--service-account', 'synthetic-credentials.json'])
        self.assertEqual(self.auth.authenticate.call_args.kwargs['service_account'], 'synthetic-credentials.json')

    def test_azure_provider(self):
        self.assert_successful_provider('azure', ['--cli'])
        self.assertTrue(self.auth.authenticate.call_args.kwargs['cli'])

    def test_unauthenticated(self):
        self.auth.authenticate.return_value = None
        self.assertEqual(self.call_cli(['aws', '--no-browser']), 101)
        self.auth.authenticate.assert_called_once()
        self.mocks['get_provider'].assert_not_called()
        self.provider.fetch.assert_not_awaited()
        self.report.save.assert_not_called()

    def test_keyboardinterrupted(self):
        self.provider.fetch.side_effect = KeyboardInterrupt
        self.assertEqual(self.call_cli(['aws', '--no-browser']), 130)
        self.provider.fetch.assert_awaited_once()
        self.provider.preprocessing.assert_not_called()
        self.report.save.assert_not_called()
        self.browser.assert_not_called()
