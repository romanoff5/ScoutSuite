"""Offline M04-D strict completeness and finite botocore client policy."""
from unittest import TestCase
from unittest.mock import Mock, patch

from ScoutSuite import __main__ as main
from ScoutSuite.core.cli_parser import ScoutSuiteArgumentParser
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils


class TestM04StrictCompleteness(TestCase):
    def test_cli_flag_is_opt_in(self):
        with patch('sys.argv', ['scout', 'aws', '--no-browser']):
            args = ScoutSuiteArgumentParser().parse_args()
        self.assertFalse(args.strict_completeness)
        with patch('sys.argv', ['scout', 'aws', '--no-browser', '--strict-completeness']):
            args = ScoutSuiteArgumentParser().parse_args()
        self.assertTrue(args.strict_completeness)
        self.assertTrue(main._extract_run_args(vars(args))['strict_completeness'])

    def test_zero_checks_are_not_evidence_of_compliance(self):
        context = RunContext('aws')
        status = context.collection_summary(checked_items=0)
        self.assertTrue(status['complete'])
        self.assertFalse(status['evidence_evaluated'])
        self.assertEqual(status['checked_items'], 0)

    def test_positive_checked_items_remain_distinct_from_compliance(self):
        context = RunContext('aws')
        status = context.collection_summary(checked_items=2)
        self.assertTrue(status['evidence_evaluated'])
        self.assertFalse(status['compliance_verified'])


class TestM04AWSClientTimeoutPolicy(TestCase):
    def test_default_timeouts_and_finite_retries(self):
        session = Mock()
        client = AWSFacadeUtils.get_client('s3', session, 'eu-central-1')
        self.assertIs(client, session.client.return_value)
        kwargs = session.client.call_args.kwargs
        self.assertEqual(kwargs['region_name'], 'eu-central-1')
        config = kwargs['config']
        self.assertEqual(config.connect_timeout, 5)
        self.assertEqual(config.read_timeout, 30)
        self.assertEqual(config.retries['total_max_attempts'], 3)

    def test_client_factory_failure_does_not_reuse_a_stale_client(self):
        session = Mock()
        session.client.side_effect = RuntimeError('synthetic constructor failure')
        self.assertIsNone(AWSFacadeUtils.get_client('s3', session, 'us-east-1'))
        self.assertEqual(session.client.call_count, 1)
