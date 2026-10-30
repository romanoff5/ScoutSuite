"""A wrong CLI outcome must fail each formerly unawaited test body."""

import unittest
from unittest.mock import patch

import pytest

from tests import test_main as cli_tests


@pytest.mark.parametrize('name', ['test_empty', 'test_aws_provider', 'test_gcp_provider',
                                 'test_azure_provider', 'test_unauthenticated', 'test_keyboardinterrupted'])
def test_cli_assertions_reject_wrong_result(name):
    case = cli_tests.TestMainClass(name)
    result = unittest.TestResult()
    with patch.object(cli_tests.main, 'run_from_cli', return_value=999):
        case.run(result)
    assert result.testsRun == 1
    assert len(result.failures) == 1, 'Wrong CLI outcome escaped the test assertion'
    assert not result.errors, 'Test failed in setup instead of exercising its assertion'
