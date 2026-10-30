"""Default offline policy; installed before any test module imports ScoutSuite."""

import json
from pathlib import Path
import sys

import pytest

from tests.offline import OfflineGuard, validate_test_item


offline_guard = OfflineGuard().install()
verified_cases = {}


def pytest_addoption(parser):
    parser.addoption('--offline-manifest-report', help='Write fixture validity and actual verification results as JSON')


def pytest_configure(config):
    if config.option.basetemp is None:
        config.option.basetemp = str(offline_guard.home / 'pytest-temp')


def pytest_collection_modifyitems(items):
    from tests.fixtures import read_manifest, validate_manifest_catalog

    try:
        validate_manifest_catalog(read_manifest())
    except ValueError as error:
        raise pytest.UsageError(str(error)) from error
    for item in items:
        try:
            validate_test_item(item)
        except ValueError as error:
            raise pytest.UsageError(item.nodeid + ': ' + str(error)) from error
    try:
        offline_guard.assert_no_violations()
    except AssertionError as error:
        raise pytest.UsageError(str(error)) from error


@pytest.fixture
def offline():
    return offline_guard


@pytest.fixture(autouse=True)
def check_offline_boundary():
    offline_guard.assert_no_violations()
    if 'ScoutSuite' in sys.modules:
        sys.modules['ScoutSuite'].ERRORS_LIST.clear()
    yield
    offline_guard.assert_no_violations()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    result = yield
    report = result.get_result()
    if report.skipped:
        report.outcome = 'failed'
        report.longrepr = 'Offline tests must execute; runtime skip/xfail is not accepted: ' + item.nodeid
    for name, key in report.user_properties:
        if name == 'rule_case':
            if report.failed:
                verified_cases[key] = 'failed'
            elif report.when == 'call' and report.passed:
                verified_cases[key] = 'verified'


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    from tests.fixtures import fixture_inventory, read_manifest

    manifest = read_manifest()
    rows = fixture_inventory(manifest)
    for row in rows:
        row['test_status'] = verified_cases.get(row['key'], 'not_run')
    terminalreporter.section('Offline rule fixture coverage (not full service coverage)')
    for provider, untested in manifest['untested'].items():
        cases = [row for row in rows if row['provider'] == provider]
        rules = {row['rule'] for row in cases}
        verified = sum(row['test_status'] == 'verified' for row in cases)
        terminalreporter.write_line(
            f'{provider}: {len(rules)} declared rules, {verified}/{len(cases)} verified cases, '
            f'{len(untested)} untested rules')
    report = config.getoption('--offline-manifest-report')
    if report:
        Path(report).write_text(json.dumps({'exitstatus': int(exitstatus), 'cases': rows,
                                          'untested': manifest['untested']}, indent=2) + '\n', encoding='utf-8')
