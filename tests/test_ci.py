"""CI evidence must reject missing execution and incomplete fixtures."""

import copy
from threading import Barrier
import xml.etree.ElementTree as ET

import pytest

from tools.ci import CLI_CASES, Pipeline, clean_environment, verify_execution


def execution():
    suite = ET.Element('testsuite')
    for name in sorted(CLI_CASES):
        ET.SubElement(suite, 'testcase', classname='tests.test_main.TestMainClass', name=name)
    for module in ('test_offline', 'test_cli_assertions', 'test_characterization'):
        ET.SubElement(suite, 'testcase', classname='tests.' + module, name='synthetic')
    manifest = {'exitstatus': 0, 'cases': [{'fixture_status': 'valid', 'test_status': 'verified'}],
                'warnings': {'synthetic:DeprecationWarning': 2}, 'untested': {'aws': ['untested']}}
    return suite, manifest


def test_ci_accepts_executed_bodies_and_retains_warning_debt():
    suite, manifest = execution()
    result = verify_execution(ET.tostring(suite), manifest)
    assert result['cli_bodies'] == 6
    assert result['junit_cases'] == 9
    assert result['warnings'] == manifest['warnings']
    assert result['untested_rules'] == {'aws': 1}


@pytest.mark.parametrize('module', ['TestMainClass', 'test_offline', 'test_cli_assertions', 'test_characterization'])
def test_ci_rejects_omitted_regression_bodies(module):
    suite, manifest = execution()
    suite.remove(next(case for case in suite if module in case.attrib['classname']))
    with pytest.raises(AssertionError, match='did not all execute|Missing M01 gate'):
        verify_execution(ET.tostring(suite), manifest)


@pytest.mark.parametrize('outcome', ['skipped', 'failure', 'error'])
def test_ci_rejects_nonpassing_results(outcome):
    suite, manifest = execution()
    ET.SubElement(suite[0], outcome)
    with pytest.raises(AssertionError, match='Non-passing'):
        verify_execution(ET.tostring(suite), manifest)


@pytest.mark.parametrize('field,value', [('test_status', 'not_run'), ('fixture_status', 'missing'),
                                       ('fixture_status', 'invalid')])
def test_ci_rejects_incomplete_fixture_evidence(field, value):
    suite, manifest = execution()
    changed = copy.deepcopy(manifest)
    changed['cases'][0][field] = value
    with pytest.raises(AssertionError, match='Incomplete fixture'):
        verify_execution(ET.tostring(suite), changed)


def test_ci_child_environment_clears_synthetic_credentials(monkeypatch, tmp_path):
    for name in ('AWS_ACCESS_KEY_ID', 'AZURE_CLIENT_SECRET', 'GOOGLE_APPLICATION_CREDENTIALS',
                 'GITHUB_TOKEN', 'GH_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'PYTHONPATH'):
        monkeypatch.setenv(name, 'synthetic-must-not-inherit')
    env = clean_environment(tmp_path, offline=True)
    assert 'synthetic-must-not-inherit' not in env.values()
    assert env['HOME'] == str(tmp_path / 'home')
    assert env['PIP_NO_INDEX'] == '1'
    assert env['AWS_EC2_METADATA_DISABLED'] == 'true'


def test_ci_parallel_independent_gates_execute_concurrently():
    pipeline = object.__new__(Pipeline)
    barrier = Barrier(3, timeout=5)
    results = []

    def job(name):
        barrier.wait()
        results.append(name)

    pipeline.parallel([(name, lambda value=name: job(value))
                       for name in ('test', 'wheel', 'sdist')])
    assert set(results) == {'test', 'wheel', 'sdist'}


def test_ci_parallel_gate_waits_for_all_and_propagates_failure():
    pipeline = object.__new__(Pipeline)
    completed = []

    def fail():
        raise ValueError('synthetic build failure')

    def complete():
        completed.append('other independent check completed')

    with pytest.raises(RuntimeError, match='Parallel CI gates failed: broken'):
        pipeline.parallel([('broken', fail), ('other', complete)], max_workers=2)
    assert completed == ['other independent check completed']
