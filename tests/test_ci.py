"""CI evidence must reject missing execution and incomplete fixtures."""

import copy
import json
from pathlib import Path
from threading import Barrier
import xml.etree.ElementTree as ET

import pytest

from tools.ci import (CLI_CASES, LEGACY_VENDOR_WARNING_BUDGET, Pipeline,
                      clean_environment, verify_execution, verify_warning_debt)


def execution():
    suite = ET.Element('testsuite')
    for name in sorted(CLI_CASES):
        ET.SubElement(suite, 'testcase', classname='tests.test_main.TestMainClass', name=name)
    for module in ('test_offline', 'test_cli_assertions', 'test_characterization'):
        ET.SubElement(suite, 'testcase', classname='tests.' + module, name='synthetic')
    manifest = {'exitstatus': 0, 'cases': [{'fixture_status': 'valid', 'test_status': 'verified'}],
                'warnings': {}, 'untested': {'aws': ['untested']}}
    return suite, manifest


def test_ci_accepts_executed_bodies_without_warnings():
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



def test_zero_warning_gate_rejects_historical_vendor_warning_budget():
    assert LEGACY_VENDOR_WARNING_BUDGET == {}
    result = verify_warning_debt({})
    assert result == {'observed': 0, 'vendor_warning_budget': 0,
                      'first_party_warnings': 0}
    with pytest.raises(AssertionError, match='Zero-warning gate violated'):
        verify_warning_debt({'azure/mgmt/sql/models/_models_py3.py:DeprecationWarning': 2})


@pytest.mark.parametrize('warning', [
    'ScoutSuite/ScoutSuite/ScoutSuite/providers/utils.py:DeprecationWarning',
    'tests/test_new_feature.py:RuntimeWarning',
    'google/cloud/kms_v1/new_generator.py:DeprecationWarning',
])
def test_warning_debt_gate_rejects_new_or_first_party_warnings(warning):
    with pytest.raises(AssertionError, match='Zero-warning gate violated'):
        verify_warning_debt({warning: 1})


@pytest.mark.parametrize('value', [3, -1, True, 'many'])
def test_warning_debt_gate_rejects_over_budget_or_invalid_counts(value):
    with pytest.raises(AssertionError, match='Zero-warning gate violated'):
        verify_warning_debt({'azure/mgmt/sql/models/_models_py3.py:DeprecationWarning': value})


def test_ci_rejects_new_warning_even_if_fixture_and_test_results_are_green():
    suite, manifest = execution()
    manifest['warnings'] = {'ScoutSuite/providers/utils.py:DeprecationWarning': 1}
    with pytest.raises(AssertionError, match='Zero-warning gate violated'):
        verify_execution(ET.tostring(suite), manifest)


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


def test_wheelhouse_manifest_detects_corruption_and_incomplete_restore(tmp_path):
    pipeline = object.__new__(Pipeline)
    pipeline.root = tmp_path
    wheelhouse = tmp_path / 'wheelhouse'
    wheelhouse.mkdir()
    wheel = wheelhouse / 'synthetic-1.0-py3-none-any.whl'
    wheel.write_bytes(b'synthetic wheel bytes')
    pipeline.record_wheelhouse()
    assert pipeline.wheelhouse_valid()
    wheel.write_bytes(b'corrupted')
    assert not pipeline.wheelhouse_valid()
    wheel.write_bytes(b'synthetic wheel bytes')
    assert pipeline.wheelhouse_valid()
    wheel.unlink()
    assert not pipeline.wheelhouse_valid()
    wheel.write_bytes(b'synthetic wheel bytes')
    manifest = tmp_path / 'wheelhouse-manifest.json'
    data = json.loads(manifest.read_text(encoding='utf-8'))
    data['inputs'] = 'outdated requirements fingerprint'
    manifest.write_text(json.dumps(data), encoding='utf-8')
    assert not pipeline.wheelhouse_valid()


def test_pip_disables_eager_bytecode_compilation_only_for_installs(tmp_path):
    pipeline = object.__new__(Pipeline)
    pipeline.root = tmp_path
    commands = []
    pipeline.run = lambda command: commands.append(command)
    pipeline.pip('test', 'install', '--no-index', 'synthetic==1.0')
    assert commands[-1][4:6] == ['install', '--no-compile']
    pipeline.pip('build', 'wheel', '--no-index', 'synthetic==1.0')
    assert commands[-1][4] == 'wheel'
    assert '--no-compile' not in commands[-1]


def test_ci_independent_gates_preserve_cross_platform_matrix():
    assert set(Pipeline.independent_gates('Linux', (3, 11))) == {
        'dependencies', 'lint', 'tests', 'p3c', 'sqlite_http',
        'xss_browser', 'report_e2e', 'packaging',
    }
    assert set(Pipeline.independent_gates('Linux', (3, 14))) == set(
        Pipeline.independent_gates('Linux', (3, 11)))
    assert set(Pipeline.independent_gates('Windows', (3, 14))) == {
        'dependencies', 'lint', 'tests', 'p3c', 'xss_browser',
        'report_e2e', 'packaging',
    }
    # Historical RC8 exception stays specific to Windows Python 3.11 E2E.
    assert set(Pipeline.independent_gates('Windows', (3, 11))) == {
        'windows_install', 'dependencies', 'lint', 'tests', 'p3c', 'xss_browser', 'packaging',
    }


def test_ci_parallel_verify_waits_for_all_and_fails_closed(monkeypatch, tmp_path):
    pipeline = Pipeline(tmp_path, 'verify')
    completed = []

    def fake_independent_gates(system, python_version):
        return ('lint', 'tests', 'p3c')

    def fake_gate(self, phase):
        completed.append(phase)
        if phase == 'tests':
            raise ValueError('synthetic isolated gate failed')

    monkeypatch.setattr(Pipeline, 'independent_gates', staticmethod(fake_independent_gates))
    monkeypatch.setattr(Pipeline, '_verify_one', fake_gate)
    with pytest.raises(RuntimeError, match='Parallel CI gates failed: tests'):
        pipeline.verify()
    assert set(completed) == {'lint', 'tests', 'p3c'}


def test_ci_parallel_verify_writes_individual_status_on_failure(monkeypatch, tmp_path):
    pipeline = Pipeline(tmp_path, 'verify')

    def broken(self):
        raise RuntimeError('synthetic lint failure')

    monkeypatch.setattr(Pipeline, 'lint', broken)
    with pytest.raises(RuntimeError, match='synthetic lint failure'):
        pipeline._verify_one('lint')
    result = json.loads((tmp_path / 'phase-lint.json').read_text())
    assert result['status'] == 'FAILED'
    assert result['phase'] == 'lint'
    assert result['seconds'] >= 0
    with pytest.raises(ValueError, match='Unsafe or unsupported'):
        pipeline._verify_one('acquire')


def test_ci_parallel_verify_preserves_successful_gate_status(monkeypatch, tmp_path):
    pipeline = Pipeline(tmp_path, 'verify')
    monkeypatch.setattr(Pipeline, 'p3c', lambda self: None)
    pipeline._verify_one('p3c')
    result = json.loads((tmp_path / 'phase-p3c.json').read_text())
    assert result['status'] == 'PASSED'
    assert result['phase'] == 'p3c'


def test_ci_windows_real_installer_remains_full_and_non_networked():
    script = (Path(__file__).resolve().parents[1] /
              'tools/ci_verify_install.ps1').read_text()
    assert all(value in script for value in (
        'install-fork.ps1', '-WheelhousePath', '-CommitSha',
        '-ExpectedSha256', 'fork-install.json',
        'invoke-selected-scout.ps1', 'aws --help'))
    assert 'Get-FileHash' in script
    assert '-FromOrigin' not in script
    assert '-FromRelease' not in script


def test_ci_windows_installer_not_executed_on_other_runtimes(monkeypatch, tmp_path):
    pipeline = Pipeline(tmp_path, 'windows_install')
    monkeypatch.setattr('tools.ci.platform.system', lambda: 'Linux')
    with pytest.raises(RuntimeError, match='Windows Python 3.11 only'):
        pipeline.windows_install()
