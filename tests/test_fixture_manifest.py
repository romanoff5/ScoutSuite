import json
import os
from pathlib import Path

import pytest

from tests.fixtures import DATA, ROOT, FixtureError, fixture_inventory, load_fixture, read_manifest, validate_manifest_catalog


def test_text_aliases_load_on_windows_and_linux(tmp_path):
    (tmp_path / 'source.json').write_text('{"services": {}}')
    (tmp_path / 'alias.json').write_text('source.json\n')
    assert load_fixture(tmp_path / 'alias.json', root=tmp_path) == {'services': {}}
    if os.name == 'posix':
        native = tmp_path / 'native.json'
        native.symlink_to('source.json')
        assert load_fixture(native, root=tmp_path) == {'services': {}}


def test_alias_cycles_and_traversal_are_invalid(tmp_path):
    alias = tmp_path / 'alias.json'
    alias.write_text('alias.json')
    with pytest.raises(FixtureError, match='cycle'):
        load_fixture(alias, root=tmp_path)
    alias.write_text('../outside.json')
    with pytest.raises(FixtureError, match='Unsafe'):
        load_fixture(alias, root=tmp_path)


def test_manifest_distinguishes_valid_missing_invalid_from_tested(tmp_path):
    (tmp_path / 'input.json').write_text('{"services": {}}')
    (tmp_path / 'expected.json').write_text('[]')
    case = {'provider': 'aws', 'rule': 'synthetic.json', 'id': 'case', 'kind': 'legacy',
            'input': 'input.json', 'expected': 'expected.json'}
    manifest = {'cases': [case]}
    row = fixture_inventory(manifest, data=tmp_path)[0]
    assert row['fixture_status'] == 'valid'
    assert row['test_status'] == 'not_run'
    (tmp_path / 'expected.json').unlink()
    assert fixture_inventory(manifest, data=tmp_path)[0]['fixture_status'] == 'missing'
    (tmp_path / 'expected.json').write_text('not JSON')
    assert fixture_inventory(manifest, data=tmp_path)[0]['fixture_status'] == 'invalid'


def test_catalog_drift_and_ambiguous_coverage_fail(tmp_path):
    path = tmp_path / 'ScoutSuite/providers/aws/rules/rulesets'
    path.mkdir(parents=True)
    (path / 'default.json').write_text('{"rules": {"new-rule.json": []}}')
    with pytest.raises(FixtureError, match='catalog drift'):
        validate_manifest_catalog({'cases': [], 'untested': {'aws': [], 'azure': [], 'gcp': []}}, root=tmp_path)
    with pytest.raises(FixtureError, match='Ambiguous'):
        validate_manifest_catalog({'cases': [], 'untested': {'aws': ['new-rule.json', 'new-rule.json'],
                                                          'azure': [], 'gcp': []}}, root=tmp_path)


def test_manifest_cannot_omit_a_provider():
    with pytest.raises(FixtureError, match='AWS, Azure and GCP'):
        validate_manifest_catalog({'cases': [], 'untested': {'aws': []}})


def test_duplicate_declared_cases_fail(tmp_path):
    case = {'provider': 'aws', 'rule': 'synthetic.json', 'id': 'case'}
    manifest = tmp_path / 'manifest.json'
    manifest.write_text(json.dumps({'version': 1, 'cases': [case, case]}))
    with pytest.raises(FixtureError, match='Duplicate'):
        read_manifest(manifest)


def test_all_historical_pairs_remain_declared():
    catalog = json.loads((ROOT / 'ScoutSuite/providers/aws/rules/rulesets/default.json').read_text())['rules']
    paired = {rule for rule in catalog if (DATA / 'rule-configs' / rule).exists()
              and (DATA / 'rule-results' / rule).exists()}
    declared = {case['rule'] for case in read_manifest()['cases'] if case['kind'] == 'legacy'}
    assert len(paired) == 19, 'Historical fixture changes require a reviewed coverage update'
    assert declared == paired
