"""Run each declared historical AWS regression instead of silently skipping the rest."""

import copy
import json
from types import SimpleNamespace

import pytest

from ScoutSuite import ERRORS_LIST
from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.ruleset import Ruleset
from tests.fixtures import DATA, case_key, load_fixture, read_manifest, validate_manifest_catalog


MANIFEST = read_manifest()
CASES = [case for case in MANIFEST['cases'] if case['kind'] == 'legacy']


def test_fixture_manifest_is_complete():
    validate_manifest_catalog(MANIFEST)


@pytest.mark.parametrize('case', CASES, ids=lambda case: case['rule'])
def test_declared_aws_rule(case, tmp_path, record_property):
    record_property('rule_case', case_key(case))
    config = load_fixture(DATA / case['input'])
    expected = load_fixture(DATA / case['expected'])
    default = json.loads((DATA.parents[1] / 'ScoutSuite/providers/aws/rules/rulesets/default.json').read_text())
    rule = copy.deepcopy(default['rules'][case['rule']][0])
    rule['enabled'] = True
    rules_path = tmp_path / 'rules.json'
    rules_path.write_text(json.dumps({'about': 'offline regression', 'rules': {case['rule']: [rule]}}))
    ruleset = Ruleset(cloud_provider='aws', filename=str(rules_path))
    assert len(ruleset.rules[case['rule']]) == 1
    provider = SimpleNamespace(**config)
    service = case['rule'].split('-')[0]
    provider.service_list = [service]
    ERRORS_LIST.clear()
    ProcessingEngine(ruleset).run(provider)
    assert not ERRORS_LIST, 'A failed rule evaluation must not count as a passing fixture'
    findings = provider.services[service]['findings']
    assert len(findings) == 1
    finding = next(iter(findings.values()))
    assert set(finding['items']) == set(expected)
    assert finding['flagged_items'] == len(expected)
    assert finding['checked_items'] > 0, 'Fixture must actually exercise the rule'
