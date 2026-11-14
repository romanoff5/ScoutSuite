"""P3-C: fail-closed, customer-free quality gate over real JSON rule contracts."""
import copy
import json
from pathlib import Path

from tools import p3c_quality as quality

DATA = Path(__file__).resolve().parent / 'data'


def loaded(name):
    return json.loads((DATA / name).read_text(encoding='utf-8'))


def active_rules():
    rules = json.loads((quality.RULE_ROOT / 'rulesets/default.json').read_text())['rules']
    return {name for name, settings in rules.items() if settings[0]['enabled']}


def test_p3c_report_census_and_quality_thresholds():
    result = quality.analyze()
    assert result['pass'] is True, result['errors']
    census = result['report_cases']
    assert census['total'] == 66 and census['in_scope'] == 63
    assert census['coverage'] == {
        'direct': 33, 'partial': 22, 'gap': 8, 'out_of_scope': 3}
    assert census['by_group']['A'] == {
        'direct': 15, 'partial': 17, 'gap': 7}
    assert census['by_group']['B'] == {
        'direct': 18, 'partial': 5, 'gap': 1, 'out_of_scope': 3}
    metrics = result['synthetic_detection']
    assert metrics['tp'] == 18 and metrics['tn'] == 17
    assert metrics['unknown_cases'] == 18
    assert metrics['unverified_negative'] == 1
    assert all(metrics.get(x, 0) == 0 for x in (
        'fp', 'fn', 'false_pass_on_unknown', 'unknown_flagged'))
    assert result['external_crosswalk']['entries'] == 10
    assert result['external_crosswalk']['parity_claimed'] is False
    assert result['report_cases']['field_detection_verified'] is False


def test_coverage_contract_rejects_missing_case_and_false_direct_rule():
    data = loaded('p3c_assessment_coverage.json')
    missing = copy.deepcopy(data)
    missing['cases'].pop()
    errors, _ = quality.validate_coverage(missing, active_rules())
    assert any('39+27' in error for error in errors)

    mapped = copy.deepcopy(data)
    mapped['cases'][0]['rule_ids'] = ['never-published-rule.json']
    errors, _ = quality.validate_coverage(mapped, active_rules())
    assert any('unknown or disabled' in error for error in errors)


def test_coverage_contract_rejects_gap_mapping_and_sensitive_report_identifier():
    data = loaded('p3c_assessment_coverage.json')
    unexpected = copy.deepcopy(data)
    row = next(x for x in unexpected['cases'] if x['id'] == 'A-14')
    assert row['coverage'] == 'gap'
    row['rule_ids'] = ['elbv2-no-access-logs.json']
    errors, _ = quality.validate_coverage(unexpected, active_rules())
    assert any('Gap / outside-scope' in error for error in errors)

    leaked = copy.deepcopy(data)
    leaked['cases'][0]['limitation'] = 'Observed account 123456789012 was assessed.'
    errors, _ = quality.validate_coverage(leaked, active_rules())
    assert any('Customer identifier' in error for error in errors)


def test_crosswalk_semantics_are_non_equivalent_and_reproducibly_pinned():
    data = loaded('p3c_external_crosswalk.json')
    errors, providers = quality.validate_crosswalk(data, active_rules())
    assert errors == []
    assert providers == {'aws_security_hub': 6, 'prowler': 4}
    leaked = copy.deepcopy(data)
    leaked['crosswalk'][0]['relation'] = 'equivalent'
    errors, _ = quality.validate_crosswalk(leaked, active_rules())
    assert any('NOT claim' in error for error in errors)


def test_false_positive_gate_detects_negative_fixture_corruption():
    data = loaded('p3c_detection_triads.json')
    corrupted = copy.deepcopy(data)
    corrupted['triads'][0]['states']['negative'] = 'exposed'
    errors, metrics = quality.validate_triads(
        corrupted, {r['id']: r for r in loaded('p3c_assessment_coverage.json')['cases']},
        active_rules())
    assert metrics['fp'] >= 1
    assert errors


def test_unknown_is_never_a_verified_pass_even_when_rule_does_not_fire():
    data = loaded('p3c_detection_triads.json')
    changed = copy.deepcopy(data)
    changed['triads'][0]['states']['incomplete'] = 'not_exposed'
    errors, metrics = quality.validate_triads(
        changed, {r['id']: r for r in loaded('p3c_assessment_coverage.json')['cases']},
        active_rules())
    assert metrics['false_pass_on_unknown'] >= 1
    assert errors


def test_report_format_is_explicit_about_limits(tmp_path):
    report = quality.analyze()
    output = quality.markdown(report)
    assert 'Not a live-assessment accuracy claim' in output
    assert 'Synthetic TN / FP' in output
    assert '## Gap control IDs' in output
    assert 'A-14: alb_unhealthy_targets_healthcheck_mismatch' in output
    j = tmp_path / 'p3c.json'
    m = tmp_path / 'p3c.md'
    j.write_text(json.dumps(report), encoding='utf-8')
    m.write_text(output, encoding='utf-8')
    assert json.loads(j.read_text())['pass'] is True
    assert m.read_text().startswith('# P3-C offline quality gate')
    assert not quality.FORBIDDEN.search(output)


def test_synthetic_fixture_contains_no_customer_raw_evidence():
    for name in ('p3c_assessment_coverage.json',
                 'p3c_external_crosswalk.json', 'p3c_detection_triads.json'):
        raw = (DATA / name).read_text(encoding='utf-8')
        assert not quality.FORBIDDEN.search(raw)
    # Every synthetic triad points to a concrete rule and at most one anonymized case.
    fixtures = loaded('p3c_detection_triads.json')['triads']
    assert len({x['id'] for x in fixtures}) == len(fixtures) == 18
