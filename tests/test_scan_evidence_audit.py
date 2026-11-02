"""Read-only postscan consistency gate using synthetic, non-customer reports."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('audit_scan_evidence',
                                             ROOT / 'tools/audit_scan_evidence.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def report(insecure=1, flagged=0, unknown=0):
    return {
        'report_schema_version': 1,
        'account_id': 'synthetic-do-not-print',
        'services': {'ecr': {'findings': {'ecr-registry-not-enhanced-scanning': {
            'flagged_items': flagged,
            'checked_items': 1,
            'assessment_status': 'incomplete',
            'items': ['synthetic-resource-id-do-not-print'],
            'evaluation_summary': {
                'assessment_status': 'incomplete' if unknown else 'evaluated',
                'counts': {'insecure': insecure, 'secure': 0,
                           'unknown': unknown, 'not_applicable': 0},
                'unknown_resources': ['secret-resource-id-do-not-print'],
                'compliance_verified': False,
            },
        }}}},
        'collection_status': {'complete': False, 'status': 'partial',
                              'issues': [{'scope': 'ecr', 'reason_code': 'synthetic'}]},
    }


def test_detects_real_rc1_basic_scanning_evidence_mismatch_without_printing_resources(tmp_path, capsys):
    path = tmp_path / 'RESULTS.js'
    path.write_text('scoutsuite_results =\n' + json.dumps(report()) + ';\n', encoding='utf-8')
    assert module.main([str(path), '--fail-on-discrepancy']) == 3
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result['discrepancy_count'] == 1
    assert result['discrepancies'][0]['type'] == 'evidence_finding_count_mismatch'
    assert result['discrepancies'][0]['insecure_count'] == 1
    assert result['discrepancies'][0]['flagged_count'] == 0
    assert result['collection_incomplete'] is True
    assert result['collection_issue_count'] == 1
    for forbidden in ('synthetic-do-not-print', 'secret-resource-id',
                      'synthetic-resource-id-do-not-print'):
        assert forbidden not in output


def test_fixed_rule_has_no_discrepancy_and_unknown_stays_incomplete(tmp_path, capsys):
    path = tmp_path / 'RESULTS.json'
    path.write_text(json.dumps(report(flagged=1, unknown=1)), encoding='utf-8')
    assert module.main([str(path), '--fail-on-discrepancy']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['incomplete_rules'] == 1
    assert result['discrepancy_count'] == 0


def test_invalid_report_fails_without_leaking_file_or_raw_json(tmp_path, capsys):
    path = tmp_path / 'private-report.json'
    path.write_text('{ "account_id": "sensitive-client-value", bad json', encoding='utf-8')
    assert module.main([str(path)]) == 2
    output = capsys.readouterr().out
    assert 'private-report' not in output
    assert 'sensitive-client-value' not in output


def test_non_evidence_rules_are_not_labeled_mismatches():
    source = report()
    source['services']['ecr']['findings']['legacy-without-evidence'] = {
        'flagged_items': 1, 'items': ['synthetic']}
    summary = module.analyze(source)
    assert summary['rules'] == 2
    assert summary['evaluated_policies'] == 1
    assert summary['discrepancy_count'] == 1


def test_hostile_report_identifiers_and_status_values_are_never_echoed(tmp_path, capsys):
    source = report()
    abnormal = source['services'].pop('ecr')
    source['services']['arn:aws:private:secret-identifier'] = abnormal
    row = abnormal['findings'].pop('ecr-registry-not-enhanced-scanning')
    abnormal['findings']['client-secret:irrelevant'] = row
    row['evaluation_summary']['assessment_status'] = 'secret-status-must-not-echo'
    source['report_schema_version'] = 'secret-schema-must-not-echo'
    path = tmp_path / 'private-report.js'
    path.write_text('scoutsuite_results = ' + json.dumps(source), encoding='utf-8')
    assert module.main([str(path), '--fail-on-discrepancy']) == 3
    output = capsys.readouterr().out
    for secret in ('secret-identifier', 'client-secret', 'secret-status', 'secret-schema'):
        assert secret not in output
    result = json.loads(output)
    assert result['discrepancies'][0]['rule'] == 'invalid_identifier'
    assert result['discrepancies'][0]['service'] == 'invalid_identifier'
    assert result['evaluation_status_counts']['unrecognized'] == 1
    assert result['report_schema_version'] is None
