"""Offline integrity check for ScoutSuite JSON or JS RESULTS.

Read-only: no SDK, credentials, network, subprocess, report modification or
resource identity output. Only rule identifiers and aggregate counts leave
this process. A mismatch is a review signal, never a fabricated vulnerability.
"""
import argparse
import json
from pathlib import Path
import re
import sys


MAX_RESULT_BYTES = 128 * 1024 * 1024
RESULTS_PREFIX = re.compile(r'^\s*scoutsuite_results\s*=\s*', flags=re.ASCII)


RULE_IDENTIFIER = re.compile(r'^[a-z][a-z0-9_-]{0,127}
    path = Path(path)
    if path.stat().st_size > MAX_RESULT_BYTES:
        raise ValueError('Report exceeds the bounded offline inspection limit')
    body = path.read_text(encoding='utf-8-sig')
    body = RESULTS_PREFIX.sub('', body, count=1).strip()
    if body.endswith(';'):
        body = body[:-1].rstrip()
    data = json.loads(body)
    if not isinstance(data, dict) or not isinstance(data.get('services'), dict):
        raise ValueError('Not a ScoutSuite RESULTS document')
    return data


def analyze(data):
    """Return no account IDs, resource identifiers, source paths or raw evidence."""
    issues = []
    inspected = incomplete = rules = 0
    by_status = {}
    for service, entry in sorted(data['services'].items(), key=lambda item: str(item[0])):
        safe_service = safe_rule_name(service)
        if not isinstance(entry, dict):
            continue
        findings = entry.get('findings')
        if not isinstance(findings, dict):
            continue
        for name, finding in sorted(findings.items(), key=lambda item: str(item[0])):
            safe_name = safe_rule_name(name)
            if not isinstance(finding, dict):
                continue
            rules += 1
            if finding.get('assessment_status') == 'incomplete':
                incomplete += 1
            summary = finding.get('evaluation_summary')
            if not isinstance(summary, dict):
                continue
            inspected += 1
            counts = summary.get('counts')
            if not isinstance(counts, dict):
                continue
            insecure = counts.get('insecure')
            flagged = finding.get('flagged_items')
            if (type(insecure) is not int or insecure < 0 or
                    type(flagged) is not int or flagged < 0):
                issues.append({'service': safe_service, 'rule': safe_name, 'type': 'invalid_counts'})
            elif flagged != insecure:
                # Evidence evaluator and rule conditions disagree. This is NOT
                # proof that either result is independently correct.
                issues.append({'service': safe_service, 'rule': safe_name,
                               'type': 'evidence_finding_count_mismatch',
                               'insecure_count': insecure, 'flagged_count': flagged})
            state = summary.get('assessment_status', 'unknown')
            state = state if isinstance(state, str) and state in SUMMARY_STATES else 'unrecognized'
            by_status[state] = by_status.get(state, 0) + 1
    status = data.get('collection_status') or {}
    incomplete_collection = not (isinstance(status, dict) and
                                 status.get('complete') is True)
    result = {
        'schema_version': 1,
        'report_schema_version': (data.get('report_schema_version')
                                  if type(data.get('report_schema_version')) is int
                                  else None),
        'services': len(data['services']),
        'rules': rules,
        'evaluated_policies': inspected,
        'incomplete_rules': incomplete,
        'collection_incomplete': incomplete_collection,
        'collection_issue_count': len(status.get('issues', []))
        if isinstance(status, dict) and isinstance(status.get('issues'), list) else None,
        'evaluation_status_counts': by_status,
        'discrepancy_count': len(issues),
        'discrepancies': issues,
    }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only report evidence alignment gate')
    parser.add_argument('report', type=Path, help='Local ScoutSuite RESULTS .js or .json')
    parser.add_argument('--fail-on-discrepancy', action='store_true',
                        help='Exit 3 on evidence/finding mismatch (not on incomplete cloud data)')
    args = parser.parse_args(argv)
    try:
        result = analyze(load_results(args.report))
    except (OSError, UnicodeError, ValueError) as exc:
        # Do not include path, raw report lines, parsed JSON or OS error text.
        print(json.dumps({'error': type(exc).__name__, 'status': 'invalid_report'}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 3 if args.fail_on_discrepancy and result['discrepancy_count'] else 0


if __name__ == '__main__':
    sys.exit(main())
, flags=re.ASCII)
SUMMARY_STATES = frozenset(('evaluated', 'incomplete', 'not_applicable', 'unknown'))


def safe_rule_name(value):
    return value if isinstance(value, str) and RULE_IDENTIFIER.fullmatch(value) else 'invalid_identifier'


def load_results(path):
    path = Path(path)
    if path.stat().st_size > MAX_RESULT_BYTES:
        raise ValueError('Report exceeds the bounded offline inspection limit')
    body = path.read_text(encoding='utf-8-sig')
    body = RESULTS_PREFIX.sub('', body, count=1).strip()
    if body.endswith(';'):
        body = body[:-1].rstrip()
    data = json.loads(body)
    if not isinstance(data, dict) or not isinstance(data.get('services'), dict):
        raise ValueError('Not a ScoutSuite RESULTS document')
    return data


def analyze(data):
    """Return no account IDs, resource identifiers, source paths or raw evidence."""
    issues = []
    inspected = incomplete = rules = 0
    by_status = {}
    for service, entry in sorted(data['services'].items()):
        if not isinstance(entry, dict):
            continue
        findings = entry.get('findings')
        if not isinstance(findings, dict):
            continue
        for name, finding in sorted(findings.items()):
            if not isinstance(finding, dict):
                continue
            rules += 1
            if finding.get('assessment_status') == 'incomplete':
                incomplete += 1
            summary = finding.get('evaluation_summary')
            if not isinstance(summary, dict):
                continue
            inspected += 1
            counts = summary.get('counts')
            if not isinstance(counts, dict):
                continue
            insecure = counts.get('insecure')
            flagged = finding.get('flagged_items')
            if (type(insecure) is not int or insecure < 0 or
                    type(flagged) is not int or flagged < 0):
                issues.append({'service': service, 'rule': name, 'type': 'invalid_counts'})
            elif flagged != insecure:
                # Evidence evaluator and rule conditions disagree. This is NOT
                # proof that either result is independently correct.
                issues.append({'service': service, 'rule': name,
                               'type': 'evidence_finding_count_mismatch',
                               'insecure_count': insecure, 'flagged_count': flagged})
            state = summary.get('assessment_status', 'unknown')
            by_status[str(state)] = by_status.get(str(state), 0) + 1
    status = data.get('collection_status') or {}
    incomplete_collection = not (isinstance(status, dict) and
                                 status.get('complete') is True)
    result = {
        'schema_version': 1,
        'report_schema_version': data.get('report_schema_version'),
        'services': len(data['services']),
        'rules': rules,
        'evaluated_policies': inspected,
        'incomplete_rules': incomplete,
        'collection_incomplete': incomplete_collection,
        'collection_issue_count': len(status.get('issues', []))
        if isinstance(status, dict) and isinstance(status.get('issues'), list) else None,
        'evaluation_status_counts': by_status,
        'discrepancy_count': len(issues),
        'discrepancies': issues,
    }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only report evidence alignment gate')
    parser.add_argument('report', type=Path, help='Local ScoutSuite RESULTS .js or .json')
    parser.add_argument('--fail-on-discrepancy', action='store_true',
                        help='Exit 3 on evidence/finding mismatch (not on incomplete cloud data)')
    args = parser.parse_args(argv)
    try:
        result = analyze(load_results(args.report))
    except (OSError, UnicodeError, ValueError) as exc:
        # Do not include path, raw report lines, parsed JSON or OS error text.
        print(json.dumps({'error': type(exc).__name__, 'status': 'invalid_report'}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 3 if args.fail_on_discrepancy and result['discrepancy_count'] else 0


if __name__ == '__main__':
    sys.exit(main())
