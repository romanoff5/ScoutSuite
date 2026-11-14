#!/usr/bin/env python3
"""P3-C: deterministic OFFLINE coverage and synthetic detector-quality gate.

No AWS credentials, network calls, customer assets, or report contents. This is
a semantic coverage benchmark, NOT field validation or a live false-positive rate.
"""
import argparse
import copy
import json
import re
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'tests' / 'data'
RULE_ROOT = ROOT / 'ScoutSuite' / 'providers' / 'aws' / 'rules'
COVERAGE_STATES = {'direct', 'partial', 'gap', 'out_of_scope'}
# Fail closed on real-looking account IDs, ARNs, emails and private-source
# placeholders without embedding customer names in a public repository.
FORBIDDEN = re.compile(
    r'(?<![0-9])[0-9]{12}(?![0-9])|arn:(?:aws|aws-us-gov|aws-cn):|'
    r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}|'
    r'\\b(?:client_name|customer_account_id|internal_host|private_domain)\\b', re.I)
SYNTHETIC_MINIMUM = 25


def _load(path):
    with Path(path).open(encoding='utf-8') as stream:
        return json.load(stream)


def _check(condition, message, problems):
    if not condition:
        problems.append(message)


def validate_coverage(document, rules):
    """Fail closed on missing scenarios, invalid mappings and confidentiality drift."""
    errors, cases = [], document.get('cases')
    _check(document.get('schema_version') == 1, 'Unsupported coverage schema', errors)
    _check(document.get('visibility') == 'synthetic-public', 'Data must be synthetic-public', errors)
    if not isinstance(cases, list):
        return ['Coverage cases must be a list'], {}
    ids, by_id = [], {}
    for row in cases:
        if not isinstance(row, dict):
            errors.append('Non-object coverage row')
            continue
        ident = row.get('id')
        if not isinstance(ident, str):
            errors.append('Invalid case identifier')
            continue
        ids.append(ident)
        by_id[ident] = row
        _check(set(row) == {'id', 'domain', 'control', 'coverage', 'rule_ids', 'limitation'},
               'Invalid fields in ' + ident, errors)
        _check(row.get('coverage') in COVERAGE_STATES, 'Unknown coverage state ' + ident, errors)
        _check(bool(re.fullmatch(r'[a-z0-9_]+', str(row.get('control', '')))),
               'Unsafe control name ' + ident, errors)
        _check(bool(re.fullmatch(r'[a-z0-9_]+', str(row.get('domain', '')))),
               'Unsafe domain name ' + ident, errors)
        _check(isinstance(row.get('limitation'), str) and bool(row.get('limitation')),
               'Missing limitation for ' + ident, errors)
        names = row.get('rule_ids')
        if not isinstance(names, list):
            errors.append('Missing rule list ' + ident)
            continue
        _check(len(names) == len(set(names)), 'Duplicate rule ' + ident, errors)
        if row.get('coverage') in ('direct', 'partial'):
            _check(bool(names), 'Covered case with no mapping ' + ident, errors)
        else:
            _check(not names, 'Gap / outside-scope case must not claim detection ' + ident, errors)
        for name in names:
            _check(name in rules, ident + ': unknown or disabled rule ' + str(name), errors)
            _check((RULE_ROOT / 'findings' / str(name)).is_file(),
                   ident + ': missing rule definition ' + str(name), errors)
    expected_ids = {f'A-{n:02d}' for n in range(1, 40)}
    expected_ids |= {f'B-{n:02d}' for n in range(1, 28)}
    _check(set(ids) == expected_ids and len(ids) == 66,
           'Expected complete anonymized 39+27 case census', errors)
    _check(len(ids) == len(set(ids)), 'Duplicate case IDs', errors)
    # Deliberately reject literal customer identifiers in this PUBLIC fixture.
    _check(not FORBIDDEN.search(json.dumps(document, ensure_ascii=False)),
           'Customer identifier detected in coverage dataset', errors)
    return errors, by_id


def validate_crosswalk(document, rules):
    errors, rows = [], document.get('crosswalk')
    _check(document.get('schema_version') == 1, 'Unsupported crosswalk schema', errors)
    if not isinstance(rows, list):
        return ['External crosswalk rows must be a list'], {}
    _check(len(rows) >= 8, 'External crosswalk too small for baseline', errors)
    keys = []
    for row in rows:
        if not isinstance(row, dict):
            errors.append('Invalid external crosswalk record')
            continue
        provider = row.get('provider')
        external = row.get('external_id')
        keys.append((provider, external))
        _check(provider in ('aws_security_hub', 'prowler'),
               'Unsupported external provider', errors)
        _check(row.get('relation') in ('related', 'partial'),
               'Crosswalk must NOT claim unverified exact parity', errors)
        _check(row.get('rule_id') in rules,
               'Unknown internal crosswalk rule ' + str(row.get('rule_id')), errors)
        url = row.get('source_url')
        _check(isinstance(url, str) and url.startswith('https://'),
               'Missing authoritative crosswalk URL', errors)
        _check(isinstance(row.get('qualification'), str) and bool(row['qualification']),
               'Missing semantic qualification', errors)
        if provider == 'prowler':
            pin = document.get('provenance', {}).get('prowler_pinned_commit')
            _check(isinstance(pin, str) and len(pin) == 40 and pin in (url or ''),
                   'Unpinned Prowler source', errors)
    _check(len(keys) == len(set(keys)), 'Duplicate external control crosswalk', errors)
    _check(not FORBIDDEN.search(json.dumps(document, ensure_ascii=False)),
           'Customer identifier in crosswalk', errors)
    return errors, Counter(row.get('provider') for row in rows if isinstance(row, dict))


def _inventory(rule_path, resource):
    """Create a single-resource synthetic inventory for a real rule path."""
    parts = rule_path.split('.')
    root, cursor = {}, None
    cursor = root
    for index, piece in enumerate(parts):
        key = 'synthetic-resource' if piece == 'id' else piece
        if index == len(parts) - 1:
            cursor[key] = resource
        else:
            cursor[key] = {}
            cursor = cursor[key]
    return root


def validate_triads(document, case_index, enabled_rules):
    """Execute the REAL rule conditions and evidence classification on three states."""
    from ScoutSuite.core.utils import recurse
    from ScoutSuite.core.rule_evidence import evaluate_rule_evidence

    errors, rows = [], document.get('triads')
    metrics = Counter()
    if not isinstance(rows, list):
        return ['Synthetic triads must be a list'], dict(metrics)
    _check(document.get('schema_version') == 1, 'Unsupported triad schema', errors)
    _check(len(rows) >= SYNTHETIC_MINIMUM, 'Too few detector triads', errors)
    seen = set()
    for triad in rows:
        ident = triad.get('id', '<unnamed>')
        _check(ident not in seen, 'Duplicate detector triad ' + ident, errors)
        seen.add(ident)
        rule_name = triad.get('rule_id')
        if rule_name not in enabled_rules:
            errors.append('Unknown or disabled detector rule: ' + str(rule_name))
            continue
        case_id = triad.get('report_case')
        if case_id is not None:
            row = case_index.get(case_id)
            _check(row is not None and rule_name in row.get('rule_ids', []),
                   'Triad not mapped to the stated report-control abstract ' + ident, errors)
        field = triad.get('field')
        _check(isinstance(field, str) and bool(re.fullmatch(r'[a-z][a-z0-9_]*', field)),
               'Invalid triad field ' + ident, errors)
        base = triad.get('base')
        states, expected = triad.get('states'), triad.get('expected')
        if not isinstance(base, dict) or not isinstance(states, dict) or not isinstance(expected, dict):
            errors.append('Malformed triad input ' + ident)
            continue
        definition = _load(RULE_ROOT / 'findings' / rule_name)
        _check(field in json.dumps(definition.get('conditions', [])),
               'Triad field not exercised by rule conditions ' + ident, errors)
        _check(definition.get('evidence_policy') is not None,
               'Triad rule missing evidence policy ' + ident, errors)
        for stage in ('positive', 'negative', 'incomplete'):
            _check(stage in states and stage in expected,
                   'Missing triad stage ' + ident + '/' + stage, errors)
            if stage not in states or stage not in expected:
                continue
            resource = copy.deepcopy(base)
            resource[field] = states[stage]
            inventory = _inventory(definition['path'], resource)
            config = SimpleNamespace(filename=rule_name, path=definition['path'],
                                     conditions=definition['conditions'],
                                     evidence_policy=definition['evidence_policy'],
                                     id_suffix=definition.get('id_suffix'),
                                     checked_items=0)
            try:
                found = recurse(inventory, inventory, config.path.split('.'), [], config, True)
                detail = evaluate_rule_evidence(config, inventory)
                status = expected[stage]
                counts = detail['counts']
                actual = next((key for key, count in counts.items() if count == 1), None)
                if sum(counts.values()) != 1:
                    raise AssertionError('Expected exactly one synthetic resource')
                if actual != status:
                    errors.append(ident + '/' + stage + ': expected evidence='
                                  + str(status) + ', got=' + str(actual))
                if stage == 'positive':
                    metrics['positive'] += 1
                    if found and actual == 'insecure':
                        metrics['tp'] += 1
                    else:
                        metrics['fn'] += 1
                elif stage == 'negative':
                    metrics['negative'] += 1
                    if found:
                        metrics['fp'] += 1
                    elif actual == 'secure':
                        metrics['tn'] += 1
                    else:
                        metrics['unverified_negative'] += 1
                else:
                    metrics['unknown_cases'] += 1
                    if found:
                        metrics['unknown_flagged'] += 1
                    if actual == 'secure' or detail.get('assessment_status') != 'incomplete':
                        metrics['false_pass_on_unknown'] += 1
            except Exception as exc:
                errors.append(ident + '/' + stage + ': ' + type(exc).__name__ + ': ' + str(exc))
    if any(metrics.get(key, 0) for key in ('fp', 'fn', 'unknown_flagged', 'false_pass_on_unknown')):
        errors.append('Synthetic detection quality gate failed')
    _check(metrics['positive'] == len(rows)
           and metrics['negative'] == len(rows)
           and metrics['unknown_cases'] == len(rows),
           'Not all TP/TN/UNKNOWN stages executed', errors)
    return errors, dict(metrics)


def analyze():
    """Return a machine-readable result without cloud or external API access."""
    ruleset = _load(RULE_ROOT / 'rulesets' / 'default.json')
    rules = {name for name, settings in ruleset['rules'].items()
             if any(item.get('enabled') is True for item in settings)}
    coverage = _load(DATA / 'p3c_assessment_coverage.json')
    crosswalk = _load(DATA / 'p3c_external_crosswalk.json')
    triads = _load(DATA / 'p3c_detection_triads.json')
    coverage_errors, index = validate_coverage(coverage, rules)
    external_errors, providers = validate_crosswalk(crosswalk, rules)
    triad_errors, metrics = validate_triads(triads, index, rules)
    counts = Counter(row['coverage'] for row in coverage['cases'])
    by_group = {group: dict(Counter(row['coverage'] for row in coverage['cases']
                                    if row['id'].startswith(group + '-')))
                for group in ('A', 'B')}
    scoped = counts['direct'] + counts['partial'] + counts['gap']
    direct = round(counts['direct'] * 100 / scoped, 2) if scoped else 0
    detectable = round((counts['direct'] + counts['partial']) * 100 / scoped, 2) if scoped else 0
    all_errors = coverage_errors + external_errors + triad_errors
    return {
        'schema_version': 1,
        'assessment': 'OFFLINE SYNTHETIC QUALITY GATE; NO FIELD VALIDATION',
        'pass': not all_errors,
        'errors': all_errors,
        'report_cases': {'total': len(coverage['cases']), 'in_scope': scoped,
                         'coverage': dict(counts), 'by_group': by_group,
                         'direct_contract_percent': direct,
                         'direct_or_partial_contract_percent': detectable,
                         'field_detection_verified': False,
                         'direct_does_not_mean_verified': True},
        'synthetic_detection': metrics,
        'external_crosswalk': {'entries': len(crosswalk['crosswalk']), 'by_provider': dict(providers),
                               'parity_claimed': False},
        'limitations': [
            'Report-derived controls are anonymized; no customer assessment evidence is shipped.',
            'Rule contract mapping does not establish live detection or customer remediation status.',
            'Synthetic false positives/negatives cannot estimate real-world FP/FN rates.',
            'External Security Hub/Prowler IDs are related or partially comparable only.',
            'No AWS API access, DNS probes, or live deployments are exercised.'
        ]
    }


def markdown(result):
    coverage = result['report_cases']
    states = coverage['coverage']
    synthetic = result['synthetic_detection']
    lines = [
        '# P3-C offline quality gate',
        '',
        '**Result:** ' + ('PASS' if result['pass'] else 'FAIL'),
        '',
        '**Not a live-assessment accuracy claim.** No customer report contents or identifiers are embedded.',
        '',
        '| Measure | Value |',
        '|---|---:|',
        '| Anonymized cases | ' + str(coverage['total']) + ' |',
        '| In-scope cloud configuration cases | ' + str(coverage['in_scope']) + ' |',
        '| Direct rule-contract mappings | ' + str(states.get('direct', 0)) + ' |',
        '| Partial rule-contract mappings | ' + str(states.get('partial', 0)) + ' |',
        '| Uncovered report-control gaps | ' + str(states.get('gap', 0)) + ' |',
        '| Outside cloud scanner scope | ' + str(states.get('out_of_scope', 0)) + ' |',
        '| Direct mapping coverage (%) | ' + str(coverage['direct_contract_percent']) + ' |',
        '| Direct + partial mapping coverage (%) | ' + str(
            coverage['direct_or_partial_contract_percent']) + ' |',
        '| Synthetic TP / FN | ' + str(synthetic.get('tp', 0)) + ' / ' + str(
            synthetic.get('fn', 0)) + ' |',
        '| Synthetic TN / FP | ' + str(synthetic.get('tn', 0)) + ' / ' + str(
            synthetic.get('fp', 0)) + ' |',
        '| Unknown inputs misclassified as secure | ' + str(
            synthetic.get('false_pass_on_unknown', 0)) + ' |',
        '| Negative inputs deliberately unverified | ' + str(
            synthetic.get('unverified_negative', 0)) + ' |',
        '| External control crosswalk entries | ' + str(result['external_crosswalk']['entries']) + ' |',
        '',
        '## Gap control IDs',
    ]
    cases = _load(DATA / 'p3c_assessment_coverage.json')['cases']
    lines.extend('- ' + x['id'] + ': ' + x['control']
                 for x in cases if x['coverage'] == 'gap')
    lines.extend(['', '## Constraints'])
    lines.extend('- ' + limitation for limitation in result['limitations'])
    if result['errors']:
        lines.extend(['', '## Failed checks'])
        lines.extend('- ' + value for value in result['errors'])
    return '\n'.join(lines) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Fail if quality gate is not satisfied')
    parser.add_argument('--json', dest='json_path', type=Path, help='Write machine-readable summary')
    parser.add_argument('--markdown', dest='markdown_path', type=Path, help='Write human summary')
    options = parser.parse_args(argv)
    result = analyze()
    if options.json_path:
        options.json_path.parent.mkdir(parents=True, exist_ok=True)
        options.json_path.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n',
                                     encoding='utf-8')
    if options.markdown_path:
        options.markdown_path.parent.mkdir(parents=True, exist_ok=True)
        options.markdown_path.write_text(markdown(result), encoding='utf-8')
    print(json.dumps({
        'pass': result['pass'], 'cases': result['report_cases']['total'],
        'coverage': result['report_cases']['coverage'],
        'synthetic': result['synthetic_detection'],
        'crosswalk': result['external_crosswalk']['entries'],
        'errors': result['errors']
    }, sort_keys=True))
    return 0 if result['pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
