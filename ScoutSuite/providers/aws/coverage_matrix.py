"""AWS service/Region evidence matrix.

A result with zero findings is not evidence of a complete assessment. The
matrix reports only observed AWS SDK API outcomes and evidence-policy checks.
Legacy collectors may emit issues without a Region: conservatively apply
these issues to all Region rows of their service, rather than inventing scope.
"""
from collections import defaultdict

SCOPE_ALIASES = {
    'lambda': 'awslambda',
    'macie2': 'macie',
    'network-firewall': 'networkfirewall',
    'bedrock-agent': 'bedrock',
    'route53domains': 'route53',
    's3control': 's3',
    'logs': 'cloudwatch',
    'elasticloadbalancing': 'elbv2',
}

UNKNOWN_STATES = frozenset((
    'UNKNOWN', 'PARTIAL', 'DENIED', 'SKIPPED', 'NOT_ASSESSED'))


def _canonical(value):
    return SCOPE_ALIASES.get(value, value)


def _reported_inventory_count(region):
    """Sum exposed resource-type counters; not a unique asset inventory."""
    if not isinstance(region, dict):
        return None
    counts = [
        value for key, value in region.items()
        if isinstance(key, str) and key.endswith('_count')
        and key not in ('regions_count', 'dns_domains_count')
        and type(value) is int and value >= 0
    ]
    return sum(counts) if counts else None


def _collector_gaps(region_data):
    """Explicit collector status fields, including bounded partial-page evidence."""
    if not isinstance(region_data, dict):
        return []
    bad = frozenset(('partial', 'denied', 'failed', 'unknown',
                     'unavailable', 'not_collected',
                     'deferred_no_current_backup_inventory'))
    gaps = set()
    for field, value in region_data.items():
        if not isinstance(field, str):
            continue
        if field == 'collection' or field.endswith('inventory_status'):
            pass
        elif 'collection_status' not in field:
            continue
        if isinstance(value, str) and value in bad:
            gaps.add(field + ':' + value)
        elif isinstance(value, dict):
            for subfield, state in value.items():
                if not isinstance(subfield, str):
                    continue
                if state is False or (isinstance(state, str) and state in bad):
                    gaps.add(field + '.' + subfield)
    return sorted(gaps)[:64]


def _regions(service_data, requested_regions, excluded_regions):
    if not isinstance(service_data, dict):
        return ['undetermined']
    if 'regions' not in service_data:
        return ['global']
    records = service_data.get('regions')
    observed = set(records) if isinstance(records, dict) else set()
    # Explicitly requested but undiscovered Regions must remain visible as
    # UNKNOWN, and excluded Regions must remain visible as SKIPPED.
    regions = observed | set(requested_regions) | set(excluded_regions)
    return sorted(regions) if regions else ['undetermined']


def _findings_in_region(service, region, data):
    """Count matched rule instances, not unique exploitable vulnerabilities."""
    if not isinstance(data, dict):
        return 0
    prefix = service + '.regions.' + region + '.'
    count = 0
    for finding in (data.get('findings') or {}).values():
        if not isinstance(finding, dict):
            continue
        items = finding.get('items') or []
        if not isinstance(items, list):
            continue
        if region == 'global':
            count += sum(1 for item in items if isinstance(item, str)
                         and item.startswith(service + '.')
                         and not item.startswith(service + '.regions.'))
        else:
            count += sum(1 for item in items
                         if isinstance(item, str)
                         and (item.startswith(prefix)
                              or item == prefix[:-1]))
    return count


def build_aws_coverage_matrix(service_list, services, context,
                              requested_regions=(), excluded_regions=(),
                              skipped_services=(), enabled_rule_counts=None,
                              extra_issues=()):
    """Return bounded JSON-safe observability, not a positive compliance verdict.

    'checked_resources' counts *distinct evaluated evidence-policy paths*; no
    claim that every inventoried resource has an evidence-policy rule.
    'api.success' counts Botocore final responses, not unique operations or pages.
    A successful API response cannot by itself prove completeness of all AWS APIs.
    """
    telemetry = context.aws_telemetry_snapshot()
    api = defaultdict(lambda: {
        'success': 0, 'absent': 0, 'denied': 0, 'failed': 0,
        'unsupported': 0, 'operations': {}
    })
    for (service, region), counts in telemetry['api'].items():
        row = api[(_canonical(service), region)]
        for outcome in ('success', 'absent', 'denied', 'failed', 'unsupported'):
            row[outcome] += counts.get(outcome, 0)
        for operation, statuses in counts.get('operations', {}).items():
            entry = row['operations'].setdefault(
                operation, {'success': 0, 'absent': 0, 'denied': 0,
                            'failed': 0, 'unsupported': 0})
            for outcome in entry:
                entry[outcome] += statuses.get(outcome, 0)

    evidence = defaultdict(lambda: {'checked': 0, 'unknown': 0, 'not_applicable': 0})
    for (service, region), counts in telemetry['evidence'].items():
        item = evidence[(_canonical(service), region)]
        for name in item:
            item[name] += counts.get(name, 0)

    issues = [issue for issue in list(context.collection_issues) + list(extra_issues)
              if isinstance(issue, dict)]
    enabled_rule_counts = enabled_rule_counts or {}
    rows = []
    selected = sorted(set(service_list))
    # Explicitly skipped services remain visible, without fabricated API calls.
    for service in sorted(set(selected) | set(skipped_services) | set(enabled_rule_counts)):
        service_skipped = service not in selected
        data = services.get(service) if isinstance(services, dict) else None
        regions = (['not_scanned'] if service_skipped
                   else _regions(data, requested_regions, excluded_regions))
        for region in regions:
            region_excluded = region in excluded_regions
            skipped = service_skipped or region_excluded
            matching = [
                issue for issue in issues
                if _canonical(issue.get('scope')) in (service, 'aws', 'assessment')
                and (issue.get('region') is None
                     or issue.get('region') == region)
            ]
            outcomes = api[(service, region)]
            evid = evidence[(service, region)]
            region_data = ((data.get('regions') or {}).get(region)
                           if isinstance(data, dict)
                           and isinstance(data.get('regions'), dict)
                           else data)
            inventory = None if skipped else _reported_inventory_count(region_data)
            collector_gaps = [] if skipped else _collector_gaps(region_data)
            observed = outcomes['success'] + outcomes['absent']
            errors = outcomes['denied'] + outcomes['failed'] + outcomes['unsupported']
            unscoped = any(issue.get('region') is None for issue in matching)
            if skipped:
                state = 'SKIPPED'
            elif matching or errors or evid['unknown'] or collector_gaps:
                if (outcomes['denied'] or any(
                        issue.get('status') == 'denied' for issue in matching)
                        ) and not observed and not outcomes['failed'] and not evid['checked']:
                    state = 'DENIED'
                else:
                    state = 'PARTIAL'
            elif observed == 0:
                state = 'UNKNOWN'
            elif evid['checked'] == 0:
                # API calls alone do not certify that any security check ran.
                state = 'NOT_ASSESSED'
            else:
                state = 'OBSERVED_COMPLETE'
            flagged = 0 if skipped else _findings_in_region(service, region, data)
            # Only explicitly excluded services count as skipped checks.
            skipped_checks = enabled_rule_counts.get(service, 0) if skipped else 0
            rows.append({
                'service': service, 'region': region, 'status': state,
                'region_excluded': region_excluded,
                'inventory_records_observed': inventory,
                'checked_resources': 0 if skipped else evid['checked'],
                'unknown_resources': 0 if skipped else evid['unknown'],
                'not_applicable_resources': 0 if skipped else evid['not_applicable'],
                'flagged_rule_items': flagged,
                'skipped_checks': skipped_checks,
                'api': {k: outcomes[k] for k in (
                    'success', 'absent', 'denied', 'failed', 'unsupported')},
                'api_operations': {k: outcomes['operations'][k]
                                   for k in sorted(outcomes['operations'])},
                'collection_issues': matching,
                'collector_gaps': collector_gaps,
                'issues_without_region': unscoped,
                'zero_findings_interpretation': (
                    'NOT_VERIFIED_CLEAN' if flagged == 0 and state != 'OBSERVED_COMPLETE'
                    else 'NO_FINDINGS_OBSERVED' if flagged == 0 else
                    'FINDINGS_OBSERVED'),
                'compliance_verified': False,
            })
    status = ('observed_complete' if rows
              and all(row['status'] == 'OBSERVED_COMPLETE' for row in rows)
              else 'partial')
    return {
        'version': 1, 'status': status, 'complete': status == 'observed_complete',
        'scope': 'observed_api_responses_and_evidence_policy_rules_only',
        'count_basis': ('checked_resources = distinct evidence-policy paths; '
                        'inventory_records_observed = sum of available resource-type '
                        'counters, not a distinct asset total'),
        'clean_result_verified': False, 'rows': rows,
        'rows_count': len(rows),
        'incomplete_rows': sum(1 for row in rows
                               if row['status'] in UNKNOWN_STATES),
    }
