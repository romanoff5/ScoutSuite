"""M10-R: read-only, per-account/per-region CloudTrail organization coverage.

Correlates existing CloudTrail and Organizations inventory. Configuration is
NOT proof of per-account delivery: no cross-account sessions or S3 object reads.
"""
from ScoutSuite.core.run_context import get_current_run_context

_VERSION = 1
_ENABLED = frozenset(('ENABLED', 'ENABLED_BY_DEFAULT'))
_TRANSITION = frozenset(('ENABLING', 'DISABLING'))


def _issue(reason):
    context = get_current_run_context()
    if context is not None:
        context.record_collection_issue('partial', 'cloudtrail', 'M10R.' + reason)


def _management_events_complete(trail):
    """Only unconditional read AND write management selectors qualify."""
    if trail.get('selector_collection_status') != 'success':
        return None
    basic = trail.get('EventSelectors')
    advanced = trail.get('AdvancedEventSelectors')
    if not isinstance(basic, list) or not isinstance(advanced, list):
        return None
    for selector in basic:
        if not isinstance(selector, dict):
            return None
        if (selector.get('IncludeManagementEvents') is True
                and selector.get('ReadWriteType') in ('All', None)
                and not selector.get('ExcludeManagementEventSources')):
            return True
    for selector in advanced:
        if not isinstance(selector, dict):
            return None
        fields = selector.get('FieldSelectors')
        if not isinstance(fields, list):
            return None
        if (len(fields) == 1 and isinstance(fields[0], dict)
                and fields[0].get('Field') == 'eventCategory'
                and fields[0].get('Equals') == ['Management']
                and set(fields[0]) <= {'Field', 'Equals'}):
            return True
    return False


def _trail_inventory(cloudtrail):
    if not isinstance(cloudtrail, dict):
        return [], False
    regions = cloudtrail.get('regions')
    if not isinstance(regions, dict) or not regions:
        return [], False
    complete = True
    unique = {}
    for region_name, entry in regions.items():
        if not isinstance(entry, dict) or entry.get('trails_inventory_status') != 'complete':
            complete = False
        trails = entry.get('trails') if isinstance(entry, dict) else None
        if not isinstance(trails, dict):
            complete = False
            continue
        for raw in trails.values():
            if not isinstance(raw, dict) or raw.get('scout_link'):
                continue
            arn = raw.get('arn') or raw.get('TrailARN')
            if not isinstance(arn, str) or not arn:
                _issue('TrailMissingARN')
                complete = False
                continue
            if arn in unique:
                _issue('DuplicateHomeTrailARN')
                complete = False
            else:
                unique[arn] = raw
    return [item for item in unique.values() if item.get('is_organization_trail') is True], complete


def _candidate(trail, region, enabled_regions):
    home = trail.get('home_region') or trail.get('HomeRegion')
    if not isinstance(home, str) or not home:
        return None, 'home_region_unknown'
    if home not in enabled_regions:
        return False, 'organization_trail_home_region_not_enabled'
    if not trail.get('IsMultiRegionTrail') and home != region:
        return False, 'single_region_trail'
    if trail.get('IsLogging') is False:
        return False, 'trail_logging_disabled'
    if trail.get('IsLogging') is not True:
        return None, 'trail_status_unknown'
    management = _management_events_complete(trail)
    if management is None:
        return None, 'event_selectors_unavailable'
    if management is False:
        return False, 'read_write_management_events_not_fully_enabled'
    if trail.get('LatestDeliveryError') or trail.get('LatestCloudWatchLogsDeliveryError'):
        # A delivery error prevents claiming healthy service delivery, even
        # though the trail is configured. No member-specific conclusion.
        return None, 'organization_trail_delivery_error'
    return True, 'organization_management_logging_configured'


def _coverage_for_region(region, states, trails, inventory_complete, account_region_complete):
    state = states[region]
    evidence = {
        'region': region, 'region_opt_status': state,
        'configuration_state': 'unknown', 'reason': None, 'trail_arns': [],
        'per_account_delivery_verified': False,
        'delivery_evidence': 'not_collected',
    }
    if state == 'DISABLED':
        evidence['configuration_state'] = 'not_applicable'
        evidence['reason'] = 'region_disabled'
        return evidence
    if state in _TRANSITION:
        evidence['reason'] = 'region_opt_in_transition'
        return evidence
    if state not in _ENABLED:
        evidence['reason'] = 'unrecognized_region_opt_status'
        return evidence
    enabled = {r for r, s in states.items() if s in _ENABLED}
    unknown = False
    for trail in trails:
        applies, reason = _candidate(trail, region, enabled)
        if applies is True:
            evidence['trail_arns'].append(trail.get('arn') or trail.get('TrailARN'))
        elif applies is None:
            unknown = True
    if evidence['trail_arns'] and account_region_complete and inventory_complete:
        evidence['configuration_state'] = 'configured'
        evidence['reason'] = 'organization_trail_configuration_only'
    elif not account_region_complete or not inventory_complete or unknown:
        evidence['reason'] = 'incomplete_inventory_or_trail_evidence'
    else:
        evidence['configuration_state'] = 'gap'
        evidence['reason'] = ('no_effective_read_write_management_organization_trail'
                              if trails else 'no_organization_trail_observed')
    return evidence


def reconcile_cloudtrail_organization_coverage(services, selected_services, scanned_account_id=None):
    """Build an auditable account matrix; never infer PASS from missing API data.

    All active accounts remain present even if Account Management denied
    region status. Only a complete scope can produce a negative finding.
    """
    selected = set(selected_services or ())
    if not {'organizations', 'cloudtrail'} <= selected:
        return None
    organizations = services.get('organizations') if isinstance(services, dict) else None
    cloudtrail = services.get('cloudtrail') if isinstance(services, dict) else None
    if not isinstance(organizations, dict) or not isinstance(cloudtrail, dict):
        return None

    accounts = organizations.get('accounts')
    collection = organizations.get('collection') or {}
    region_inventory = organizations.get('account_regions') or {}
    trails, trails_complete = _trail_inventory(cloudtrail)
    # A restricted --regions scan is not a complete absence census. Validate
    # scanner-account enabled Regions before allowing any negative result.
    caller_regions = region_inventory.get(scanned_account_id)
    caller_states = (caller_regions.get('regions')
                     if isinstance(caller_regions, dict) else None)
    scanned_regions = set((cloudtrail.get('regions') or {}).keys())
    if (not isinstance(caller_regions, dict)
            or caller_regions.get('collection_status') != 'complete'
            or not isinstance(caller_states, dict) or not caller_states):
        trails_complete = False
        _issue('ScannerAccountRegionInventoryUnavailable')
    elif not {r for r, state in caller_states.items()
              if state in _ENABLED} <= scanned_regions:
        trails_complete = False
        _issue('RestrictedCloudTrailRegionCensus')
    accounts_complete = (isinstance(collection, dict)
                         and collection.get('accounts') == 'complete'
                         and isinstance(accounts, dict))
    if not isinstance(accounts, dict):
        accounts = {}
    if not isinstance(region_inventory, dict):
        region_inventory = {}
    summary = {
        'version': _VERSION,
        'scope': 'organization_account_region_configuration',
        'api_calls_during_reconciliation': 0,
        'accounts_inventory_complete': accounts_complete,
        'cloudtrail_inventory_complete': trails_complete,
        'organization_trail_arns': sorted(
            str(t.get('arn') or t.get('TrailARN')) for t in trails),
        'active_accounts': 0, 'accounts_with_config_gaps': 0,
        'accounts_unknown': 0, 'known_enabled_regions': 0,
        'configured_regions': 0, 'gap_regions': 0, 'unknown_regions': 0,
        'all_accounts_configured': False,
        'per_account_delivery_verified': False,
        'per_account_event_delivery_collected': False,
        'account_scope': sorted(accounts),
        'limitations': [
            'Configuration alone cannot prove event delivery for each member account.',
            'Per-account region lists require account:ListRegions with organization trusted access.',
            'An organization trail in an opt-in home region only covers members enabling that region.',
        ],
    }
    if not accounts_complete:
        _issue('OrganizationAccountsInventoryIncomplete')
    if not trails_complete:
        _issue('CloudTrailInventoryIncomplete')
    for identifier, account in accounts.items():
        if not isinstance(account, dict):
            continue
        if account.get('state') in ('SUSPENDED', 'CLOSED', 'PENDING_CLOSURE'):
            account['m10r_cloudtrail_coverage'] = {
                'state': 'not_applicable', 'reason': 'account_not_active',
                'regions': {}, 'delivery_verified': False}
            account['m10r_cloudtrail_config_gap'] = False
            continue
        summary['active_accounts'] += 1
        region_data = region_inventory.get(identifier)
        region_status = (region_data.get('collection_status')
                         if isinstance(region_data, dict) else None)
        states = region_data.get('regions') if isinstance(region_data, dict) else None
        complete = region_status == 'complete' and isinstance(states, dict) and bool(states)
        matrix = {}
        if isinstance(states, dict):
            for region in sorted(states):
                status = states[region]
                if not isinstance(region, str) or not isinstance(status, str):
                    continue
                row = _coverage_for_region(region, states, trails, trails_complete, complete)
                matrix[region] = row
                if status in _ENABLED:
                    summary['known_enabled_regions'] += 1
                    summary[row['configuration_state'] + '_regions'] += 1
        gaps = [r for r in matrix.values() if r['configuration_state'] == 'gap']
        uncertain = [r for r in matrix.values() if r['configuration_state'] == 'unknown']
        if gaps:
            status = 'gap'
            summary['accounts_with_config_gaps'] += 1
        elif (accounts_complete and complete and trails_complete and matrix
              and account.get('state') == 'ACTIVE' and not uncertain):
            status = 'configured'
        else:
            status = 'unknown'
            summary['accounts_unknown'] += 1
        account['m10r_cloudtrail_coverage'] = {
            'state': status, 'reason': ('account_regions_not_verified' if not complete
                                      else 'configuration_only_not_delivery_proof'),
            'region_inventory_status': region_status or 'not_collected',
            'regions': matrix, 'configured_region_count': sum(
                r['configuration_state'] == 'configured' for r in matrix.values()),
            'gap_region_count': len(gaps),
            'delivery_verified': False,
        }
        account['m10r_cloudtrail_config_gap'] = bool(gaps)
    summary['all_accounts_configured'] = bool(
        accounts_complete and summary['active_accounts']
        and not summary['accounts_with_config_gaps']
        and not summary['accounts_unknown'])
    # Scoped to the existing AWS report, not a new pseudo service.
    for org in (organizations.get('organizations') or {}).values():
        if isinstance(org, dict):
            org['m10r_cloudtrail_summary'] = summary
    organizations['m10r_cloudtrail_summary'] = summary
    cloudtrail['m10r_organization_coverage'] = summary
    return summary
