"""M10-Q v2: deeper AWS service coverage and S3 advanced resource joins.

Read-only report postprocessing. Never equate configuration or an historical
event with verified operational protection; never report an absent target from
a partial or unverified source inventory.
"""
from fnmatch import fnmatchcase

from ScoutSuite.providers.aws.resources.coverage_reconciliation import (
    _source, _regions, _values, _timestamp,
)


def _bucket_from_scope(value):
    """Exact S3 bucket-name extraction, not loose substring matching."""
    if not isinstance(value, str) or not value.startswith('s3://'):
        return None
    rest = value[5:].split('/', 1)[0]
    if not rest or '*' in rest or '?' in rest:
        return None
    return rest


def _bucket_from_reference(value):
    if not isinstance(value, str) or not value:
        return None
    if value.startswith('arn:'):
        parts = value.split(':', 5)
        if len(parts) == 6 and parts[2] == 's3' and parts[5].startswith('bucket/'):
            return parts[5][7:]
        return None
    return value if '/' not in value else None


def _link_reference(resource, bucket_name, targets, status, *,
                    region=None, owner=None, account_id=None, kind='access_point'):
    """Add reversible, explicit relation without treating missing as a security fail."""
    target = targets.get(bucket_name) if isinstance(bucket_name, str) else None
    state = 'unknown'
    reasons = []
    if isinstance(owner, str) and owner != account_id:
        state = 'foreign_account'
        reasons.append('target_owned_by_other_account')
    elif target is not None and (region is None or target.get('region') in (None, region)):
        state = 'observed_local_bucket'
        if owner is None:
            reasons.append('bucket_account_id_not_returned')
        reference = resource.get('AccessPointArn') or resource.get('AccessPointAlias')
        if reference is None:
            reference = resource.get('Name') or resource.get('AccessGrantArn')
        if not isinstance(reference, str):
            reference = str(reference) if reference is not None else 'unidentified'
        linked = target.setdefault('m10q_s3_entrypoints', [])
        if not any(item['kind'] == kind and item['reference'] == reference
                   for item in linked):
            linked.append({
                'kind': kind, 'reference': reference,
                'region': resource.get('region'),
                'policy_public': resource.get('policy_public'),
                'reference_status': 'observed_local_bucket',
            })
    elif (bucket_name is not None and status == 'complete'
          and isinstance(owner, str) and owner == account_id):
        state = 'not_in_local_bucket_inventory'
        reasons.append('same_account_bucket_reference_not_in_verified_inventory')
    elif bucket_name is not None:
        reasons.append('bucket_inventory_or_ownership_unverified')
    else:
        reasons.append('non_exact_or_unknown_bucket_reference')
    evidence = {
        'status': state, 'target_bucket': bucket_name,
        'target_region': region, 'bucket_listing_status': status,
        'ownership_confirmed': owner == account_id if isinstance(owner, str) else None,
        'reasons': reasons,
    }
    resource['m10q_bucket_target'] = evidence
    resource['m10q_bucket_target_not_reported'] = state == 'not_in_local_bucket_inventory'
    return evidence


def reconcile_s3_advanced(services, selected, account_id):
    s3 = _source(services, 's3', selected)
    if not isinstance(s3, dict):
        return {'status': 'not_collected', 'counts': {}}
    buckets = s3.get('buckets')
    if not isinstance(buckets, dict):
        return {'status': 'unknown', 'counts': {}}
    standard = {row['name']: row for row in buckets.values()
                if isinstance(row, dict) and isinstance(row.get('name'), str)}
    for row in standard.values():
        row['m10q_s3_entrypoints'] = []
        row['m10q_s3_public_access_point_count'] = 0
    listing_status = s3.get('bucket_inventory_status', 'unknown')
    advanced = s3.get('advanced')
    if not isinstance(advanced, dict):
        for row in standard.values():
            row['m10q_s3_entrypoint_inventory_status'] = 'unknown'
        return {'status': 'advanced_not_collected', 'counts': {}}
    regions = advanced.get('regions')
    if not isinstance(regions, dict):
        return {'status': 'unknown', 'counts': {}}
    stats = {'access_points': 0, 'directory_access_points': 0,
             'directory_buckets': 0, 'multi_region_access_points': 0,
             'access_grants': 0, 'access_grants_locations': 0}
    unresolved = []
    directory_index = {}
    for region, inv in regions.items():
        if not isinstance(inv, dict):
            continue
        for row in _values(inv.get('directory_buckets')):
            if isinstance(row, dict) and isinstance(row.get('Name'), str):
                directory_index[(region, row['Name'])] = row
                row['m10q_access_points'] = []
                row['m10q_backup_support_verified'] = False
                row['m10q_backup_coverage_status'] = 'not_evaluated'
                stats['directory_buckets'] += 1
    for region, inv in regions.items():
        if not isinstance(inv, dict):
            continue
        collections = inv.get('collection') or {}
        for kind in ('access_points', 'directory_access_points'):
            for row in _values(inv.get(kind)):
                if not isinstance(row, dict):
                    continue
                stats[kind] += 1
                bucket_name = _bucket_from_reference(row.get('Bucket'))
                owner = row.get('BucketAccountId')
                if kind == 'directory_access_points':
                    linked = directory_index.get((region, bucket_name))
                    state = 'observed_directory_bucket' if linked is not None else 'unknown'
                    if (state == 'unknown' and
                            collections.get('directory_buckets') == 'complete'
                            and owner == account_id and bucket_name):
                        state = 'not_in_local_directory_bucket_inventory'
                    row['m10q_bucket_target'] = {
                        'status': state, 'target_bucket': bucket_name,
                        'target_region': region,
                        'directory_bucket_inventory_complete': (
                            collections.get('directory_buckets') == 'complete'),
                    }
                    row['m10q_bucket_target_not_reported'] = (
                        state == 'not_in_local_directory_bucket_inventory')
                    if linked is not None:
                        linked['m10q_access_points'].append(row.get('Name'))
                    if row['m10q_bucket_target_not_reported']:
                        unresolved.append({'kind': kind, 'region': region,
                                           'name': row.get('Name')})
                else:
                    ev = _link_reference(
                        row, bucket_name, standard, listing_status,
                        region=None, owner=owner, account_id=account_id, kind=kind)
                    if ev['status'] == 'not_in_local_bucket_inventory':
                        unresolved.append({'kind': kind, 'region': region,
                                           'name': row.get('Name')})
        locations_by_id = {}
        for loc in _values(inv.get('access_grants_locations')):
            if not isinstance(loc, dict):
                continue
            stats['access_grants_locations'] += 1
            loc_id = loc.get('AccessGrantsLocationId')
            if isinstance(loc_id, str):
                locations_by_id[loc_id] = loc
            scope = loc.get('LocationScope')
            name = _bucket_from_scope(scope)
            _link_reference(loc, name, standard, listing_status, owner=None,
                            account_id=account_id, kind='access_grants_location')
        for grant in _values(inv.get('access_grants')):
            if not isinstance(grant, dict):
                continue
            stats['access_grants'] += 1
            loc = locations_by_id.get(grant.get('AccessGrantsLocationId'))
            location_bucket = _bucket_from_scope(loc.get('LocationScope')) if loc else None
            scope_bucket = _bucket_from_scope(grant.get('GrantScope'))
            bucket_name = scope_bucket or location_bucket
            if scope_bucket is not None and location_bucket is not None and (
                    scope_bucket != location_bucket):
                ev = {'status': 'unknown', 'target_bucket': None,
                      'reasons': ['grant_scope_conflicts_with_location']}
                grant['m10q_bucket_target'] = ev
                grant['m10q_bucket_target_not_reported'] = False
            else:
                ev = _link_reference(grant, bucket_name, standard, listing_status,
                                     owner=None, account_id=account_id, kind='access_grant')
            ev['location_linked'] = loc is not None
            ev['location_scope'] = loc.get('LocationScope') if loc else None
            ev['grant_scope'] = grant.get('GrantScope')
            ev['permission'] = grant.get('Permission')
    for point in _values(advanced.get('multi_region_access_points')):
        if not isinstance(point, dict):
            continue
        stats['multi_region_access_points'] += 1
        record = point.get('Regions')
        target_refs = []
        for target in record if isinstance(record, list) else ():
            if not isinstance(target, dict):
                continue
            name = _bucket_from_reference(target.get('Bucket'))
            region = target.get('Region')
            matches = standard.get(name)
            if matches is not None and (not region or matches.get('region') == region):
                state = 'observed_local_bucket'
                link = matches.setdefault('m10q_s3_entrypoints', [])
                reference = point.get('Name') or point.get('Alias') or 'unnamed-mrap'
                link.append({'kind': 'multi_region_access_point',
                             'reference': reference, 'region': region,
                             'policy_public': point.get('policy_public'),
                             'reference_status': state})
            else:
                # MRAP target accounts are not independently established here.
                state = 'unknown'
            target_refs.append({'bucket': name, 'region': region, 'status': state})
        point['m10q_bucket_targets'] = target_refs
        point['m10q_bucket_target_status'] = (
            'partial' if not point.get('detail_verified') or not isinstance(record, list)
            or any(t['status'] != 'observed_local_bucket' for t in target_refs)
            else 'observed')
    for row in standard.values():
        entries = row.get('m10q_s3_entrypoints', [])
        row['m10q_s3_entrypoint_count'] = len(entries)
        row['m10q_s3_public_access_point_count'] = sum(
            1 for item in entries if item['kind'] in (
                'access_points', 'directory_access_points', 'multi_region_access_point')
            and item.get('policy_public') is True)
        row['m10q_s3_entrypoint_inventory_status'] = (
            'complete' if advanced.get('coverage_status') == 'complete'
            and listing_status == 'complete' else 'unknown')
    return {'status': 'complete' if advanced.get('coverage_status') == 'complete'
            and listing_status == 'complete' else 'partial',
            'counts': stats, 'same_account_reference_gaps': unresolved,
            'bucket_listing_status': listing_status,
            'advanced_inventory_status': advanced.get('coverage_status')}


def _selection_for(arn, plan):
    """Only unconditional explicit ARN patterns can be resolved locally."""
    if plan.get('selection_collection_complete') is not True:
        return 'unknown'
    found = False
    conditional = False
    for row in plan.get('selections', []):
        selection = row.get('BackupSelection') if isinstance(row, dict) else None
        if not isinstance(selection, dict):
            conditional = True
            continue
        has_conditions = bool(selection.get('ListOfTags') or selection.get('Conditions'))
        if has_conditions:
            conditional = True
        includes = selection.get('Resources')
        excludes = selection.get('NotResources')
        if not isinstance(includes, list) or not isinstance(excludes, list):
            conditional = True
            continue
        if (not has_conditions
                and any(isinstance(p, str) and fnmatchcase(arn, p) for p in includes)
                and not any(isinstance(p, str) and fnmatchcase(arn, p)
                            for p in excludes)):
            found = True
    return 'explicitly_selected' if found else 'conditional_unknown' if conditional else 'not_explicitly_selected'


def enrich_backup_relationships(services, selected):
    """Merge plan/restore-test/cross-region evidence without overwriting success."""
    s3 = _source(services, 's3', selected)
    backups = _regions(services, 'backup', selected)
    if not isinstance(s3, dict) or not isinstance(s3.get('buckets'), dict):
        return {'count': 0}
    count = 0
    for bucket in s3['buckets'].values():
        if not isinstance(bucket, dict):
            continue
        ev = bucket.get('m10q_backup')
        if not isinstance(ev, dict):
            continue
        count += 1
        arn = ev.get('canonical_bucket_arn')
        region = ev.get('region')
        ev.update({'plan_selection_status': 'unknown', 'selected_plan_ids': [],
                   'conditional_plan_ids': [], 'restore_test_jobs_observed': [],
                   'cross_region_evidence_regions': [],
                   'recovery_point_freshness_verified': False,
                   'restore_test_success_verified': False})
        if not isinstance(arn, str) or backups is None:
            continue
        # Historical copy/recovery points can reside in another Region. Their
        # presence prevents a categorical 'not reported' conclusion at home.
        for candidate_region, inventory in backups.items():
            if candidate_region == region or not isinstance(inventory, dict):
                continue
            status = inventory.get('backup_inventory_status') or {}
            if status.get('protected_resources') != 'complete':
                continue
            if any(row.get('ResourceArn') == arn for row in _values(
                    inventory.get('protected_resources')) if isinstance(row, dict)):
                ev['cross_region_evidence_regions'].append(candidate_region)
        home = backups.get(region)
        if not isinstance(home, dict):
            if ev['cross_region_evidence_regions']:
                ev['state'] = 'cross_region_evidence_only'
                ev['reasons'].append('recovery_point_observed_in_different_region')
                bucket['m10q_backup_evidence_gap'] = False
            continue
        plans = home.get('plans')
        statuses = home.get('backup_inventory_status') or {}
        if not isinstance(plans, dict):
            continue
        selections = []
        for plan in plans.values():
            if not isinstance(plan, dict):
                continue
            pid = plan.get('backup_plan_id')
            match = _selection_for(arn, plan)
            if match == 'explicitly_selected':
                ev['selected_plan_ids'].append(pid)
            elif match == 'conditional_unknown':
                ev['conditional_plan_ids'].append(pid)
            selections.append(match)
        if selections and all(x == 'not_explicitly_selected' for x in selections):
            ev['plan_selection_status'] = 'no_explicit_plan_match'
        elif ev['selected_plan_ids']:
            ev['plan_selection_status'] = 'explicit_assignment_observed'
        elif not selections:
            ev['plan_selection_status'] = 'no_plans_observed'
        else:
            ev['plan_selection_status'] = 'conditional_or_incomplete'
        for plan in _values(home.get('restore_testing_plans')):
            if not isinstance(plan, dict):
                continue
            for job in plan.get('observed_restore_jobs', []):
                if isinstance(job, dict) and job.get('SourceResourceArn') == arn:
                    ev['restore_test_jobs_observed'].append({
                        'restore_testing_plan_arn': plan.get('RestoreTestingPlanArn'),
                        'restore_job_id': job.get('RestoreJobId'),
                        'status': job.get('Status'),
                        'validation_status': job.get('ValidationStatus')})
        if ev['cross_region_evidence_regions'] and ev['state'] == 'not_reported':
            ev['state'] = 'cross_region_evidence_only'
            ev['reasons'].append('recovery_point_observed_in_different_region')
            bucket['m10q_backup_evidence_gap'] = False
        # Plan assignments never imply a recovery point actually exists.
        ev['ongoing_schedule_verified'] = False
    return {'count': count}


def enrich_inspector_and_waf(services, selected, account_id):
    """Do not count stopped hosts as failures or ALB existence as traffic proof."""
    inspector = _regions(services, 'inspector2', selected)
    ec2 = _regions(services, 'ec2', selected)
    ecr = _regions(services, 'ecr', selected)
    changes = {'stopped_ec2_not_flagged': 0, 'inspector_account_conflicts': 0,
               'waf_association_target_conflicts': 0}
    for service, regions, resources in (('ec2', ec2, 'instances'),
                                        ('ecr', ecr, 'repositories')):
        if regions is None:
            continue
        for region, entry in regions.items():
            if not isinstance(entry, dict):
                continue
            rows = []
            if service == 'ec2':
                for vpc in _values(entry.get('vpcs')):
                    rows.extend(_values(vpc.get('instances')) if isinstance(vpc, dict) else ())
            else:
                rows.extend(_values(entry.get(resources)))
            inspector_region = inspector.get(region) if inspector is not None else None
            accounts = inspector_region.get('accounts') if isinstance(inspector_region, dict) else None
            account_known = None
            if isinstance(accounts, dict) and accounts:
                for account in accounts.values():
                    if isinstance(account, dict) and account.get('account_id') == account_id:
                        account_known = account
                        break
            disabled = isinstance(account_known, dict) and (
                account_known.get('status') in ('DISABLED', 'SUSPENDED',
                                                'DISABLING', 'SUSPENDING'))
            for row in rows:
                if not isinstance(row, dict):
                    continue
                ev = row.get('m10q_inspector')
                if not isinstance(ev, dict):
                    continue
                if service == 'ec2':
                    state = row.get('State')
                    state_name = state.get('Name') if isinstance(state, dict) else state
                    if state_name in ('stopped', 'stopping') and ev.get('state') == 'not_reported':
                        ev['state'] = 'unknown'
                        ev['reasons'].append('stopped_instance_scan_applicability_unverified')
                        row['m10q_inspector_not_reported'] = False
                        changes['stopped_ec2_not_flagged'] += 1
                if disabled and ev.get('state') in ('active_observed', 'not_reported'):
                    ev['state'] = 'unknown'
                    ev['reasons'].append('inspector_account_enrollment_inactive')
                    row['m10q_inspector_not_reported'] = False
                    if service == 'ecr':
                        operational = row.get('operational_image_scans') or {}
                        if operational.get('status') != 'gap_observed':
                            row['m10q_repository_scan_gap_candidate'] = False
                    changes['inspector_account_conflicts'] += 1
                if service == 'ecr':
                    scan = row.get('m10q_image_scanning')
                    if isinstance(scan, dict):
                        operational = row.get('operational_image_scans')
                        if not isinstance(operational, dict):
                            scan['image_level_scan_execution_verified'] = False
                            scan['image_inventory_available'] = False
                        scan['configuration_only'] = not isinstance(operational, dict)
                        scan['effective_scan_freshness'] = (
                            'verified_for_observed_images' if scan.get('image_level_scan_execution_verified')
                            else 'unknown')
    waf = _regions(services, 'wafv2', selected)
    if waf is not None:
        for region in waf.values():
            for acl in _values(region.get('web_acls') if isinstance(region, dict) else None):
                if not isinstance(acl, dict):
                    continue
                targets = acl.get('m10q_protected_targets')
                if not isinstance(targets, dict):
                    continue
                targets['independent_target_existence_only'] = True
                targets['independent_waf_attachment_verified'] = False
                targets['traffic_routing_through_waf_verified'] = False
                traffic = acl.get('operational_traffic') or {}
                targets['observed_request_processing'] = traffic.get('requests_observed') is True
                targets['inspection_applied_to_requests_verified'] = traffic.get('requests_observed') is True
                if targets.get('state') == 'independent_target_observed':
                    # Independently observed target *existence*, not ALB->WAF
                    # attachment nor proof that any request is inspected.
                    targets['independent_target_existence_confirmed'] = True
                    targets['association_evidence_source'] = 'wafv2_associations_only'
                    changes['waf_association_target_conflicts'] += 1
    return changes


def reconcile_m10q_deep(services, selected, account_id):
    """One enrichment pass after the existing four primary correlations."""
    return {
        'version': 2,
        's3_advanced': reconcile_s3_advanced(services, selected, account_id),
        's3_backup_plans': enrich_backup_relationships(services, selected),
        'inspector_waf': enrich_inspector_and_waf(services, selected, account_id),
        'no_additional_api_calls': True,
    }
