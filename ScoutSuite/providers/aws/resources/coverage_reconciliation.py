"""M10-Q: correlate already collected AWS inventories without SDK access.

An absent record is an evidence gap, not proof that a resource is eligible,
unprotected, or noncompliant. This module never mutates source inventories
other than additive, versioned annotations on the observed resources.
"""
from datetime import datetime, timezone
from fnmatch import fnmatchcase

from ScoutSuite.core.run_context import get_current_run_context

_VERSION = 1
_EC2 = 'AWS_EC2_INSTANCE'
_ECR = 'AWS_ECR_REPOSITORY'


def _issue(scope, reason):
    context = get_current_run_context()
    if context is not None:
        context.record_collection_issue('partial', scope, 'M10Q:' + reason)


def _regions(services, name, selected):
    if name not in selected:
        return None
    obj = services.get(name)
    if not isinstance(obj, dict) or not isinstance(obj.get('regions'), dict):
        return None
    return obj['regions']


def _source(services, name, selected):
    return services.get(name) if name in selected and isinstance(
        services.get(name), dict) else None


def _values(dictionary):
    return dictionary.values() if isinstance(dictionary, dict) else ()


def _timestamp(value):
    if isinstance(value, datetime):
        date = value
    elif isinstance(value, str):
        try:
            date = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return None
    else:
        return None
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return date.astimezone(timezone.utc)


def _inspector_evidence(inspector_regions, region, resource_type, ids, account_id):
    evidence = {'state': 'unknown', 'source': 'inspector2.ListCoverage',
                'coverage_record_ids': [], 'scan_types': [],
                'reasons': [], 'independent_scan_execution_verified': False}
    if (inspector_regions is None or region not in inspector_regions
            or not isinstance(inspector_regions[region], dict)):
        evidence['reasons'].append('inspector_region_not_collected')
        return evidence
    region_data = inspector_regions[region]
    summary = region_data.get('coverage_summary')
    if not isinstance(summary, dict) or summary.get('status') != 'complete':
        evidence['reasons'].append('inspector_coverage_census_incomplete')
        return evidence
    if (not isinstance(account_id, str) or len(account_id) != 12
            or not account_id.isascii() or not account_id.isdigit()):
        evidence['reasons'].append('account_scope_unverified')
        return evidence
    coverage = region_data.get('coverage')
    if not isinstance(coverage, dict):
        evidence['reasons'].append('inspector_coverage_records_missing')
        return evidence
    matched = []
    foreign = False
    for row in coverage.values():
        if not isinstance(row, dict):
            evidence['reasons'].append('malformed_inspector_record')
            return evidence
        if row.get('resource_type') != resource_type or row.get('resource_id') not in ids:
            continue
        if row.get('account_id') != account_id:
            foreign = True
            continue
        matched.append(row)
    if not matched:
        if foreign:
            evidence['reasons'].append('foreign_account_resource_match_only')
            return evidence
        evidence['state'] = 'not_reported'
        evidence['reasons'].append('resource_absent_from_complete_inspector_list')
        return evidence
    statuses = {row.get('scan_status') for row in matched}
    evidence['coverage_record_ids'] = sorted({
        row['id'] for row in matched if isinstance(row.get('id'), str)})
    evidence['scan_types'] = sorted({
        row['scan_type'] for row in matched if isinstance(row.get('scan_type'), str)})
    if statuses == {'ACTIVE'}:
        evidence['state'] = 'active_observed'
        evidence['reasons'].append('active_inspector_coverage_record_observed')
    elif statuses == {'INACTIVE'}:
        evidence['state'] = 'inactive_reported'
        evidence['reasons'].append('inspector_reports_inactive_scan')
    elif statuses <= {'ACTIVE', 'INACTIVE'} and len(statuses) > 1:
        evidence['state'] = 'mixed_reported'
        evidence['reasons'].append('mixed_active_and_inactive_scan_types')
    else:
        evidence['reasons'].append('unknown_inspector_scan_status')
    # ACTIVE confirms enrollment/status, not a successful execution time.
    return evidence


def _ec2(services, selected, inspector, account_id):
    regions = _regions(services, 'ec2', selected)
    if regions is None:
        return 0
    total = 0
    for region, region_data in regions.items():
        if not isinstance(region_data, dict):
            _issue('ec2', 'MalformedEC2Region')
            continue
        for vpc in _values(region_data.get('vpcs')):
            if not isinstance(vpc, dict):
                continue
            for instance in _values(vpc.get('instances')):
                if not isinstance(instance, dict):
                    continue
                iid = instance.get('id')
                if not isinstance(iid, str) or not iid.startswith('i-'):
                    _issue('ec2', 'EC2InstanceIdentityUnknown')
                    continue
                state = instance.get('State', {})
                state_name = (state.get('Name') if isinstance(state, dict)
                              else state if isinstance(state, str) else None)
                evidence = _inspector_evidence(inspector, region, _EC2, (iid,), account_id)
                if state_name in ('terminated', 'shutting-down'):
                    evidence['state'] = 'not_applicable'
                    evidence['reasons'] = ['instance_terminated']
                instance['m10q_inspector'] = evidence
                instance['m10q_inspector_not_reported'] = evidence['state'] == 'not_reported'
                total += 1
    return total


def _enhanced_rules_match(registry_record, repository_name):
    rules = registry_record.get('rules')
    if not isinstance(rules, list):
        return None
    # Empty rule lists and unknown filter types are ambiguous under
    # version-dependent ECR defaults. Never infer a disabled scan.
    if not rules:
        return None
    candidate = False
    for rule in rules:
        if not isinstance(rule, dict):
            return None
        filters = rule.get('repositoryFilters')
        if not isinstance(filters, list) or not filters:
            return None
        for item in filters:
            if not isinstance(item, dict) or item.get('filterType') != 'WILDCARD':
                return None
            pattern = item.get('filter')
            if not isinstance(pattern, str):
                return None
            if fnmatchcase(repository_name, pattern):
                candidate = True
    return candidate


def _ecr(services, selected, inspector, account_id):
    regions = _regions(services, 'ecr', selected)
    if regions is None:
        return 0
    total = 0
    for region, region_data in regions.items():
        if not isinstance(region_data, dict):
            _issue('ecr', 'MalformedECRRegion')
            continue
        config = list(_values(region_data.get('registry_scanning')))
        for repository in _values(region_data.get('repositories')):
            if not isinstance(repository, dict):
                continue
            arn = repository.get('repository_arn')
            name = repository.get('repository_name')
            if not isinstance(arn, str) or not isinstance(name, str):
                _issue('ecr', 'RepositoryIdentityUnknown')
                continue
            ids = (arn, name)  # Inspector response model may use either.
            inspector_evidence = _inspector_evidence(
                inspector, region, _ECR, ids, account_id)
            scanning = {'status': 'unknown', 'mode': None,
                        'scan_on_push': None, 'enhanced_rule_match': None}
            if len(config) == 1 and isinstance(config[0], dict):
                cfg = config[0]
                if cfg.get('registry_id') == account_id:
                    scanning['mode'] = cfg.get('scan_type')
                    if cfg.get('scan_type') == 'ENHANCED':
                        matching = _enhanced_rules_match(cfg, name)
                        scanning['enhanced_rule_match'] = matching
                        scanning['status'] = ('configured_candidate' if matching is True
                                              else 'not_matched' if matching is False
                                              else 'unknown')
                    elif cfg.get('scan_type') == 'BASIC':
                        push = (repository.get('image_scanning_configuration') or {}).get('scanOnPush')
                        if isinstance(push, bool):
                            scanning['scan_on_push'] = push
                            scanning['status'] = 'scan_on_push' if push else 'not_scan_on_push'
            repository['m10q_inspector'] = inspector_evidence
            operational = repository.get('operational_image_scans')
            observed = isinstance(operational, dict)
            repository['m10q_image_scanning'] = {
                **scanning,
                'image_level_scan_execution_verified': bool(observed and operational.get('image_level_scan_execution_verified')),
                'image_inventory_available': bool(observed and operational.get('census_complete')),
                'status': operational.get('status', 'unverified') if observed else 'unverified',
                'inspector_enrollment': inspector_evidence['state'],
                'reason': 'per_image_api_evidence' if observed else 'no_image_level_scan_results_collected',
                'operational_evidence': operational if observed else None,
            }
            # Report a specific gap, without claiming images exist or are unscanned.
            repo_gap = (inspector_evidence['state'] in ('not_reported', 'inactive_reported')
                        and scanning['status'] in ('not_scan_on_push', 'not_matched'))
            repository['m10q_repository_scan_gap_candidate'] = repo_gap
            total += 1
    return total


def _backup(services, selected):
    regions = _regions(services, 'backup', selected)
    return regions


def _s3(services, selected, backup_regions):
    s3 = _source(services, 's3', selected)
    if s3 is None or not isinstance(s3.get('buckets'), dict):
        return 0
    total = 0
    for bucket in s3['buckets'].values():
        if not isinstance(bucket, dict):
            continue
        original_arn, region = bucket.get('arn'), bucket.get('region')
        name = bucket.get('name')
        # S3 bucket ARNs have no region/account/resource-type component.
        # Legacy bucket["arn"] may be formatted as arn:...:s3:::*/name;
        # do not mutate it: canonicalize only this correlation identity.
        partition = (original_arn.split(':', 2)[1]
                     if isinstance(original_arn, str)
                     and original_arn.startswith('arn:') else None)
        arn = (f'arn:{partition}:s3:::{name}'
               if isinstance(partition, str) and partition
               and isinstance(name, str) and name else None)
        evidence = {'state': 'unknown', 'source': 'backup.ListProtectedResources',
                    'region': region, 'canonical_bucket_arn': arn,
                    'recovery_point_arns': [],
                    'completed_job_ids': [], 'last_completed_job_at': None,
                    'ongoing_schedule_verified': False, 'reasons': []}
        if not isinstance(arn, str) or not arn.startswith('arn:'):
            evidence['reasons'].append('s3_bucket_identity_unknown')
        elif not isinstance(region, str) or not region:
            evidence['reasons'].append('bucket_region_unknown')
        elif backup_regions is None or not isinstance(backup_regions.get(region), dict):
            evidence['reasons'].append('backup_region_not_collected')
        else:
            inventory = backup_regions[region]
            status = inventory.get('backup_inventory_status', {})
            protected = inventory.get('protected_resources')
            jobs = inventory.get('backup_jobs')
            protected_complete = (isinstance(status, dict)
                                  and status.get('protected_resources') == 'complete'
                                  and isinstance(protected, dict))
            jobs_complete = (isinstance(status, dict)
                             and status.get('backup_jobs') == 'complete'
                             and isinstance(jobs, dict))
            if not protected_complete or not jobs_complete:
                evidence['reasons'].append('backup_inventory_incomplete')
            else:
                matches = [item for item in protected.values()
                           if isinstance(item, dict) and item.get('ResourceArn') == arn]
                done = [item for item in jobs.values()
                        if isinstance(item, dict) and item.get('ResourceArn') == arn
                        and item.get('State') == 'COMPLETED']
                evidence['recovery_point_arns'] = sorted({
                    x['ResourceArn'] for x in matches})
                evidence['completed_job_ids'] = sorted({
                    x['BackupJobId'] for x in done if isinstance(
                        x.get('BackupJobId'), str)})
                timestamps = [_timestamp(job.get('CompletionDate')) for job in done]
                timestamps = [t for t in timestamps if t is not None]
                if timestamps:
                    evidence['last_completed_job_at'] = max(timestamps).isoformat()
                if not matches and not done:
                    evidence['state'] = 'not_reported'
                    evidence['reasons'].append('no_protected_resource_or_completed_job_reported')
                elif matches and done:
                    evidence['state'] = 'recovery_and_job_observed'
                    evidence['reasons'].append('recovery_point_and_completed_job_observed')
                else:
                    evidence['state'] = 'partial_evidence'
                    evidence['reasons'].append('backup_job_or_recovery_point_not_correlated')
        operational = backup_regions.get(region, {}).get('operational_rpo', {}) if isinstance(backup_regions, dict) and isinstance(region, str) else {}
        evidence['operational_rpo'] = operational.get('resources', {}).get(arn) if isinstance(operational, dict) and arn else None
        bucket['m10q_backup'] = evidence
        bucket['m10q_backup_evidence_gap'] = evidence['state'] in (
            'not_reported', 'partial_evidence')
        total += 1
    return total


def _target_inventory(services, selected):
    """Independent target ARNs only; missing sources cannot prove WAF unused."""
    resources = {}
    elb_regions = _regions(services, 'elbv2', selected)
    if elb_regions is not None:
        for region, entry in elb_regions.items():
            for vpc in _values(entry.get('vpcs') if isinstance(entry, dict) else None):
                for lb in _values(vpc.get('lbs') if isinstance(vpc, dict) else None):
                    if isinstance(lb, dict) and lb.get('Type') == 'application' and isinstance(
                            lb.get('arn'), str):
                        resources[lb['arn']] = ('ALB', region)
    cloudfront = _source(services, 'cloudfront', selected)
    if cloudfront is not None:
        for distribution in _values(cloudfront.get('distributions')):
            if isinstance(distribution, dict) and isinstance(distribution.get('arn'), str):
                resources[distribution['arn']] = (
                    'CLOUDFRONT', distribution.get('web_acl_id'))
    return resources


def _waf(services, selected):
    regions = _regions(services, 'wafv2', selected)
    if regions is None:
        return 0
    targets = _target_inventory(services, selected)
    total = 0
    for region, region_data in regions.items():
        for acl in _values(region_data.get('web_acls') if isinstance(
                region_data, dict) else None):
            if not isinstance(acl, dict):
                continue
            associations = acl.get('associated_resources')
            associated = (associations if isinstance(associations, list) else [])
            observed = []
            for item in associated:
                arn = item.get('resource_arn') if isinstance(item, dict) else None
                if not isinstance(arn, str) or arn not in targets:
                    continue
                resource_type, constraint = targets[arn]
                if resource_type == 'ALB' and constraint == region:
                    observed.append(arn)
                if resource_type == 'CLOUDFRONT' and constraint == acl.get('web_acl_arn'):
                    observed.append(arn)
            status = acl.get('association_status')
            if observed:
                state = 'independent_target_observed'
            elif status == 'associated' and associated:
                state = 'waf_association_only'
            elif status == 'unused_candidate' and acl.get('association_scope_complete') is True:
                state = 'no_supported_association_observed'
            else:
                state = 'unknown'
            traffic = acl.get('operational_traffic') or {}
            acl['m10q_protected_targets'] = {
                'state': state, 'verified_resource_arns': sorted(set(observed)),
                'waf_association_arns': sorted({
                    item['resource_arn'] for item in associated
                    if isinstance(item, dict) and isinstance(
                        item.get('resource_arn'), str)}),
                'independent_target_inventory_selected': {
                    'alb': 'elbv2' in selected,
                    'cloudfront': 'cloudfront' in selected,
                    'api_gateway': False,
                },
                'traffic_routing_through_waf_verified': False,
                'observed_request_processing': traffic.get('requests_observed') is True,
                'request_processing_evidence_status': traffic.get('status', 'unknown'),
                'scope_note': ('API Gateway resources have no independent inventory. '
                               'A WAF association is not evidence of request traffic.'),
            }
            total += 1
    return total


def reconcile_m10q_coverage(services, selected_services, account_id=None):
    """Add cross-service observations; selected-only and local-replay safe."""
    if not isinstance(services, dict):
        return None
    selected = set(selected_services or ())
    inspector = _regions(services, 'inspector2', selected)
    backup = _backup(services, selected)
    summary = {
        'version': _VERSION,
        'mode': 'report_postprocessing_only',
        'api_calls': 0,
        'selected_sources': sorted(selected & {
            'ec2', 'inspector2', 'ecr', 's3', 'backup', 'wafv2', 'elbv2', 'cloudfront'}),
        'resource_counts': {},
        'negative_findings_are_evidence_gaps_not_proof_of_unprotected_resource': True,
        'image_level_scans_verified': False,
        'backup_schedule_verified': False,
        'waf_request_traffic_verified': False,
    }
    summary['resource_counts']['ec2_inspector'] = _ec2(
        services, selected, inspector, account_id)
    summary['resource_counts']['ecr_scanning'] = _ecr(
        services, selected, inspector, account_id)
    summary['resource_counts']['s3_backup'] = _s3(services, selected, backup)
    summary['resource_counts']['waf_targets'] = _waf(services, selected)
    # Summary is additive metadata attached to services already included in
    # the report; do not create a pseudo AWS SDK service.
    for name in ('inspector2', 'ecr', 's3', 'wafv2'):
        source = _source(services, name, selected)
        if source is not None:
            source['m10q_reconciliation'] = summary
    from ScoutSuite.providers.aws.resources.coverage_reconciliation_deep import (
        reconcile_m10q_deep)
    summary['deep'] = reconcile_m10q_deep(services, selected, account_id)
    summary['version'] = 2
    return summary
