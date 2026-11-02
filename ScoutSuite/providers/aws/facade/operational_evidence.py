"""M10-Q operational evidence. Read-only; no image contents, vulnerabilities or WAF request data."""
import os
from datetime import datetime, timedelta, timezone

from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently

ECR_PAGE = 100
ECR_MAX_PAGES = 100
BACKUP_PAGE = 100
BACKUP_MAX_PAGES = 100
BACKUP_MAX_RESOURCES = 10000
WAF_METRICS = ('AllowedRequests', 'BlockedRequests', 'CountedRequests',
               'CaptchaRequests', 'ChallengeRequests')


def _date(value):
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (float, int)) and not isinstance(value, bool):
        try:
            dt = datetime.fromtimestamp(value, timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return None
    else:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _failure(facade, operation, error):
    # Expose stable reason codes, not exception messages containing account data.
    if hasattr(facade, 'failure'):
        facade.failure(operation, error, partial=True)
    else:
        facade.issue('partial', operation + 'Failed')


async def collect_ecr_images(facade, region, repo_name):
    """Account-scoped digest census and per-image DescribeImageScanFindings."""
    result = {'source': 'ecr.DescribeImages+DescribeImageScanFindings',
              'status': 'unknown', 'census_complete': False, 'images': {},
              'total_images': 0, 'verified_images': 0, 'unverified_images': 0,
              'image_level_scan_execution_verified': False, 'reasons': []}
    client = AWSFacadeUtils.get_client('ecr', facade.session, region)
    if client is None:
        result['reasons'].append('client_unavailable')
        return result
    account = facade.owner_id
    images, seen, tokens = [], set(), set()
    token = None
    for _ in range(ECR_MAX_PAGES):
        params = {'registryId': account, 'repositoryName': repo_name, 'maxResults': ECR_PAGE}
        if token is not None:
            params['nextToken'] = token
        try:
            response = await run_concurrently(lambda params=params: client.describe_images(**params))
        except Exception as exc:
            _failure(facade, 'DescribeImages', exc)
            result['reasons'].append('describe_images_failed')
            break
        rows = response.get('imageDetails') if isinstance(response, dict) else None
        if not isinstance(rows, list) or len(rows) > ECR_PAGE:
            facade.issue('partial', 'MalformedImageCensus')
            result['reasons'].append('malformed_image_census')
            break
        valid = True
        for row in rows:
            digest = row.get('imageDigest') if isinstance(row, dict) else None
            if (not isinstance(digest, str) or not digest.startswith('sha256:')
                    or digest in seen):
                valid = False
                continue
            seen.add(digest)
            images.append(row)
        if not valid:
            facade.issue('partial', 'InvalidImageDigest')
            result['reasons'].append('invalid_or_duplicate_image')
        following = response.get('nextToken')
        if following in (None, ''):
            result['census_complete'] = valid and not result['reasons']
            break
        if not isinstance(following, str) or following in tokens or len(following) > 4096:
            result['reasons'].append('invalid_image_pagination')
            facade.issue('partial', 'InvalidImagePagination')
            break
        tokens.add(following)
        token = following
    else:
        facade.issue('partial', 'ImagePageLimit')
        result['reasons'].append('image_page_limit')
    result['total_images'] = len(images)
    for row in images:
        digest = row['imageDigest']
        record = {'digest': digest, 'tags': row.get('imageTags') or [],
                  'pushed_at': _date(row.get('imagePushedAt')).isoformat()
                  if _date(row.get('imagePushedAt')) else None,
                  'scan_status': None, 'last_scan_completed_at': None,
                  'state': 'unknown', 'reason': 'scan_result_unavailable'}
        if row.get('imageStatus') == 'ARCHIVED':
            record.update(state='not_applicable', reason='archived_image')
        else:
            try:
                scan = await run_concurrently(
                    lambda digest=digest: client.describe_image_scan_findings(
                        registryId=account, repositoryName=repo_name,
                        imageId={'imageDigest': digest}, maxResults=1))
                if (not isinstance(scan, dict) or scan.get('registryId') != account
                        or scan.get('repositoryName') != repo_name
                        or scan.get('imageId', {}).get('imageDigest') != digest):
                    record['reason'] = 'scan_identity_mismatch'
                else:
                    status = (scan.get('imageScanStatus') or {}).get('status')
                    findings = scan.get('imageScanFindings') or {}
                    scanned = _date(findings.get('imageScanCompletedAt'))
                    pushed = _date(row.get('imagePushedAt'))
                    record['scan_status'] = status
                    record['last_scan_completed_at'] = scanned.isoformat() if scanned else None
                    if status in ('COMPLETE', 'ACTIVE') and scanned and (
                            pushed is None or scanned >= pushed - timedelta(minutes=5)):
                        record.update(state='verified', reason='successful_scan_timestamp_observed')
                    elif status in ('FAILED', 'UNSUPPORTED_IMAGE', 'SCAN_ELIGIBILITY_EXPIRED',
                                    'FINDINGS_UNAVAILABLE', 'LIMIT_EXCEEDED'):
                        record.update(state='not_scanned', reason='scan_failure_or_ineligible')
                    else:
                        record['reason'] = 'no_completed_scan_evidence'
            except Exception as exc:
                _failure(facade, 'DescribeImageScanFindings', exc)
                record['reason'] = 'scan_api_failed'
        result['images'][digest] = record
    applicable = [x for x in result['images'].values() if x['state'] != 'not_applicable']
    result['verified_images'] = sum(x['state'] == 'verified' for x in applicable)
    result['unverified_images'] = len(applicable) - result['verified_images']
    if result['census_complete'] and applicable and result['unverified_images'] == 0:
        result['status'] = 'verified'
        result['image_level_scan_execution_verified'] = True
    elif result['census_complete'] and any(x['state'] == 'not_scanned' for x in applicable):
        result['status'] = 'gap_observed'
    elif result['census_complete'] and not applicable:
        result['status'] = 'not_applicable'
    else:
        result['status'] = 'unknown'
    return result


async def collect_waf_traffic(facade, region, acl):
    """CloudWatch aggregates prove observed WAF decisions, not end-to-end routing."""
    visible = acl.get('visibility_config') or {}
    scope = acl.get('scope')
    result = {'source': 'cloudwatch.GetMetricData(AWS/WAFV2)', 'status': 'unknown',
              'requests_observed': False, 'completeness': 'unknown',
              'metrics': {}, 'reasons': [], 'window_start': None, 'window_end': None}
    if visible.get('CloudWatchMetricsEnabled') is not True or not visible.get('MetricName'):
        result['reasons'].append('web_acl_cloudwatch_metrics_not_confirmed')
        return result
    metric_region = 'us-east-1' if scope == 'CLOUDFRONT' else region
    client = AWSFacadeUtils.get_client('cloudwatch', facade.session, metric_region)
    if client is None:
        result['reasons'].append('cloudwatch_client_unavailable')
        return result
    end = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=15)
    start = end - timedelta(hours=1)
    result['window_start'], result['window_end'] = start.isoformat(), end.isoformat()
    dimensions = [{'Name': 'WebACL', 'Value': visible['MetricName']},
                  {'Name': 'Rule', 'Value': 'ALL'}]
    if scope == 'REGIONAL':
        dimensions.append({'Name': 'Region', 'Value': region})
    queries = [{'Id': 'm' + str(i),
                'MetricStat': {'Metric': {'Namespace': 'AWS/WAFV2', 'MetricName': name,
                                          'Dimensions': dimensions},
                               'Period': 300, 'Stat': 'Sum'}, 'ReturnData': True}
               for i, name in enumerate(WAF_METRICS)]
    try:
        response = await run_concurrently(
            lambda: client.get_metric_data(MetricDataQueries=queries,
                                           StartTime=start, EndTime=end,
                                           ScanBy='TimestampDescending',
                                           MaxDatapoints=1000))
    except Exception as exc:
        _failure(facade, 'GetWAFCloudWatchMetrics', exc)
        result['reasons'].append('cloudwatch_query_failed')
        return result
    series = response.get('MetricDataResults') if isinstance(response, dict) else None
    if not isinstance(series, list) or response.get('NextToken'):
        result['reasons'].append('metric_response_incomplete')
        return result
    by_id = {item.get('Id'): item for item in series if isinstance(item, dict)}
    complete = True
    for i, name in enumerate(WAF_METRICS):
        row = by_id.get('m' + str(i), {})
        values = row.get('Values')
        if (row.get('StatusCode') != 'Complete' or not isinstance(values, list)
                or any(not isinstance(x, (int, float)) or isinstance(x, bool)
                       or x < 0 or x != x for x in values)):
            complete = False
            continue
        result['metrics'][name] = sum(values)
    result['completeness'] = 'complete' if complete else 'partial'
    result['requests_observed'] = any(v > 0 for v in result['metrics'].values())
    result['status'] = ('observed' if result['requests_observed'] and complete
                        else 'observed_partial' if result['requests_observed']
                        else 'unknown')
    if not result['requests_observed']:
        result['reasons'].append('no_nonzero_waf_metrics_observed')
    if not complete:
        result['reasons'].append('metric_series_incomplete')
    return result


def configured_rpo_minutes():
    """Explicit audit objective, never infer RPO from backup cron cadence."""
    raw = os.environ.get('SCOUTSUITE_BACKUP_RPO_MINUTES')
    if raw is None:
        return None
    try:
        value = int(raw)
    except (ValueError, TypeError):
        return None
    return value if 1 <= value <= 43200 else None


async def collect_backup_rpo(facade, region, arns, jobs):
    """Recovery point snapshots + 30-day job evidence. Scope is the observed window."""
    rpo = configured_rpo_minutes()
    output = {'source': 'backup.ListRecoveryPointsByResource+ListBackupJobs',
              'configured_rpo_minutes': rpo, 'resources': {},
              'status': 'unknown', 'continuous_compliance_verified': False,
              'history_scope': 'observed_recovery_points_and_30_day_job_history'}
    client = AWSFacadeUtils.get_client('backup', facade.session, region)
    if client is None:
        facade.issue('partial', 'RecoveryPointsClientUnavailable')
        return output
    if len(arns) > BACKUP_MAX_RESOURCES:
        facade.issue('partial', 'RPOResourceLimit')
    for arn in sorted(arns)[:BACKUP_MAX_RESOURCES]:
        entry = {'resource_arn': arn, 'state': 'unknown', 'recovery_points': [],
                 'latest_available_point_at': None, 'age_minutes': None,
                 'max_observed_gap_minutes': None, 'reasons': []}
        token, tokens, complete = None, set(), False
        for _ in range(BACKUP_MAX_PAGES):
            params = {'ResourceArn': arn, 'MaxResults': BACKUP_PAGE}
            if token is not None:
                params['NextToken'] = token
            try:
                page = await run_concurrently(lambda params=params:
                                              client.list_recovery_points_by_resource(**params))
            except Exception as exc:
                _failure(facade, 'ListRecoveryPointsByResource', exc)
                entry['reasons'].append('recovery_points_query_failed')
                break
            rows = page.get('RecoveryPoints') if isinstance(page, dict) else None
            if not isinstance(rows, list) or len(rows) > BACKUP_PAGE:
                entry['reasons'].append('malformed_recovery_points')
                break
            for row in rows:
                if not isinstance(row, dict) or not isinstance(row.get('RecoveryPointArn'), str):
                    entry['reasons'].append('malformed_recovery_point')
                    continue
                created = _date(row.get('CreationDate'))
                entry['recovery_points'].append({
                    'arn': row['RecoveryPointArn'], 'status': row.get('Status'),
                    'creation_date': created.isoformat() if created else None,
                    'vault_name': row.get('BackupVaultName')})
            following = page.get('NextToken')
            if following in (None, ''):
                complete = not entry['reasons']
                break
            if not isinstance(following, str) or following in tokens or len(following) > 4096:
                entry['reasons'].append('recovery_point_pagination')
                break
            tokens.add(following)
            token = following
        else:
            entry['reasons'].append('recovery_point_page_limit')
        points = sorted((d for d in (_date(p['creation_date']) for p in entry['recovery_points']
                                   if p['status'] in ('AVAILABLE', 'COMPLETED'))
                         if d is not None))
        if points:
            entry['latest_available_point_at'] = points[-1].isoformat()
            entry['age_minutes'] = round((datetime.now(timezone.utc) - points[-1]).total_seconds() / 60, 2)
            if len(points) > 1:
                entry['max_observed_gap_minutes'] = round(max(
                    (b-a).total_seconds() / 60 for a,b in zip(points,points[1:])), 2)
        failures = [j.get('BackupJobId') for j in jobs
                    if isinstance(j, dict) and j.get('ResourceArn') == arn
                    and j.get('State') in ('FAILED', 'ABORTED', 'EXPIRED')]
        entry['failed_job_ids'] = [v for v in failures if isinstance(v, str)]
        entry['census_complete'] = complete
        dated_points = [(when, p) for p in entry['recovery_points']
                        if (when := _date(p.get('creation_date'))) is not None]
        latest_record = max(dated_points, key=lambda pair: pair[0])[1] if dated_points else None
        if complete and latest_record is not None and latest_record['status'] == 'STOPPED':
            entry['state'] = 'gap_observed'
            entry['reasons'].append('continuous_recovery_point_stopped')
        elif rpo is None:
            entry['reasons'].append('rpo_objective_not_configured')
        elif not complete:
            entry['reasons'].append('recovery_point_history_incomplete')
        elif entry['age_minutes'] is not None and entry['age_minutes'] > rpo:
            entry['state'] = 'rpo_review_candidate'
            entry['reasons'].append('last_snapshot_timestamp_exceeds_rpo_pitr_not_excluded')
        elif entry['max_observed_gap_minutes'] is not None and entry['max_observed_gap_minutes'] > rpo:
            entry['state'] = 'rpo_review_candidate'
            entry['reasons'].append('snapshot_interval_exceeds_rpo_pitr_not_excluded')
        elif entry['age_minutes'] is not None and entry['age_minutes'] <= rpo:
            # PITR creation dates and historic gap cannot confirm ongoing RPO.
            entry['state'] = 'fresh_point_observed'
        output['resources'][arn] = entry
    if len(arns) > BACKUP_MAX_RESOURCES or any(
            not row['census_complete'] for row in output['resources'].values()):
        output['status'] = 'partial'
    elif any(x['state'] == 'gap_observed' for x in output['resources'].values()):
        output['status'] = 'gap_observed'
    elif any(x['state'] == 'rpo_review_candidate' for x in output['resources'].values()):
        output['status'] = 'review_required'
    else:
        output['status'] = 'observed_only' if output['resources'] else 'not_applicable'
    return output
