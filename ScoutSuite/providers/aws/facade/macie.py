"""M10-P: bounded read-only Amazon Macie configuration and S3 coverage.

Never call GetFindings, GetSensitiveDataOccurrences, S3 GetObject or read
classification-result repositories. All records are metadata-only.
"""
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently

PAGE_SIZE = 100
MAX_PAGES = 500
MAX_ITEMS = 50000
STALE_DAYS = 45
DENIED = {'AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation'}
UNSUPPORTED = {'UnsupportedOperationException', 'UnknownOperationException'}


def date(value):
    return value.isoformat() if isinstance(value, datetime) else value


def parse_date(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            return None
    return None


def age_days(value, now=None):
    parsed = parse_date(value)
    if parsed is None:
        return None
    now = now or datetime.now(timezone.utc)
    return max(0, (now - parsed).total_seconds() / 86400)


def is_macie_session_not_enabled(error):
    """Classify only explicit Macie-disabled responses, not generic IAM denials.

    Macie can return AccessDeniedException with the message "Macie is not
    enabled." for a disabled regional account. An AccessDeniedException without
    that exact service-state message remains UNKNOWN/denied.
    """
    if not isinstance(error, ClientError):
        return False
    details = error.response.get('Error', {})
    code = details.get('Code')
    if code == 'ResourceNotFoundException':
        return True
    if code != 'AccessDeniedException':
        return False
    message = details.get('Message', '')
    if not isinstance(message, str):
        return False
    normalized = ' '.join(message.split()).strip().rstrip('.').casefold()
    return normalized in (
        'macie is not enabled',
        'amazon macie is not enabled',
        "macie isn't enabled",
        "amazon macie isn't enabled",
    )


class PageRows(list):
    def __init__(self, iterable=()):
        super().__init__(iterable)
        self.complete = True


class MacieFacade(AWSBaseFacade):
    """Macie regional inventory without any sensitive data findings."""

    def issue(self, status, reason):
        ctx = get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue(status, 'macie', reason)

    def failure(self, operation, error):
        if isinstance(error, ClientError):
            code = error.response.get('Error', {}).get('Code', '')
            status = 'denied' if code in DENIED else (
                'unsupported' if code in UNSUPPORTED else 'failed')
            self.issue(status, operation + status.capitalize())
        else:
            self.issue('failed', operation + 'Failed')

    async def _pages(self, call, key, operation):
        result, token, seen = PageRows(), None, set()
        for _ in range(MAX_PAGES):
            params = {'maxResults': PAGE_SIZE}
            if token is not None:
                params['nextToken'] = token
            try:
                response = await run_concurrently(lambda params=params: call(**params))
            except Exception as error:
                self.failure(operation, error)
                result.complete = False
                break
            if not isinstance(response, dict) or not isinstance(response.get(key), list):
                self.issue('partial', operation + 'MalformedPage')
                result.complete = False
                break
            batch = response[key]
            if len(batch) > PAGE_SIZE or any(not isinstance(item, dict) for item in batch):
                self.issue('partial', operation + 'MalformedPage')
                result.complete = False
                break
            if len(result) + len(batch) > MAX_ITEMS:
                result.extend(batch[:MAX_ITEMS - len(result)])
                self.issue('partial', operation + 'ItemLimit')
                result.complete = False
                break
            result.extend(batch)
            next_token = response.get('nextToken')
            if next_token in (None, ''):
                break
            if (not isinstance(next_token, str) or len(next_token) > 4096
                    or next_token in seen):
                self.issue('partial', operation + 'InvalidPaginationToken')
                result.complete = False
                break
            seen.add(next_token)
            token = next_token
        else:
            self.issue('partial', operation + 'PageLimit')
            result.complete = False
        return result

    async def get_region(self, region):
        result = {
            'session_status': 'UNKNOWN', 'session_verified': False,
            'automated_discovery_status': 'UNKNOWN',
            'automated_discovery_verified': False,
            'classification_scope_id': None, 'excluded_bucket_names': [],
            'jobs': [], 'jobs_complete': False,
            'buckets': [], 'buckets_complete': False,
        }
        client = AWSFacadeUtils.get_client('macie2', self.session, region)
        if client is None:
            self.issue('failed', 'ClientConstruction')
            return result
        try:
            session = await run_concurrently(client.get_macie_session)
        except ClientError as error:
            if is_macie_session_not_enabled(error):
                result['session_status'] = 'NOT_ENABLED'
                result['session_verified'] = True
                return result
            self.failure('GetMacieSession', error)
            return result
        except Exception as error:
            self.failure('GetMacieSession', error)
            return result
        if not isinstance(session, dict) or session.get('status') not in ('ENABLED', 'PAUSED'):
            self.issue('partial', 'MalformedMacieSession')
            return result

        result.update({
            'session_status': session['status'], 'session_verified': True,
            'session_created_at': date(session.get('createdAt')),
            'session_updated_at': date(session.get('updatedAt')),
            'service_role': session.get('serviceRole'),
        })
        if session['status'] != 'ENABLED':
            return result

        try:
            automated = await run_concurrently(client.get_automated_discovery_configuration)
            if not isinstance(automated, dict) or automated.get('status') not in ('ENABLED', 'DISABLED'):
                self.issue('partial', 'MalformedAutomatedDiscoveryConfig')
            else:
                result['automated_discovery_status'] = automated['status']
                result['automated_discovery_verified'] = True
                result['classification_scope_id'] = automated.get('classificationScopeId')
                result['automated_discovery_updated_at'] = date(automated.get('lastUpdatedAt'))
                result['auto_enable_org_members'] = automated.get('autoEnableOrganizationMembers')
        except Exception as error:
            self.failure('GetAutomatedDiscoveryConfiguration', error)

        scope_id = result['classification_scope_id']
        if isinstance(scope_id, str) and scope_id:
            try:
                scope = await run_concurrently(lambda: client.get_classification_scope(id=scope_id))
                if (not isinstance(scope, dict) or scope.get('id') != scope_id
                        or not isinstance(scope.get('s3'), dict)):
                    self.issue('partial', 'MalformedClassificationScope')
                else:
                    excludes = scope['s3'].get('excludes', {})
                    bucket_names = excludes.get('bucketNames', []) if isinstance(excludes, dict) else []
                    if isinstance(bucket_names, list) and all(isinstance(x, str) for x in bucket_names):
                        result['excluded_bucket_names'] = bucket_names
                    else:
                        self.issue('partial', 'MalformedClassificationScopeExclusions')
            except Exception as error:
                self.failure('GetClassificationScope', error)

        summaries = await self._pages(
            client.list_classification_jobs, 'items', 'ListClassificationJobs')
        result['jobs_complete'] = summaries.complete
        job_ids = set()
        for summary in summaries:
            job_id = summary.get('jobId')
            if not isinstance(job_id, str) or not job_id or job_id in job_ids:
                self.issue('partial', 'InvalidOrDuplicateJobId')
                result['jobs_complete'] = False
                continue
            job_ids.add(job_id)
            try:
                detail = await run_concurrently(
                    lambda job_id=job_id: client.describe_classification_job(jobId=job_id))
            except Exception as error:
                self.failure('DescribeClassificationJob', error)
                result['jobs_complete'] = False
                continue
            if not isinstance(detail, dict) or detail.get('jobId') != job_id:
                self.issue('partial', 'MismatchedClassificationJob')
                result['jobs_complete'] = False
                continue
            result['jobs'].append({
                'job_id': job_id, 'job_arn': detail.get('jobArn'),
                'name': detail.get('name') or summary.get('name') or job_id,
                'status': detail.get('jobStatus'), 'type': detail.get('jobType'),
                'created_at': date(detail.get('createdAt')),
                'last_run_at': date(detail.get('lastRunTime')),
                'last_run_error': (detail.get('lastRunErrorStatus') or {}).get('code')
                if isinstance(detail.get('lastRunErrorStatus') or {}, dict) else None,
                'schedule': detail.get('scheduleFrequency'),
                'bucket_definitions': (detail.get('s3JobDefinition') or {}).get('bucketDefinitions')
                if isinstance(detail.get('s3JobDefinition') or {}, dict) else None,
                'bucket_criteria': (detail.get('s3JobDefinition') or {}).get('bucketCriteria')
                if isinstance(detail.get('s3JobDefinition') or {}, dict) else None,
                'number_of_runs': (detail.get('statistics') or {}).get('numberOfRuns')
                if isinstance(detail.get('statistics') or {}, dict) else None,
                'approximate_objects_remaining': (detail.get('statistics') or {}).get(
                    'approximateNumberOfObjectsToProcess')
                if isinstance(detail.get('statistics') or {}, dict) else None,
                'last_run_age_days': age_days(detail.get('lastRunTime')),
                # No classification contents or findings retrieved. This proves
                # at most a completed run with no reported job access errors.
                'execution_success_evidence': (
                    detail.get('jobStatus') in ('COMPLETE', 'IDLE')
                    and detail.get('lastRunTime') is not None
                    and (detail.get('lastRunErrorStatus') or {}).get('code') == 'NONE'
                    and isinstance((detail.get('statistics') or {}).get('numberOfRuns'), (int, float))
                    and (detail.get('statistics') or {}).get('numberOfRuns') > 0),
                'classification_results_verified': False,
            })

        inventory = await self._pages(client.describe_buckets, 'buckets', 'DescribeBuckets')
        result['buckets_complete'] = inventory.complete
        bucket_ids = set()
        for bucket in inventory:
            name, account = bucket.get('bucketName'), bucket.get('accountId')
            if (not isinstance(name, str) or not name
                    or not isinstance(account, str) or not account
                    or (account, name) in bucket_ids):
                self.issue('partial', 'InvalidOrDuplicateBucketIdentity')
                result['buckets_complete'] = False
                continue
            bucket_ids.add((account, name))
            job = bucket.get('jobDetails') or {}
            if not isinstance(job, dict):
                self.issue('partial', 'MalformedBucketJobDetails')
                result['buckets_complete'] = False
                job = {}
            last_automated = date(bucket.get('lastAutomatedDiscoveryTime'))
            last_job = date(job.get('lastJobRunTime'))
            status = bucket_coverage(
                bucket, result['session_status'], result['automated_discovery_status'])
            result['buckets'].append({
                'bucket_name': name, 'bucket_arn': bucket.get('bucketArn'),
                'account_id': account, 'region': bucket.get('region') or region,
                'last_inventory_update': date(bucket.get('lastUpdated')),
                'auto_monitoring_status': bucket.get('automatedDiscoveryMonitoringStatus'),
                'job_defined': job.get('isDefinedInJob'),
                'job_monitored': job.get('isMonitoredByJob'),
                'last_job_id': job.get('lastJobId'),
                'last_job_run_at': last_job, 'last_automated_discovery_at': last_automated,
                'last_job_age_days': age_days(last_job),
                'last_automated_age_days': age_days(last_automated),
                'classifiable_object_count': bucket.get('classifiableObjectCount'),
                'object_count': bucket.get('objectCount'),
                'error_code': bucket.get('errorCode'), 'error_message': bucket.get('errorMessage'),
                'coverage_status': status,
                'review_required': status in (
                    'ERROR', 'STALE_ACTIVITY', 'NO_RECENT_ACTIVITY_EVIDENCE',
                    'NO_MONITORING_CONFIGURED'),
            })
        return result


def bucket_coverage(bucket, session_status, automated_status, now=None):
    """Recent activity is NOT evidence of a successful classification result."""
    if session_status != 'ENABLED':
        return 'UNKNOWN'
    if bucket.get('errorCode'):
        return 'ERROR'
    job = bucket.get('jobDetails')
    if not isinstance(job, dict):
        job = {}
    last = [parse_date(x) for x in (
        bucket.get('lastAutomatedDiscoveryTime'), job.get('lastJobRunTime'))]
    ages = [age_days(x, now=now) for x in last if x is not None]
    if ages:
        return 'RECENT_ACTIVITY' if min(ages) <= STALE_DAYS else 'STALE_ACTIVITY'
    auto = (automated_status == 'ENABLED'
            and bucket.get('automatedDiscoveryMonitoringStatus') == 'MONITORED')
    periodic = job.get('isMonitoredByJob') == 'TRUE'
    if auto or periodic or job.get('isDefinedInJob') == 'TRUE':
        return 'NO_RECENT_ACTIVITY_EVIDENCE'
    if (automated_status == 'DISABLED' and job.get('isMonitoredByJob') == 'FALSE'
            and job.get('isDefinedInJob') == 'FALSE'):
        return 'NO_MONITORING_CONFIGURED'
    return 'UNKNOWN'
