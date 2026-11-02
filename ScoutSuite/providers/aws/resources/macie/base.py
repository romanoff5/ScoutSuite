"""M10-P Macie region inventory with explicit completeness and no object contents."""
import asyncio

from ScoutSuite.providers.aws.resources.regions import Regions
from ScoutSuite.providers.utils import get_non_provider_id


class MaciePublic(Regions):
    _children = []

    def __init__(self, facade):
        super().__init__('macie2', facade)

    async def fetch_all(self, regions=None, excluded_regions=None, partition_name='aws', **kwargs):
        available = await self.facade.build_region_list(
            'macie2', regions, excluded_regions, partition_name)
        self['regions'] = {}
        items = await asyncio.gather(
            *(self.facade.macie.get_region(region) for region in available),
            return_exceptions=True)
        from ScoutSuite.core.run_context import get_current_run_context
        for region, raw in zip(available, items):
            if isinstance(raw, BaseException) or not isinstance(raw, dict):
                ctx = get_current_run_context()
                if ctx is not None:
                    ctx.record_collection_issue('failed', 'macie', 'RegionCollectionFailed')
                raw = {}
            status = raw.get('session_status', 'UNKNOWN')
            data = {
                'id': region, 'name': region, 'region': region,
                'session_status': status,
                'session_verified': raw.get('session_verified', False),
                'not_enabled': status in ('NOT_ENABLED', 'PAUSED'),
                'service_role': raw.get('service_role'),
                'session_created_at': raw.get('session_created_at'),
                'session_updated_at': raw.get('session_updated_at'),
                'automated_discovery_status': raw.get('automated_discovery_status', 'UNKNOWN'),
                'automated_discovery_verified': raw.get('automated_discovery_verified', False),
                'automated_discovery_updated_at': raw.get('automated_discovery_updated_at'),
                'auto_enable_org_members': raw.get('auto_enable_org_members'),
                'classification_scope_id': raw.get('classification_scope_id'),
                'excluded_bucket_names': raw.get('excluded_bucket_names', []),
                'jobs_complete': raw.get('jobs_complete', False),
                'buckets_complete': raw.get('buckets_complete', False),
                'jobs': {}, 'buckets': {},
            }
            for job in raw.get('jobs', []):
                identity = job.get('job_id') if isinstance(job, dict) else None
                if not isinstance(identity, str) or not identity:
                    data['jobs_complete'] = False
                    continue
                key = get_non_provider_id(identity)
                if key in data['jobs']:
                    data['jobs_complete'] = False
                    continue
                item = dict(job)
                from ScoutSuite.providers.aws.facade.macie import age_days, STALE_DAYS
                age = age_days(item.get('last_run_at'))
                created_age = age_days(item.get('created_at'))
                item.update({
                    'id': key, 'region': region,
                    'execution_issue': (
                        item.get('last_run_error') == 'ERROR'
                        or item.get('status') in ('CANCELLED', 'PAUSED', 'USER_PAUSED')),
                    'last_run_age_days': age,
                    'execution_evidence_status': (
                        'completed_without_reported_access_errors'
                        if item.get('execution_success_evidence') is True
                        else 'reported_run_error' if item.get('last_run_error') == 'ERROR'
                        else 'not_verified'),
                    'classification_results_verified': False,
                    'stale': (
                        item.get('type') == 'SCHEDULED'
                        and (age > STALE_DAYS if age is not None
                             else created_age is not None and created_age > STALE_DAYS)),
                })
                data['jobs'][key] = item
            for bucket in raw.get('buckets', []):
                if not isinstance(bucket, dict):
                    data['buckets_complete'] = False
                    continue
                name, account = bucket.get('bucket_name'), bucket.get('account_id')
                if not isinstance(name, str) or not isinstance(account, str):
                    data['buckets_complete'] = False
                    continue
                key = get_non_provider_id(account + '/' + name)
                if key in data['buckets']:
                    data['buckets_complete'] = False
                    continue
                last_job_id = bucket.get('last_job_id')
                linked_job = next((job for job in data['jobs'].values()
                                   if job.get('job_id') == last_job_id), None)
                bucket_evidence = (
                    'linked_job_completed_no_reported_access_errors'
                    if linked_job and linked_job.get('execution_success_evidence') is True
                    and bucket.get('last_job_run_at')
                    else 'linked_job_failed'
                    if linked_job and linked_job.get('last_run_error') == 'ERROR'
                    else 'not_verified')
                data['buckets'][key] = {
                    'id': key, 'name': name, **bucket,
                    'job_execution_evidence_status': bucket_evidence,
                    'classification_results_verified': False,
                    'classification_evidence_note': (
                        'A linked job run without reported access errors does not '
                        'prove which objects were classified or that the bucket '
                        'was fully analyzed.'),
                }
            data['verified_job_executions_count'] = sum(
                j.get('execution_success_evidence') is True
                for j in data['jobs'].values())
            data['verified_bucket_classifications_count'] = 0
            data['jobs_count'] = len(data['jobs'])
            data['buckets_count'] = len(data['buckets'])
            data['no_classification_configured'] = (
                status == 'ENABLED'
                and data['automated_discovery_verified']
                and data['automated_discovery_status'] == 'DISABLED'
                and data['jobs_complete'] and data['jobs_count'] == 0)
            # Unknown permissions are not treated as a clean empty inventory.
            data['coverage_assessment_status'] = (
                'complete' if data['session_verified'] and status == 'ENABLED'
                and data['buckets_complete'] and data['jobs_complete']
                and data['automated_discovery_verified'] else 'incomplete')
            self['regions'][region] = data
        self['regions_count'] = len(self['regions'])
        self['jobs_count'] = sum(x['jobs_count'] for x in self['regions'].values())
        self['buckets_count'] = sum(x['buckets_count'] for x in self['regions'].values())
