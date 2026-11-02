"""Regional AWS Backup evidence, plans, protected resources and job reconciliation."""
import asyncio
from fnmatch import fnmatchcase

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.utils import get_non_provider_id
from ScoutSuite.providers.aws.resources.regions import Regions

from .vaults import Vaults
from .plans import Plans


def _issue(reason):
    ctx = get_current_run_context()
    if ctx is not None:
        ctx.record_collection_issue('partial', 'backup', reason)


def _store(rows, field, prefix):
    """Index intact AWS evidence without silently dropping duplicate records."""
    indexed = {}
    for row in rows:
        key = row.get(field) if isinstance(row, dict) else None
        if not isinstance(key, str) or not key or key in indexed:
            _issue(prefix + 'InvalidOrDuplicateIdentity')
            continue
        indexed[key] = {'id': get_non_provider_id(key), 'name': row.get(
            'ResourceName') or row.get('RestoreTestingPlanName') or key, **row}
    return indexed


def _matches_selection(arn, detail):
    """Direct ARN/wildcard matching; tag/condition selectors need independent inventory."""
    selection = detail.get('BackupSelection', {})
    if not isinstance(selection, dict):
        return False
    if selection.get('ListOfTags') or any(selection.get('Conditions', {}).values()):
        return False
    includes = selection.get('Resources', [])
    excludes = selection.get('NotResources', [])
    return (isinstance(includes, list) and isinstance(excludes, list)
            and any(isinstance(pattern, str) and fnmatchcase(arn, pattern)
                    for pattern in includes)
            and not any(isinstance(pattern, str) and fnmatchcase(arn, pattern)
                        for pattern in excludes))


class BackupPublic(Regions):
    _children = [(Vaults, 'vaults'), (Plans, 'plans')]

    def __init__(self, facade):
        super().__init__('backup', facade)

    async def fetch_all(self, **kwargs):
        await super().fetch_all(**kwargs)
        await asyncio.gather(*(
            self._enrich_region(region, data)
            for region, data in self['regions'].items()))
        for key in ('protected_resources', 'backup_jobs', 'restore_jobs',
                    'restore_testing_plans'):
            self[key + '_count'] = sum(
                item[key + '_count'] for item in self['regions'].values())

    async def _enrich_region(self, region, data):
        backup = self.facade.backup
        methods = (
            ('protected_resources', 'get_protected_resources', 'ResourceArn'),
            ('backup_jobs', 'get_backup_jobs', 'BackupJobId'),
            ('restore_jobs', 'get_restore_jobs', 'RestoreJobId'),
            ('restore_testing_plans', 'get_restore_testing_plans',
             'RestoreTestingPlanArn'),
        )
        results = await asyncio.gather(*(
            getattr(backup, method)(region) for _, method, _ in methods),
            return_exceptions=True)
        status = {}
        for (key, _, identity), result in zip(methods, results):
            if isinstance(result, BaseException):
                _issue(key + 'CollectionFailed')
                result = []
                complete = False
            else:
                complete = getattr(result, 'complete', True)
            data[key] = _store(result, identity, key)
            data[key + '_count'] = len(data[key])
            status[key] = 'complete' if complete else 'partial'
        data['backup_inventory_status'] = status

        protected = set(data['protected_resources'])
        jobs = data['backup_jobs'].values()
        for plan in data['plans'].values():
            plan_id = plan.get('backup_plan_id')
            completed = sorted({
                j['ResourceArn'] for j in jobs
                if j.get('State') == 'COMPLETED'
                and isinstance(j.get('ResourceArn'), str)
                and isinstance(j.get('CreatedBy'), dict)
                and j['CreatedBy'].get('BackupPlanId') == plan_id
            })
            matching = sorted(arn for arn in protected if any(
                _matches_selection(arn, detail)
                for detail in plan.get('selections', [])))
            explicit = sorted({
                arn for detail in plan.get('selections', [])
                for arn in detail.get('BackupSelection', {}).get('Resources', [])
                if isinstance(arn, str) and arn.startswith('arn:')
                and not any(c in arn for c in '*?[')
                and _matches_selection(arn, detail)})
            plan['matching_protected_resource_arns'] = matching
            plan['observed_completed_backup_resource_arns'] = completed
            plan['completed_job_resource_arns_with_recovery_point'] = sorted(
                set(completed) & protected)
            plan['explicit_resource_arns_without_reported_recovery_point'] = sorted(
                set(explicit) - protected) if status['protected_resources'] == 'complete' else []
            plan['correlation_status'] = (
                'partial' if status['backup_jobs'] != 'complete'
                or status['protected_resources'] != 'complete'
                or not plan.get('selection_collection_complete') else 'complete')
            plan['correlation_note'] = (
                'Plan selections describe assignments, not successful backups. '
                'ListProtectedResources records recovery points of any status. '
                'Completed jobs are limited to AWS Backup job history. '
                'Tag conditions cannot be resolved from these APIs alone.')

        for test in data['restore_testing_plans'].values():
            arn = test.get('RestoreTestingPlanArn')
            matching_jobs = [j for j in data['restore_jobs'].values()
                             if isinstance(j.get('CreatedBy'), dict)
                             and j['CreatedBy'].get('RestoreTestingPlanArn') == arn]
            test['observed_restore_jobs'] = [
                {'RestoreJobId': j.get('RestoreJobId'),
                 'SourceResourceArn': j.get('SourceResourceArn'),
                 'Status': j.get('Status'),
                 'ValidationStatus': j.get('ValidationStatus'),
                 'StatusMessage': j.get('StatusMessage'),
                 'ValidationStatusMessage': j.get('ValidationStatusMessage')}
                for j in matching_jobs]
            test['results_status'] = (
                'partial' if status['restore_jobs'] != 'complete'
                or not test.get('selection_collection_complete') else 'complete')
