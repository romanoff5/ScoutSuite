"""Regional AWS Backup evidence, plans, protected resources and job reconciliation."""
import asyncio
from fnmatch import fnmatchcase

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.utils import get_non_provider_id
from ScoutSuite.providers.aws.resources.regions import Regions

from .vaults import Vaults
from .plans import Plans


class MissingCollection(list):
    complete = False


def _issue(reason):
    ctx = get_current_run_context()
    if ctx is not None:
        ctx.record_collection_issue('partial', 'backup', reason)


def _store(rows, field, prefix):
    """Index intact AWS evidence without silently dropping duplicate records."""
    indexed, malformed = {}, False
    for row in rows:
        key = row.get(field) if isinstance(row, dict) else None
        hashed = get_non_provider_id(key) if isinstance(key, str) and key else None
        if not hashed or hashed in indexed:
            _issue(prefix + 'InvalidOrDuplicateIdentity')
            malformed = True
            continue
        indexed[hashed] = {'id': hashed, 'name': row.get(
            'ResourceName') or row.get('RestoreTestingPlanName') or key, **row}
    return indexed, malformed


def _selection_decision(arn, detail, tags=None):
    """Conservative selection evaluation for *observed* resources.

    A verified mapping is required for tag matching; no Resource Groups
    Tagging API row cannot establish an untagged resource.
    """
    selection = detail.get('BackupSelection', {}) if isinstance(detail, dict) else {}
    if not isinstance(selection, dict):
        return 'unknown'
    include = selection.get('Resources') or []
    exclude = selection.get('NotResources') or []
    legacy = selection.get('ListOfTags') or []
    conditions = selection.get('Conditions') or {}
    if (not isinstance(include, list) or not isinstance(exclude, list)
            or not isinstance(legacy, list) or not isinstance(conditions, dict)):
        return 'unknown'
    if not all(isinstance(x, str) for x in include + exclude):
        return 'unknown'
    if any(fnmatchcase(arn, pattern) for pattern in exclude):
        return 'excluded'
    direct = any(fnmatchcase(arn, pattern) for pattern in include)
    # Resources OR ListOfTags (AWS Backup), then Conditions AND.
    if not include and not legacy and not conditions:
        return 'unknown'
    if not legacy and not conditions:
        return 'matched' if direct else 'not_matched'
    if tags is None:
        if direct and legacy and not conditions:
            return 'matched'
        if include and not direct and not legacy:
            return 'not_matched'
        return 'unknown'

    def compare(entry, op, *, legacy_tag=False):
        if not isinstance(entry, dict):
            return None
        key, expected = entry.get('ConditionKey'), entry.get('ConditionValue')
        if not isinstance(key, str) or not isinstance(expected, str):
            return None
        if not legacy_tag:
            if not key.startswith('aws:ResourceTag/'):
                return None
            key = key[len('aws:ResourceTag/'):]
        actual = tags.get(key)
        if actual is None:
            return False
        if op == 'StringEquals':
            return actual == expected
        if op == 'StringNotEquals':
            return actual != expected
        if op == 'StringLike':
            return fnmatchcase(actual, expected)
        if op == 'StringNotLike':
            return not fnmatchcase(actual, expected)
        return None

    legacy_match = False
    if legacy:
        checks = [compare(x, 'StringEquals', legacy_tag=True)
                  if isinstance(x, dict) and isinstance(x.get('ConditionType'), str)
                  and x['ConditionType'].upper() == 'STRINGEQUALS'
                  else None for x in legacy]
        if any(x is None for x in checks):
            return 'unknown'
        legacy_match = any(checks)
    if include or legacy:
        if not (direct or legacy_match):
            return 'not_matched'
    for op, entries in conditions.items():
        if op not in ('StringEquals', 'StringNotEquals', 'StringLike', 'StringNotLike'):
            return 'unknown'
        if not isinstance(entries, list):
            return 'unknown'
        outcomes = [compare(x, op) for x in entries]
        if any(x is None for x in outcomes):
            return 'unknown'
        if not all(outcomes):
            return 'not_matched'
    return 'matched'


def _matches_selection(arn, detail):
    # Legacy boolean used for explicit ARN diagnostics; unknown is not a match.
    return _selection_decision(arn, detail) == 'matched'


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
            (getattr(backup, method)(region) if hasattr(backup, method)
             else asyncio.sleep(0, result=MissingCollection()))
            for _, method, _ in methods),
            return_exceptions=True)
        status = {}
        for (key, _, identity), result in zip(methods, results):
            if isinstance(result, BaseException):
                _issue(key + 'CollectionFailed')
                result = []
                complete = False
            else:
                complete = getattr(result, 'complete', True)
            data[key], malformed = _store(result, identity, key)
            data[key + '_count'] = len(data[key])
            status[key] = 'complete' if complete and not malformed else 'partial'
        data['backup_inventory_status'] = status

        protected = {
            item['ResourceArn'] for item in data['protected_resources'].values()
            if isinstance(item.get('ResourceArn'), str)}
        jobs = data['backup_jobs'].values()
        tag_selections = any(
            bool(detail.get('BackupSelection', {}).get('ListOfTags')
                 or detail.get('BackupSelection', {}).get('Conditions'))
            for plan in data['plans'].values() for detail in plan.get('selections', [])
            if isinstance(detail.get('BackupSelection'), dict))
        tag_inventory = {'tags': {}, 'status': 'not_required',
                         'unknown_arns': []}
        if tag_selections and protected:
            if hasattr(backup, 'get_resource_tags'):
                try:
                    tag_inventory = await backup.get_resource_tags(region, protected)
                except Exception:
                    _issue('GetResourceTagsFailed')
                    tag_inventory = {'tags': {}, 'status': 'partial',
                                     'unknown_arns': sorted(protected)}
            else:
                tag_inventory = {'tags': {}, 'status': 'not_collected',
                                 'unknown_arns': sorted(protected)}
        elif tag_selections:
            tag_inventory['status'] = 'not_collected'
        data['resource_tag_evidence'] = tag_inventory

        for plan in data['plans'].values():
            plan_id = plan.get('backup_plan_id')
            completed = sorted({
                j['ResourceArn'] for j in jobs
                if j.get('State') == 'COMPLETED'
                and isinstance(j.get('ResourceArn'), str)
                and isinstance(j.get('CreatedBy'), dict)
                and j['CreatedBy'].get('BackupPlanId') == plan_id
            })
            decisions = {
                arn: [_selection_decision(
                    arn, detail, tag_inventory['tags'].get(arn))
                    for detail in plan.get('selections', [])]
                for arn in protected}
            matching = sorted(
                arn for arn, checks in decisions.items() if 'matched' in checks)
            unresolved = sorted(
                arn for arn, checks in decisions.items()
                if 'matched' not in checks and 'unknown' in checks)
            plan['tag_condition_evaluated_resource_arns'] = sorted(
                arn for arn in protected if arn in tag_inventory['tags'])
            plan['selection_unresolved_resource_arns'] = unresolved
            plan['selection_evidence_scope'] = 'observed_protected_resources_only'
            plan['selection_evaluation_status'] = (
                'partial' if unresolved or
                (tag_selections and tag_inventory['status'] != 'complete')
                else 'observed_resources_only')
            explicit = sorted({
                arn for detail in plan.get('selections', [])
                for arn in detail.get('BackupSelection', {}).get('Resources', [])
                if isinstance(arn, str) and arn.startswith('arn:')
                and not any(c in arn for c in '*?[')
                and _matches_selection(arn, detail)})
            plan['observed_backup_jobs'] = [
                {'BackupJobId': j.get('BackupJobId'),
                 'State': j.get('State'),
                 'MessageCategory': j.get('MessageCategory'),
                 'StatusMessage': j.get('StatusMessage'),
                 'ResourceArn': j.get('ResourceArn'),
                 'CreationDate': j.get('CreationDate'),
                 'CompletionDate': j.get('CompletionDate')}
                for j in jobs if isinstance(j.get('CreatedBy'), dict)
                and j['CreatedBy'].get('BackupPlanId') == plan_id]
            plan['matching_protected_resource_arns'] = matching
            plan['observed_completed_backup_resource_arns'] = completed
            plan['completed_job_resource_arns_with_recovery_point'] = sorted(
                set(completed) & protected)
            plan['explicit_resource_arns_without_reported_recovery_point'] = sorted(
                set(explicit) - protected) if status['protected_resources'] == 'complete' else []
            plan['correlation_status'] = (
                'partial' if status['backup_jobs'] != 'complete'
                or status['protected_resources'] != 'complete'
                or not plan.get('selection_collection_complete')
                or bool(unresolved) else 'complete')
            plan['correlation_note'] = (
                'Plan selections describe assignments, not successful backups. '
                'ListProtectedResources records recovery points of any status. '
                'Completed jobs are limited to AWS Backup job history. '
                'Tag conditions are evaluated only for resources with verified '
                'tag mappings; missing mappings and resources with no observed '
                'recovery points remain unverified.')

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
