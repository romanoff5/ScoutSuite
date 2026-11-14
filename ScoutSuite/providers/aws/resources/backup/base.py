"""Regional AWS Backup evidence, plans, protected resources and job reconciliation."""
import asyncio
from fnmatch import fnmatchcase

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.utils import get_non_provider_id
from ScoutSuite.providers.aws.resources.regions import Regions

from .vaults import Vaults
from .plans import Plans
from .restore_assurance import assess_restore_testing_plan


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
        # First perform the SecurityAudit-accessible protected-resource census.
        # Only suppress deeper restricted job/restore APIs when *all three*
        # discovery collections were verified complete and empty. An empty
        # array returned after AccessDenied must never be treated as absence.
        try:
            protected_raw = (await backup.get_protected_resources(region)
                             if hasattr(backup, 'get_protected_resources')
                             else MissingCollection())
        except Exception:
            _issue('protected_resourcesCollectionFailed')
            protected_raw = MissingCollection()
        protected_complete = getattr(protected_raw, 'complete', True)
        data['protected_resources'], malformed = _store(
            protected_raw, 'ResourceArn', 'protected_resources')
        data['protected_resources_count'] = len(data['protected_resources'])
        protected_complete = bool(protected_complete and not malformed)

        discovery = getattr(backup, 'discovery_complete', {}).get(region, {})
        verified_empty = (
            discovery.get('plans') is True
            and discovery.get('vaults') is True
            and protected_complete
            and not data['plans'] and not data['vaults']
            and not data['protected_resources'])
        methods = (
            ('backup_jobs', 'get_backup_jobs', 'BackupJobId'),
            ('restore_jobs', 'get_restore_jobs', 'RestoreJobId'),
            ('restore_testing_plans', 'get_restore_testing_plans',
             'RestoreTestingPlanArn'),
        )
        status = {
            'protected_resources': 'complete' if protected_complete else 'partial'}
        if verified_empty:
            # Historical jobs or standalone restore-testing plans can still
            # exist. They are deliberately *unassessed*, not verified absent.
            # Native RDS snapshots/PITR and EBS backups are independently
            # evaluated by their respective service collectors.
            for key, _, _ in methods:
                data[key] = {}
                data[key + '_count'] = 0
                status[key] = 'deferred_no_current_backup_inventory'
            data['backup_service_activity'] = 'no_current_resources_observed'
        else:
            results = await asyncio.gather(*(
                getattr(backup, method)(region) if hasattr(backup, method)
                else asyncio.sleep(0, result=MissingCollection())
                for _, method, _ in methods),
                return_exceptions=True)
            for (key, _, identity), result in zip(methods, results):
                if isinstance(result, BaseException):
                    _issue(key + 'CollectionFailed')
                    result = MissingCollection()
                complete = getattr(result, 'complete', True)
                data[key], malformed = _store(result, identity, key)
                data[key + '_count'] = len(data[key])
                status[key] = 'complete' if complete and not malformed else 'partial'
            data['backup_service_activity'] = 'not_determined'
        data['backup_inventory_status'] = status

        protected = {
            item['ResourceArn'] for item in data['protected_resources'].values()
            if isinstance(item.get('ResourceArn'), str)}
        jobs = list(data['backup_jobs'].values())
        if hasattr(backup, 'get_rpo_evidence'):
            try:
                data['operational_rpo'] = await backup.get_rpo_evidence(region, protected, jobs)
            except Exception:
                _issue('RPOOperationalCollectionFailed')
                data['operational_rpo'] = {'status': 'unknown', 'resources': {}}
        else:
            data['operational_rpo'] = {'status': 'unknown', 'resources': {}}
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
        selector_keys = set()
        for plan in data['plans'].values():
            for detail in plan.get('selections', []):
                selection = detail.get('BackupSelection', {}) if isinstance(detail, dict) else {}
                if not isinstance(selection, dict):
                    continue
                for tag in selection.get('ListOfTags') or []:
                    if isinstance(tag, dict) and isinstance(tag.get('ConditionKey'), str):
                        selector_keys.add(tag['ConditionKey'])
                conditions = selection.get('Conditions') or {}
                if isinstance(conditions, dict):
                    for entries in conditions.values():
                        if not isinstance(entries, list):
                            continue
                        for condition in entries:
                            if not isinstance(condition, dict):
                                continue
                            key = condition.get('ConditionKey')
                            if isinstance(key, str) and key.startswith('aws:ResourceTag/'):
                                selector_keys.add(key[len('aws:ResourceTag/'):])
        candidates = {'tags': {}, 'status': 'not_required'}
        if tag_selections and hasattr(backup, 'get_tagged_resource_candidates'):
            try:
                candidates = await backup.get_tagged_resource_candidates(region, selector_keys)
            except Exception:
                _issue('GetTaggedResourceCandidatesFailed')
                candidates = {'tags': {}, 'status': 'partial'}
        elif tag_selections:
            candidates = {'tags': {}, 'status': 'not_collected'}
        if tag_selections and not selector_keys:
            candidates['status'] = 'partial'
            _issue('UnresolvedTagSelectorKeys')
        data['tagged_candidate_evidence'] = candidates
        candidate_tags = candidates.get('tags', {})
        known_tags = {**tag_inventory.get('tags', {}), **candidate_tags}

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
                    arn, detail, known_tags.get(arn))
                    for detail in plan.get('selections', [])]
                for arn in protected}
            matching = sorted(
                arn for arn, checks in decisions.items() if 'matched' in checks)
            unresolved = sorted(
                arn for arn, checks in decisions.items()
                if 'matched' not in checks and 'unknown' in checks)
            plan['tag_condition_evaluated_resource_arns'] = sorted(
                arn for arn in protected if arn in known_tags)
            selected_tagged = sorted(
                arn for arn, tags in candidate_tags.items()
                if any(_selection_decision(arn, detail, tags) == 'matched'
                       for detail in plan.get('selections', [])))
            plan['tagged_selection_candidate_arns'] = selected_tagged
            plan['tagged_candidate_inventory_status'] = candidates['status']
            plan['selected_tagged_resource_arns_without_reported_recovery_point'] = (
                sorted(set(selected_tagged) - protected)
                if status['protected_resources'] == 'complete' else [])
            plan['tagged_resource_gap_evidence_status'] = (
                'partial' if candidates['status'] not in ('complete', 'not_required')
                or status['protected_resources'] != 'complete'
                else 'candidate_only_not_opt_in_verified')
            plan['selection_unresolved_resource_arns'] = unresolved
            plan['selection_evidence_scope'] = 'observed_protected_resources_only'
            plan['selection_evaluation_status'] = (
                'partial' if unresolved or
                (tag_selections and candidates['status'] != 'complete')
                or (tag_selections and tag_inventory['status'] != 'complete'
                    and bool(protected))
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
                or bool(unresolved)
                or (tag_selections and candidates['status'] != 'complete')
                else 'complete')
            rpo_resources = data['operational_rpo'].get('resources', {})
            plan['operational_rpo_evidence'] = [
                rpo_resources[arn] for arn in sorted(set(matching) | set(explicit) |
                                                     set(selected_tagged)) if arn in rpo_resources]
            plan['correlation_note'] = (
                'Plan selections describe assignments, not successful backups. '
                'ListProtectedResources records recovery points of any status. '
                'Completed jobs are limited to AWS Backup job history. '
                'Tag conditions are evaluated only for resources with verified '
                'tag mappings. Tagged candidates without recovery points '
                'are potential gaps; resource type opt-in and supported '
                'resource coverage are not independently verified.')

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
                or status['restore_testing_plans'] != 'complete'
                or not test.get('selection_collection_complete') else 'complete')
            test.update(assess_restore_testing_plan(
                test, matching_jobs, test['results_status']))
