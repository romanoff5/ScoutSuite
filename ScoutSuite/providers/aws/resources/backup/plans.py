"""Backup plan schedules and retention lifecycle evidence (read-only)."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class Plans(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for raw in await self.facade.backup.get_plans(self.region):
            arn = raw.get('arn') if isinstance(raw, dict) else None
            if not isinstance(arn, str) or not arn.startswith('arn:'):
                ctx = get_current_run_context()
                if ctx is not None:
                    ctx.record_collection_issue('partial', 'backup', 'InvalidPlanRecord')
                continue
            key = get_non_provider_id(arn)
            if key in self:
                ctx = get_current_run_context()
                if ctx is not None:
                    ctx.record_collection_issue('partial', 'backup', 'DuplicatePlanRecord')
                continue
            self[key] = {
                'id': key, 'name': raw.get('name'),
                'backup_plan_id': raw.get('plan_id'), 'backup_plan_arn': arn,
                'region': self.region, 'version_id': raw.get('version_id'),
                'creation_date': raw.get('creation_date'),
                'last_execution_date': raw.get('last_execution_date'),
                'creator_request_id': raw.get('creator_request_id'),
                'selection_count': len(raw.get('selections', [])),
                'selections': raw.get('selections', []),
                'selection_collection_complete': raw.get('selection_collection_complete', False),
                'rule_count': len(raw.get('rules', [])),
                'rules': raw.get('rules', []),
                'advanced_backup_settings': raw.get('advanced_backup_settings', []),
            }
