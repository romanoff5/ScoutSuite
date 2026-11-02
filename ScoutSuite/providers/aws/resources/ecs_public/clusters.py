"""Preserve ECS cluster identifiers and operational security metadata."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class Clusters(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        for row in await self.facade.ecs.get_clusters(self.region):
            parsed = self._parse_cluster(row)
            if parsed is None:
                ctx = get_current_run_context()
                if ctx is not None:
                    ctx.record_collection_issue('partial', 'ecs', 'InvalidCluster')
                continue
            key, value = parsed
            if key in self:
                ctx = get_current_run_context()
                if ctx is not None:
                    ctx.record_collection_issue('partial', 'ecs', 'DuplicateClusterKey')
                continue
            self[key] = value

    def _parse_cluster(self, raw):
        if not isinstance(raw, dict):
            return None
        arn, name = raw.get('clusterArn'), raw.get('clusterName')
        if (not isinstance(arn, str) or not arn.startswith('arn:')
                or not isinstance(name, str) or not name):
            return None
        settings = raw.get('settings')
        settings = settings if isinstance(settings, list) else []
        insights = [
            setting.get('value') for setting in settings
            if isinstance(setting, dict) and setting.get('name') == 'containerInsights'
        ]
        value = insights[0] if len(insights) == 1 and isinstance(insights[0], str) else None
        key = get_non_provider_id(arn)
        return key, {
            'id': key, 'name': name, 'cluster_name': name, 'cluster_arn': arn,
            'region': self.region, 'status': raw.get('status'),
            'container_insights': value, 'container_insights_disabled': value == 'disabled',
            'settings': settings, 'configuration': raw.get('configuration') or {},
            'capacity_providers': raw.get('capacityProviders') or [],
            'default_capacity_provider_strategy': raw.get('defaultCapacityProviderStrategy') or [],
            'running_tasks_count': raw.get('runningTasksCount'),
            'pending_tasks_count': raw.get('pendingTasksCount'),
            'registered_container_instances_count': raw.get('registeredContainerInstancesCount'),
            'active_services_count': raw.get('activeServicesCount'),
            'statistics': raw.get('statistics') or [],
            'tags': raw.get('tags') or [],
            'attachments_status': raw.get('attachmentsStatus'),
            'service_connect_defaults': raw.get('serviceConnectDefaults') or {},
        }
