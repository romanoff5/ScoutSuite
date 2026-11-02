"""Normalize hubs and standards subscriptions without finding payloads."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class Hubs(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        result = await self.facade.securityhub.get_hub(self.region)
        if result is None:
            return
        arn = result.get('hub_arn')
        if not isinstance(arn, str) or not arn.startswith('arn:'):
            self._issue('MalformedHubResource')
            return
        standards = {}
        for item in result.get('standards', []):
            if not isinstance(item, dict):
                self._issue('MalformedStandardResource')
                continue
            subscription = item.get('subscription_arn')
            standard = item.get('standards_arn')
            if (not isinstance(subscription, str) or not subscription.startswith('arn:')
                    or not isinstance(standard, str) or not standard.startswith('arn:')):
                self._issue('MalformedStandardResource')
                continue
            key = get_non_provider_id(subscription)
            if key in standards:
                self._issue('DuplicateStandardResource')
                continue
            status = item.get('status')
            standards[key] = {
                'id': key,
                'subscription_arn': subscription,
                'standards_arn': standard,
                'name': standard.rsplit('/', 1)[-1],
                'status': status,
                'unhealthy': status in ('FAILED', 'INCOMPLETE'),
                'status_reason': item.get('status_reason'),
                'status_reason_details': item.get('status_reason_details') or {},
                'standards_controls_updatable': item.get('standards_controls_updatable'),
                'provider': item.get('provider'),
                'region': self.region,
            }
        hub_key = get_non_provider_id(arn)
        self[hub_key] = {
            'id': hub_key, 'name': 'Security Hub', 'region': self.region,
            'hub_arn': arn,
            'auto_enable_controls': result.get('auto_enable_controls'),
            'control_finding_generator': result.get('control_finding_generator'),
            'standards': standards,
            'standards_count': len(standards),
            'standards_inventory_complete': result.get('standards_inventory_complete') is True,
        }

    @staticmethod
    def _issue(reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue('partial', 'securityhub', reason)
