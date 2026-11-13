"""Read-only CloudWatch and CloudWatch Logs census with explicit API outcomes.

Do not call the generic get_all_pages helper here: it can swallow AccessDenied
and paginator timeouts and return [], indistinguishable from an empty inventory.
"""
from ScoutSuite.core.console import print_exception
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently


class CloudWatch(AWSBaseFacade):
    def __init__(self, session):
        super().__init__(session)
        self.metric_filter_collection_status = {}
        self.alarm_collection_status = {}

    @staticmethod
    def _issue(reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue('partial', 'cloudwatch', reason)

    async def _list_region(self, region, service, operation, field):
        client = AWSFacadeUtils.get_client(service, self.session, region)
        if client is None:
            self._issue(operation + 'ClientUnavailable')
            return None
        try:
            def collect():
                pages = client.get_paginator(operation).paginate()
                return AWSFacadeUtils._get_all_pages_from_paginator(pages, [field])[field]
            result = await run_concurrently(collect)
            if not isinstance(result, list) or not all(isinstance(x, dict) for x in result):
                raise ValueError('MalformedCloudWatchInventory')
            return result
        except Exception as error:
            AWSFacadeUtils.record_listing_failure('cloudwatch', error, operation)
            self._issue(operation + 'Incomplete')
            print_exception('Incomplete CloudWatch inventory: ' + operation +
                            ' (' + type(error).__name__ + ')')
            return None

    async def get_alarms(self, region):
        data = await self._list_region(region, 'cloudwatch', 'describe_alarms', 'MetricAlarms')
        self.alarm_collection_status[region] = 'complete' if data is not None else 'unknown'
        return data if data is not None else []

    async def get_metric_filters(self, region):
        data = await self._list_region(region, 'logs', 'describe_metric_filters', 'metricFilters')
        self.metric_filter_collection_status[region] = 'complete' if data is not None else 'unknown'
        return data if data is not None else []
