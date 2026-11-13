"""Read-only CloudWatch/Logs inventory with explicit collection completeness."""
from ScoutSuite.core.console import print_exception
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils


class CloudWatch(AWSBaseFacade):
    def __init__(self, session):
        super().__init__(session)
        self.metric_filter_collection_status = {}
        self.alarm_collection_status = {}

    @staticmethod
    def _issue(reason):
        ctx = get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue('partial', 'cloudwatch', reason)

    async def get_alarms(self, region):
        try:
            result = await AWSFacadeUtils.get_all_pages(
                'cloudwatch', region, self.session, 'describe_alarms', 'MetricAlarms')
            if not isinstance(result, list):
                raise ValueError('Non-list metric alarm inventory')
            self.alarm_collection_status[region] = 'complete'
            return result
        except Exception as exc:
            self.alarm_collection_status[region] = 'unknown'
            self._issue('DescribeMetricAlarmsIncomplete')
            print_exception(f'Failed to get CloudWatch metric alarms: {exc}')
            return []

    async def get_metric_filters(self, region):
        try:
            result = await AWSFacadeUtils.get_all_pages(
                'logs', region, self.session, 'describe_metric_filters', 'metricFilters')
            if not isinstance(result, list):
                raise ValueError('Non-list metric filter inventory')
            self.metric_filter_collection_status[region] = 'complete'
            return result
        except Exception as exc:
            self.metric_filter_collection_status[region] = 'unknown'
            self._issue('DescribeMetricFiltersIncomplete')
            print_exception(f'Failed to get CloudWatch metric filters: {exc}')
            return []
