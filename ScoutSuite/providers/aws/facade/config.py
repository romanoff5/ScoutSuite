from ScoutSuite.core.console import print_exception
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.pagination import collect_token_pages, PaginationError
from ScoutSuite.providers.utils import run_concurrently


class ConfigFacade(AWSBaseFacade):
    @staticmethod
    def _issue(reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue('partial', 'config', reason)

    async def get_rules(self, region):
        try:
            return await AWSFacadeUtils.get_all_pages(
                'config', region, self.session, 'describe_config_rules', 'ConfigRules')
        except Exception:
            self._issue('ConfigRules')
            print_exception('Unable to get Config rules')
            return []

    async def get_recorders(self, region: str):
        client = AWSFacadeUtils.get_client('config', self.session, region)
        if client is None:
            self._issue('RecorderClient')
            return []
        try:
            summaries = await collect_token_pages(
                client.list_configuration_recorders,
                items_path=('ConfigurationRecorderSummaries',),
                input_token='NextToken', output_token=('NextToken',),
                first_kwargs={'MaxResults': 20}, scope='config'
            )
        except PaginationError as error:
            summaries = error.items
            if not summaries:
                # Preserve older customer-managed scans, but flag
                # service-linked coverage as unverified.
                try:
                    recorders = (await run_concurrently(
                        client.describe_configuration_recorders
                    )).get('ConfigurationRecorders', [])
                except Exception:
                    print_exception('Unable to describe Config recorders')
                    return []
                self._issue('RecorderInventoryPartial')
                return await self._attach_statuses(client, recorders)

        recorders = []
        for summary in summaries:
            arn = summary.get('arn') if isinstance(summary, dict) else None
            if not arn:
                self._issue('RecorderSummaryMalformed')
                continue
            try:
                result = await run_concurrently(
                    lambda arn=arn: client.describe_configuration_recorders(Arn=arn))
                recorders.extend(result.get('ConfigurationRecorders', []))
            except Exception:
                self._issue('RecorderDescribe')
                print_exception('Unable to describe Config recorder')
        return await self._attach_statuses(client, recorders)

    async def _attach_statuses(self, client, recorders):
        for recorder in recorders:
            arn, name = recorder.get('arn'), recorder.get('name')
            kwargs = {'Arn': arn} if arn else (
                {'ConfigurationRecorderNames': [name]} if name else {}
            )
            try:
                result = await run_concurrently(
                    lambda kwargs=kwargs: client.describe_configuration_recorder_status(
                        **kwargs))
                statuses = result.get('ConfigurationRecordersStatus', [])
                status = next((
                    s for s in statuses if (arn and s.get('arn') == arn)
                    or (name and s.get('name') == name)
                ), None)
            except Exception:
                status = None
                print_exception('Unable to retrieve Config recorder status')
            recorder['ConfigurationRecordersStatus'] = status
            if status is None:
                self._issue('RecorderStatusUnavailable')
        return recorders
