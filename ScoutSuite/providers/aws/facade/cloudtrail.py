from botocore.exceptions import ClientError

from ScoutSuite.core.console import print_exception
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import get_and_set_concurrently
from ScoutSuite.providers.utils import run_concurrently


class CloudTrailFacade(AWSBaseFacade):
    async def get_trails(self, region):
        client = AWSFacadeUtils.get_client('cloudtrail', self.session, region)
        try:
            trails = await run_concurrently(
                lambda: client.describe_trails()['trailList'])
        except Exception as e:
            print_exception(f'Failed to describe CloudTrail trail: {e}')
            trails = []
        else:
            await get_and_set_concurrently(
                [self._get_and_set_status, self._get_and_set_selectors], trails, region=region)
        finally:
            return trails

    @staticmethod
    def _record_collection_failure(error, reason):
        context = get_current_run_context()
        if context is not None:
            denied = isinstance(error, ClientError) and error.response.get(
                'Error', {}).get('Code', '') in (
                    'AccessDenied', 'AccessDeniedException',
                    'UnauthorizedOperation', 'InsufficientEncryptionPolicyException'
                )
            context.record_collection_issue(
                'denied' if denied else 'failed', 'cloudtrail', reason
            )

    async def _get_and_set_status(self, trail: {}, region: str):
        # Both trail status and selectors belong to the trail home region.
        home_region = trail.get('HomeRegion') or region
        client = AWSFacadeUtils.get_client('cloudtrail', self.session, home_region)
        if client is None:
            self._record_collection_failure(RuntimeError('client'), 'TrailStatus')
            return
        try:
            status = await run_concurrently(
                lambda: client.get_trail_status(Name=trail['TrailARN'])
            )
            trail.update(status)
        except Exception as error:
            self._record_collection_failure(error, 'TrailStatus')
            print_exception('Unable to retrieve CloudTrail status')

    async def _get_and_set_selectors(self, trail: {}, region: str):
        home_region = trail.get('HomeRegion') or region
        client = AWSFacadeUtils.get_client('cloudtrail', self.session, home_region)
        trail.setdefault('EventSelectors', [])
        trail.setdefault('AdvancedEventSelectors', [])
        if client is None:
            trail['selector_collection_status'] = 'failed'
            self._record_collection_failure(RuntimeError('client'), 'EventSelectors')
            return
        try:
            # Full TrailARN also covers organization trails from member accounts.
            response = await run_concurrently(
                lambda: client.get_event_selectors(TrailName=trail['TrailARN'])
            )
            if not isinstance(response, dict):
                raise ValueError('MalformedSelectors')
            basic = response.get('EventSelectors', [])
            advanced = response.get('AdvancedEventSelectors', [])
            if not isinstance(basic, list) or not isinstance(advanced, list):
                raise ValueError('MalformedSelectors')
            trail['EventSelectors'] = basic
            trail['AdvancedEventSelectors'] = advanced
            trail['selector_collection_status'] = 'success'
        except Exception as error:
            trail['selector_collection_status'] = 'failed'
            self._record_collection_failure(error, 'EventSelectors')
            print_exception('Unable to retrieve CloudTrail event selectors')
