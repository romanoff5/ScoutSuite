import asyncio
import json
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from ScoutSuite.core.console import print_exception
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import get_and_set_concurrently
from ScoutSuite.providers.utils import run_concurrently


class CloudTrailFacade(AWSBaseFacade):
    def __init__(self, session=None):
        super().__init__(session)
        self.root_history_status = {}

    async def get_recent_root_write_events(self, region):
        """Only root management write events from bounded 90-day Event History."""
        self.root_history_status[region] = 'unknown'
        cli = AWSFacadeUtils.get_client('cloudtrail', self.session, region)
        if cli is None:
            self._record_collection_failure(RuntimeError('client'),'LookupRootEvents')
            return []
        before = datetime.now(timezone.utc)
        params = {
            'LookupAttributes': [{'AttributeKey':'Username','AttributeValue':'root'}],
            'StartTime': before-timedelta(days=89),
            'EndTime': before,
            'MaxResults': 50,
        }
        events, seen, tokens = [], set(), set()
        for _ in range(20):
            try:
                page = await run_concurrently(
                    lambda params=params.copy(): cli.lookup_events(**params))
            except Exception as error:
                self._record_collection_failure(error, 'LookupRootEvents')
                return events
            batch = page.get('Events') if isinstance(page,dict) else None
            if not isinstance(batch,list) or len(batch)>50:
                self._record_collection_failure(ValueError('MalformedPage'),'LookupRootEvents')
                return events
            for event in batch:
                if not isinstance(event,dict):
                    self._record_collection_failure(ValueError('MalformedEvent'),'LookupRootEvents')
                    return events
                raw = event.get('CloudTrailEvent')
                try:
                    body = json.loads(raw) if isinstance(raw,str) else None
                except (ValueError, TypeError):
                    body = None
                if not isinstance(body,dict) or not isinstance(body.get('userIdentity'),dict):
                    self._record_collection_failure(ValueError('MissingIdentity'),'LookupRootEvents')
                    return events
                if body['userIdentity'].get('type') != 'Root':
                    continue
                read_only = body.get('readOnly')
                # readOnly=false also appears for ConsoleLogin (including failed
                # logins). Restrict "performed management write" to successful
                # API calls; attempted/failed writes require a different rule.
                writes = (read_only is False or
                          isinstance(read_only,str) and read_only.lower() == 'false')
                if (not writes or body.get('eventType') != 'AwsApiCall'
                        or body.get('managementEvent') is False
                        or body.get('errorCode')):
                    continue
                eid = event.get('EventId')
                name = event.get('EventName')
                if not isinstance(eid,str) or not eid or not isinstance(name,str) or not name:
                    self._record_collection_failure(ValueError('MissingEventFields'),'LookupRootEvents')
                    return events
                if eid in seen:
                    continue
                seen.add(eid)
                stamp = event.get('EventTime')
                events.append({
                    'event_id':eid,'event_name':name,
                    'event_source':event.get('EventSource'),
                    'event_time':stamp.isoformat() if hasattr(stamp,'isoformat') else
                                 stamp if isinstance(stamp,str) else None,
                    'root_identity_verified':True,
                    'management_write_verified':True,
                })
            token = page.get('NextToken')
            if token in (None,''):
                self.root_history_status[region]='complete'
                return events
            if not isinstance(token,str) or token in tokens or len(token)>4096:
                self._record_collection_failure(ValueError('InvalidToken'),'LookupRootEvents')
                return events
            tokens.add(token)
            params['NextToken']=token
            # LookupEvents is rate-limited to 2 requests/s per account and Region.
            await asyncio.sleep(0.6)
        self._record_collection_failure(ValueError('PageLimit'),'LookupRootEvents')
        return events


    async def get_trails(self, region):
        if not hasattr(self, 'trail_inventory_status'):
            self.trail_inventory_status = {}
        self.trail_inventory_status[region] = 'unknown'
        client = AWSFacadeUtils.get_client('cloudtrail', self.session, region)
        if client is None:
            self.trail_inventory_status[region] = 'failed'
            self._record_collection_failure(RuntimeError('client'), 'DescribeTrails')
            return []
        try:
            trails = await run_concurrently(
                lambda: client.describe_trails()['trailList'])
        except Exception as e:
            self._record_collection_failure(e, 'DescribeTrails')
            self.trail_inventory_status[region] = 'denied' if (
                isinstance(e, ClientError) and e.response.get('Error', {}).get('Code')
                in ('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation')) else 'failed'
            print_exception(f'Failed to describe CloudTrail trail: {e}')
            trails = []
        else:
            self.trail_inventory_status[region] = 'complete'
            await get_and_set_concurrently(
                [self._get_and_set_status, self._get_and_set_selectors], trails, region=region)
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
