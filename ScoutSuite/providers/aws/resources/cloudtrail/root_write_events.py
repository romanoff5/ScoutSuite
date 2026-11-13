"""Sanitized recent root management write activity (90-day regional event history)."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id

class RootWriteEvents(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region=region

    async def fetch_all(self):
        for raw in await self.facade.cloudtrail.get_recent_root_write_events(self.region):
            eid=raw.get('event_id') if isinstance(raw,dict) else None
            if not isinstance(eid,str) or not eid:
                ctx=get_current_run_context()
                if ctx is not None:
                    ctx.record_collection_issue('partial','cloudtrail','MalformedRootEvent')
                continue
            key=get_non_provider_id(eid)
            if key in self:
                continue
            # No raw CloudTrailEvent (it contains request parameters and identities).
            self[key]={'id':key,'name':raw.get('event_name'),
                       'event_name':raw.get('event_name'),
                       'event_source':raw.get('event_source'),
                       'event_time':raw.get('event_time'),
                       'root_identity_verified':raw.get('root_identity_verified') is True,
                       'management_write_verified':raw.get('management_write_verified') is True,
                       'region':self.region}
