from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class Recorders(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        raw_recorders = await self.facade.config.get_recorders(self.region)
        for raw_recorder in raw_recorders:
            name, resource = self._parse_recorder(raw_recorder)
            self[name] = resource

    def _parse_recorder(self, raw_recorder):
        recorder = {}
        recorder['name'] = raw_recorder['name']
        recorder['region'] = self.region
        recorder['role_ARN'] = raw_recorder.get('roleARN')
        recorder['recording_group'] = raw_recorder.get('recordingGroup')
        status = raw_recorder.get('ConfigurationRecordersStatus') or {}
        recorder['enabled'] = status.get('recording')
        recorder['last_status'] = status.get('lastStatus')
        recorder['last_start_time'] = status.get('lastStartTime')
        recorder['last_status_change_time'] = status.get('lastStatusChangeTime')
        recorder['arn'] = raw_recorder.get('arn')
        recorder['recording_scope'] = raw_recorder.get('recordingScope')
        recorder['recording_mode'] = raw_recorder.get('recordingMode')
        recorder['recording_strategy'] = (
            (raw_recorder.get('recordingGroup') or {}).get('recordingStrategy')
        )
        recorder['service_principal'] = raw_recorder.get('servicePrincipal')
        recorder['status_complete'] = bool(status)
        return get_non_provider_id(recorder['name']), recorder
