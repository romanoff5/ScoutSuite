from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class Alarms(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        raw_alarms = await self.facade.cloudwatch.get_alarms(self.region)
        for raw_alarm in raw_alarms:
            name, resource = self._parse_alarm(raw_alarm)
            self[name] = resource

    def _parse_alarm(self, raw_alarm):
        raw_alarm['arn'] = raw_alarm.pop('AlarmArn')
        raw_alarm['name'] = raw_alarm.pop('AlarmName')

        # Drop some data
        for key in ['AlarmConfigurationUpdatedTimestamp', 'StateReason', 'StateReasonData', 'StateUpdatedTimestamp']:
            if key in raw_alarm:
                raw_alarm.pop(key)

        actions = raw_alarm.get('AlarmActions')
        enabled = raw_alarm.get('ActionsEnabled')
        raw_alarm['monitoring_action_status'] = (
            'not_applicable' if isinstance(actions, list) and not actions
            else 'disabled' if isinstance(actions, list) and actions and enabled is False
            else 'enabled' if isinstance(actions, list) and actions and enabled is True
            else 'unknown')

        alarm_id = get_non_provider_id(raw_alarm['arn'])
        return alarm_id, raw_alarm
