"""Region-scoped Security Hub inventory."""
from ScoutSuite.providers.aws.resources.regions import Regions

from .hubs import Hubs


class SecurityHubPublic(Regions):
    _children = [(Hubs, 'hubs')]

    def __init__(self, facade):
        super().__init__('securityhub', facade)

    async def fetch_all(self, **kwargs):
        await super().fetch_all(**kwargs)
        states = getattr(self.facade.securityhub, 'hub_states', {})
        for region, data in self.get('regions', {}).items():
            data['hub_subscription_status'] = states.get(region, 'unknown')

