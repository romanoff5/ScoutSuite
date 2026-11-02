"""Region-scoped Security Hub inventory."""
from ScoutSuite.providers.aws.resources.regions import Regions

from .hubs import Hubs


class SecurityHubPublic(Regions):
    _children = [(Hubs, 'hubs')]

    def __init__(self, facade):
        super().__init__('securityhub', facade)
