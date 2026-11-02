"""Region-scoped backup vault and plan inventory."""
from ScoutSuite.providers.aws.resources.regions import Regions

from .vaults import Vaults
from .plans import Plans


class BackupPublic(Regions):
    _children = [(Vaults, 'vaults'), (Plans, 'plans')]

    def __init__(self, facade):
        super().__init__('backup', facade)
