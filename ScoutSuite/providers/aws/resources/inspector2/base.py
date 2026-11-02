"""Regional Inspector v2 current-account status only."""
from ScoutSuite.providers.aws.resources.regions import Regions

from .accounts import Accounts


class Inspector2Public(Regions):
    _children = [(Accounts, 'accounts')]

    def __init__(self, facade):
        super().__init__('inspector2', facade)
