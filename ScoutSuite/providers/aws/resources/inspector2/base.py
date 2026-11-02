"""Inspector2 region-scoped resources."""
from ScoutSuite.providers.aws.resources.regions import Regions
from .accounts import InspectorAccounts
from .coverage import InspectorCoverage


class Inspector2(Regions):
    _children = [(InspectorAccounts, 'accounts'), (InspectorCoverage, 'coverage')]

    def __init__(self, facade):
        super().__init__('inspector2', facade)
