"""Region-scoped GuardDuty detector inventory."""
from ScoutSuite.providers.aws.resources.regions import Regions

from .detectors import Detectors


class GuardDutyPublic(Regions):
    _children = [(Detectors, 'detectors')]

    def __init__(self, facade):
        super().__init__('guardduty', facade)
