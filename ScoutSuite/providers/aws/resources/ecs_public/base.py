"""Region-scoped ECS inventory."""
from ScoutSuite.providers.aws.resources.regions import Regions

from .clusters import Clusters


class ECSPublic(Regions):
    _children = [(Clusters, 'clusters')]

    def __init__(self, facade):
        super().__init__('ecs', facade)
