"""Region-scoped ECS inventory."""
from ScoutSuite.providers.aws.resources.regions import Regions

from .clusters import Clusters
from .task_definitions import TaskDefinitions


class ECSPublic(Regions):
    _children = [(Clusters, 'clusters'), (TaskDefinitions, 'task_definitions')]

    def __init__(self, facade):
        super().__init__('ecs', facade)
