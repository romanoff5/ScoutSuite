"""EKS region-scoped cluster metadata."""
from ScoutSuite.providers.aws.resources.regions import Regions

from .clusters import Clusters


class EKSPublic(Regions):
    _children = [(Clusters, 'clusters')]

    def __init__(self, facade):
        super().__init__('eks', facade)
