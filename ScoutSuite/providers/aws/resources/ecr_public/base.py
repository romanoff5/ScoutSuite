"""Opt-in ECR repository inventory by region."""
from ScoutSuite.providers.aws.resources.regions import Regions

from .repositories import Repositories


class ECRPublic(Regions):
    _children = [(Repositories, 'repositories')]

    def __init__(self, facade):
        super().__init__('ecr', facade)
