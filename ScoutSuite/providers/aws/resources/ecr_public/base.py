"""Opt-in ECR repository inventory by region."""
from ScoutSuite.providers.aws.resources.regions import Regions

from .repositories import Repositories
from .registry_scanning import RegistryScanning


class ECRPublic(Regions):
    _children = [(Repositories, 'repositories'), (RegistryScanning, 'registry_scanning')]

    def __init__(self, facade):
        super().__init__('ecr', facade)
