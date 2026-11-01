"""IAM Access Analyzer regional inventory."""
from ScoutSuite.providers.aws.resources.regions import Regions

from .analyzers import Analyzers


class AccessAnalyzer(Regions):
    _children = [(Analyzers, 'analyzers')]

    def __init__(self, facade):
        super().__init__('accessanalyzer', facade)
