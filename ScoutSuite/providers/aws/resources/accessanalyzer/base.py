"""IAM Access Analyzer regional inventory."""
from ScoutSuite.providers.aws.resources.regions import Regions

from .analyzers import Analyzers


class AccessAnalyzer(Regions):
    _children = [(Analyzers, 'analyzers')]

    def __init__(self, facade):
        super().__init__('accessanalyzer', facade)

    async def fetch_all(self, **kwargs):
        await super().fetch_all(**kwargs)
        census = getattr(self.facade.accessanalyzer, 'analyzer_census', {})
        for region, data in self.get('regions', {}).items():
            analyzers = data.get('analyzers') or {}
            record = census.get(region) if isinstance(census, dict) else None
            complete = (isinstance(record, dict) and record.get('complete') is True
                        and record.get('count') == len(analyzers))
            data['analyzer_census_status'] = 'complete' if complete else 'incomplete'
            data['active_analyzers_count'] = sum(
                1 for analyzer in analyzers.values() if analyzer.get('status') == 'ACTIVE')
            data['analyzer_status'] = (
                'unknown' if not complete else
                'not_configured' if not analyzers else
                'active' if data['active_analyzers_count'] else 'inactive_only')
            # Region-level gap only; DISABLED/FAILED analyzers have their own rule.
            # An organization analyzer in another account is not visible here.
            data['analyzer_not_configured'] = data['analyzer_status'] == 'not_configured'
