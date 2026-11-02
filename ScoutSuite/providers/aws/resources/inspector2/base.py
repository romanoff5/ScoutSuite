"""Inspector2 region-scoped resources with independently verified collection scope."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.regions import Regions
from .accounts import InspectorAccounts
from .coverage import InspectorCoverage


class Inspector2(Regions):
    _children = [(InspectorAccounts, 'accounts'), (InspectorCoverage, 'coverage')]

    def __init__(self, facade):
        super().__init__('inspector2', facade)

    async def fetch_all(self, **kwargs):
        await super().fetch_all(**kwargs)
        source = self.facade.inspector2
        states = getattr(source, 'coverage_collections', {})
        stats_api = getattr(source, 'get_coverage_statistics', None)
        organization_api = getattr(source, 'get_organization_context', None)
        for region, data in self['regions'].items():
            covered = data.get('coverage', {})
            metadata = states.get(region) if isinstance(states, dict) else None
            stats = await stats_api(region) if callable(stats_api) else None
            counted = len(covered)
            inventory_status = metadata.get('status') if isinstance(metadata, dict) else 'unknown'
            statistics_status = stats.get('status') if isinstance(stats, dict) else 'unknown'
            expected = stats.get('total_count') if isinstance(stats, dict) else None
            complete = (inventory_status == 'complete' and statistics_status == 'complete'
                        and type(expected) is int and counted == expected)
            if (inventory_status == 'complete' and statistics_status == 'complete'
                    and expected != counted):
                context = get_current_run_context()
                if context is not None:
                    context.record_collection_issue('partial', 'inspector2', 'CoverageCountMismatch')
            data['coverage_summary'] = {
                'status': 'complete' if complete else 'partial',
                'inventory_status': inventory_status,
                'statistics_status': statistics_status,
                'inventory_complete': inventory_status == 'complete',
                'statistics_complete': statistics_status == 'complete',
                'collected_records': counted,
                'inspector_reported_records': expected,
                'counts_by_scan_status': (stats.get('by_status', {})
                                          if isinstance(stats, dict) else {}),
                'pages': (metadata.get('pages') if isinstance(metadata, dict) else None),
                'scope': 'inspector_inventory_only',
                'aws_resource_inventory_compared': False,
                'resource_applicability_verified': False,
                'compliance_verified': False,
            }
            organization = (await organization_api(region)
                            if callable(organization_api) else None)
            if organization is None:
                organization = {
                    'status': 'unknown', 'role': 'unknown',
                    'members': {}, 'members_count': 0,
                    'organization_roster_verified': False,
                    'scope': 'inspector_member_relationships_only',
                }
            # Organization states are independent from own-account coverage.
            # Even full Inspector-member enumeration is not a census of all
            # accounts in AWS Organizations.
            data['organization'] = organization
            for account in data.get('accounts', {}).values():
                account['organization'] = {
                    'role': organization.get('role'),
                    'status': organization.get('status'),
                    'delegated_admin_account_id': organization.get('delegated_admin_account_id'),
                    'members_count': organization.get('members_count'),
                    'members_complete': organization.get('members_complete'),
                }
