"""Region-scoped Network Firewall inventories in the default AWS scan."""
import asyncio
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.regions import Regions
from ScoutSuite.providers.utils import get_non_provider_id


class NetworkFirewallPublic(Regions):
    _children = []

    def __init__(self, facade):
        super().__init__('network-firewall', facade)

    async def fetch_all(self, regions=None, excluded_regions=None,
                        partition_name='aws', **kwargs):
        self['regions'] = {}
        chosen = await self.facade.build_region_list(
            self.service, regions, excluded_regions, partition_name)
        semaphore = asyncio.Semaphore(5)

        async def region_inventory(region):
            async with semaphore:
                return region, await self.facade.networkfirewall.inventory(region)

        for region, inv in await asyncio.gather(*(region_inventory(r) for r in chosen)):
            value = {'id': region, 'name': region, 'region': region,
                     'collection': inv.get('collection', {})}
            for kind in ('firewalls', 'policies', 'rule_groups'):
                entries = {}
                for row in inv.get(kind, []):
                    arn = row.get('arn')
                    if not isinstance(arn, str) or not arn.startswith('arn:'):
                        self.issue('InvalidResourceIdentity')
                        continue
                    key = get_non_provider_id(arn)
                    if key in entries:
                        self.issue('DuplicateResourceIdentity')
                        continue
                    entries[key] = {'id': key, 'region': region, **row}
                value[kind] = entries
                value[kind + '_count'] = len(entries)
            self['regions'][region] = value
        self['regions_count'] = len(self['regions'])
        for kind in ('firewalls', 'policies', 'rule_groups'):
            self[kind + '_count'] = sum(
                value[kind + '_count'] for value in self['regions'].values())

    @staticmethod
    def issue(reason):
        ctx = get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue('partial', 'networkfirewall', reason)
