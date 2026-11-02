"""M10-O SSM regional inventories, exposed in the normal AWS report."""
import asyncio

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.regions import Regions
from ScoutSuite.providers.utils import get_non_provider_id


def issue(reason):
    ctx = get_current_run_context()
    if ctx is not None:
        ctx.record_collection_issue('partial', 'ssm', reason)


class SSMPublic(Regions):
    _children = []

    def __init__(self, facade):
        super().__init__('ssm', facade)

    async def fetch_all(self, regions=None, excluded_regions=None,
                        partition_name='aws', **kwargs):
        self['regions'] = {}
        chosen = await self.facade.build_region_list(
            self.service, regions, excluded_regions, partition_name)
        semaphore = asyncio.Semaphore(4)

        async def collect(region):
            async with semaphore:
                return region, await self.facade.ssm.inventory(region)

        for region, inventory in await asyncio.gather(*(collect(x) for x in chosen)):
            data = {'id': region, 'name': region, 'region': region,
                    'collection': inventory.get('collection', {}),
                    'ec2_comparison_complete': inventory.get('ec2_comparison_complete', False),
                    'scan_freshness_days': inventory.get('scan_freshness_days', 7),
                    'scan_success_independently_verified': False}
            for key, identity in (('managed_nodes', 'instance_id'),
                                  ('patch_baselines', 'BaselineId'),
                                  ('patch_groups', 'PatchGroup')):
                entries = {}
                for raw in inventory.get(key, []):
                    value = raw.get(identity) if isinstance(raw, dict) else None
                    if not isinstance(value, str) or not value:
                        issue('Invalid' + key + 'Identity')
                        continue
                    index = get_non_provider_id(value)
                    if index in entries:
                        issue('Duplicate' + key + 'Identity')
                        continue
                    entries[index] = {'id': index, 'region': region,
                                      'name': raw.get('name') or raw.get('PatchGroup')
                                      or raw.get('BaselineName') or value, **raw}
                data[key] = entries
                data[key + '_count'] = len(entries)
            self['regions'][region] = data
        self['regions_count'] = len(self['regions'])
        for key in ('managed_nodes', 'patch_baselines', 'patch_groups'):
            self[key + '_count'] = sum(data[key + '_count']
                                      for data in self['regions'].values())
