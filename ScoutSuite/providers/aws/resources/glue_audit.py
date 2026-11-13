"""P2 regional Glue Data Catalog encryption governance evidence."""
import asyncio

from ScoutSuite.providers.aws.resources.regions import Regions


class GlueAudit(Regions):
    _children = []

    def __init__(self, facade):
        super().__init__('glue', facade)

    async def fetch_all(self, regions=None, excluded_regions=None,
                        partition_name='aws', **kwargs):
        self['regions'] = {}
        selected = await self.facade.build_region_list(
            self.service, regions, excluded_regions, partition_name)
        limit = asyncio.Semaphore(4)

        async def collect(region):
            async with limit:
                return region, await self.facade.glue.inventory_catalog(region)

        for region, inventory in await asyncio.gather(*(collect(r) for r in selected)):
            self['regions'][region] = {
                'id': region, 'name': region, 'region': region,
                'collection_status': inventory.get('status', 'unknown'),
                'catalog_encryption_status': inventory.get('catalog_encryption_status', 'unknown'),
                'connection_password_status': inventory.get('connection_password_status', 'unknown'),
                'database_usage': inventory.get('database_usage', 'unknown'),
                'connection_usage': inventory.get('connection_usage', 'unknown'),
            }
        self['regions_count'] = len(self['regions'])
