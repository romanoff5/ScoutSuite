from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.rds.clusters import RDSClusters
from ScoutSuite.providers.aws.resources.rds.proxies import RDSProxies
from ScoutSuite.providers.aws.resources.rds.parametergroups import ParameterGroups
from ScoutSuite.providers.aws.resources.rds.securitygroups import SecurityGroups
from ScoutSuite.providers.aws.resources.rds.vpcs import RDSVpcs
from ScoutSuite.providers.aws.resources.regions import Regions


class RDS(Regions):
    _children = [
        (RDSClusters, 'clusters'),
        (RDSProxies, 'proxies'),
        (RDSVpcs, 'vpcs'),
        (ParameterGroups, 'parameter_groups'),
        (SecurityGroups, 'security_groups')
    ]

    def __init__(self, facade: AWSFacade):
        super().__init__('rds', facade)

    async def fetch_all(self, regions=None, excluded_regions=None, partition_name='aws', **kwargs):
        await super().fetch_all(regions, excluded_regions, partition_name)

        for region in self['regions']:
            self['regions'][region]['proxies_inventory_status'] = getattr(
                self.facade.rds, 'proxy_inventory_status', {}).get(region, 'unknown')
            self['regions'][region]['instances_count'] =\
                sum([len(vpc['instances']) for vpc in self['regions'][region]['vpcs'].values()])
            self['regions'][region]['snapshots_count'] =\
                sum([len(vpc['snapshots']) for vpc in self['regions'][region]['vpcs'].values()])
            self['regions'][region]['subnet_groups_count'] =\
                sum([len(vpc['subnet_groups']) for vpc in self['regions'][region]['vpcs'].values()])
        
        self['proxies_count'] = sum(len(region['proxies']) for region in self['regions'].values())
        self['instances_count'] = sum([region['instances_count'] for region in self['regions'].values()])
        self['snapshots_count'] = sum([region['snapshots_count'] for region in self['regions'].values()])
        self['subnet_groups_count'] = sum([region['subnet_groups_count'] for region in self['regions'].values()])
