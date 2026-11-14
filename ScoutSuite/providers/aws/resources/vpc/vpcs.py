from ScoutSuite.providers.aws.resources.vpcs import Vpcs

from .network_acls import NetworkACLs
from .subnets import Subnets
from .p4a_default_vpc import classify_default_vpc_gateway


class RegionalVpcs(Vpcs):
    _children = [
        (NetworkACLs, 'network_acls'),
        (Subnets, 'subnets'),
    ]

    async def fetch_all(self):
        await super().fetch_all()
        for vpc in self.values():
            if vpc.get('default') is True:
                evidence = await self.facade.ec2.get_default_vpc_usage(
                    self.region, vpc['id'])
            else:
                evidence = {'status': 'not_applicable'}
            vpc['default_vpc_gateway_status'] = classify_default_vpc_gateway(
                vpc.get('default'), evidence)
            vpc['default_vpc_gateway_inventory_status'] = evidence.get('status', 'unknown')
            vpc['default_vpc_igw_count'] = evidence.get('igw_count')
            vpc['default_vpc_eni_count'] = evidence.get('eni_count')
