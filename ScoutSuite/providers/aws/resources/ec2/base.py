from ScoutSuite.providers.aws.resources.ec2.ami import AmazonMachineImages
from ScoutSuite.providers.aws.resources.ec2.snapshots import Snapshots
from ScoutSuite.providers.aws.resources.ec2.volumes import Volumes
from ScoutSuite.providers.aws.resources.ec2.vpcs import Ec2Vpcs
from ScoutSuite.providers.aws.resources.regions import Regions
from ScoutSuite.providers.aws.resources.ec2.regional_settings import RegionalSettings
from ScoutSuite.providers.aws.resources.ec2.direct_https import classify_direct_public_https
from ScoutSuite.providers.aws.resources.ec2.p2_checks import annotate_egress, annotate_ssh_key_reuse


class EC2(Regions):
    _children = [
        (Ec2Vpcs, 'vpcs'),
        (AmazonMachineImages, 'images'),
        (Snapshots, 'snapshots'),
        (Volumes, 'volumes'),
        (RegionalSettings, 'regional_settings')
    ]

    def __init__(self, facade):
        super().__init__('ec2', facade)

    async def fetch_all(self, regions=None, excluded_regions=None, partition_name='aws', **kwargs):
        await super().fetch_all(regions, excluded_regions, partition_name)

        for region in self['regions']:
            annotate_egress(self['regions'][region]['vpcs'])
            annotate_ssh_key_reuse(self['regions'][region]['vpcs'])
            for vpc in self['regions'][region]['vpcs'].values():
                groups = vpc.get('security_groups')
                for instance in vpc.get('instances', {}).values():
                    instance['public_https_status'] = classify_direct_public_https(instance, groups)

            self['regions'][region]['instances_count'] =\
                sum([len(vpc['instances']) for vpc in self['regions'][region]['vpcs'].values()])
            self['regions'][region]['security_groups_count'] =\
                sum([len(vpc['security_groups']) for vpc in self['regions'][region]['vpcs'].values()])
            self['regions'][region]['network_interfaces_count'] =\
                sum([len(vpc['network_interfaces']) for vpc in self['regions'][region]['vpcs'].values()])

        self['instances_count'] =\
            sum([region['instances_count'] for region in self['regions'].values()])
        self['security_groups_count'] =\
            sum([region['security_groups_count'] for region in self['regions'].values()])
        self['network_interfaces_count'] =\
            sum([region['network_interfaces_count'] for region in self['regions'].values()])
