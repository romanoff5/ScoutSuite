import asyncio

from ScoutSuite.core.console import print_exception, print_warning
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.utils import ec2_classic
from ScoutSuite.providers.utils import run_concurrently, get_and_set_concurrently


class ELBv2Facade(AWSBaseFacade):
    regional_load_balancers_cache_locks = {}
    load_balancers_cache = {}

    async def get_load_balancers(self, region: str, vpc: str):
        try:
            await self.cache_load_balancers(region)
            return [load_balancer for load_balancer in self.load_balancers_cache[region] if load_balancer['VpcId'] == vpc]
        except Exception as e:
            print_exception(f'Failed to get ELBv2 load balancers: {e}')
            return []

    async def cache_load_balancers(self, region):
        async with self.regional_load_balancers_cache_locks.setdefault(region, asyncio.Lock()):
            if region in self.load_balancers_cache:
                return

            self.load_balancers_cache[region] = \
                await AWSFacadeUtils.get_all_pages('elbv2', region, self.session,
                                                   'describe_load_balancers', 'LoadBalancers')

            for load_balancer in self.load_balancers_cache[region]:
                load_balancer['VpcId'] = \
                    load_balancer['VpcId'] if 'VpcId' in load_balancer and load_balancer['VpcId'] else ec2_classic

            await get_and_set_concurrently(
                [self._get_and_set_load_balancer_attributes], self.load_balancers_cache[region], region=region)

            await get_and_set_concurrently(
                [self._get_and_set_load_balancer_tags], self.load_balancers_cache[region], region=region)

    async def get_web_acl_for_load_balancer(self, region: str, arn: str):
        """Read-only wafv2:GetWebACLForResource; returns (associated|none|unknown, acl summary)."""
        client = AWSFacadeUtils.get_client('wafv2', self.session, region)
        if client is None:
            return 'unknown', None
        try:
            response = await run_concurrently(lambda: client.get_web_acl_for_resource(ResourceArn=arn))
        except Exception as e:
            AWSFacadeUtils.record_listing_failure('elbv2', e, 'GetWebACLForResource')
            print_exception(f'Failed to get the WAF web ACL of an ELBv2 load balancer: {e}')
            return 'unknown', None
        acl = response.get('WebACL') if isinstance(response, dict) else None
        if acl is None:
            return 'none', None
        if not isinstance(acl, dict) or not isinstance(acl.get('ARN'), str):
            AWSFacadeUtils.record_listing_failure('elbv2', ValueError(), 'MalformedWebACLForResource')
            return 'unknown', None
        return 'associated', {'arn': acl['ARN'], 'name': acl.get('Name'), 'id': acl.get('Id')}

    async def get_prefix_list_names(self, region: str, names: list):
        """Map managed prefix list IDs to names for the given names; None when unreadable."""
        cache = self.__dict__.setdefault('_prefix_list_names', {})
        if region in cache:
            return cache[region]
        client = AWSFacadeUtils.get_client('ec2', self.session, region)
        result = None
        if client is not None:
            try:
                response = await run_concurrently(lambda: client.describe_managed_prefix_lists(
                    Filters=[{'Name': 'prefix-list-name', 'Values': list(names)}]))
                result = {row['PrefixListId']: row['PrefixListName'] for row in response.get('PrefixLists', [])
                          if isinstance(row, dict) and 'PrefixListId' in row and 'PrefixListName' in row}
            except Exception as e:
                AWSFacadeUtils.record_listing_failure('elbv2', e, 'DescribeManagedPrefixLists')
                print_exception(f'Failed to describe managed prefix lists: {e}')
        cache[region] = result
        return result

    async def _get_and_set_load_balancer_attributes(self, load_balancer: dict, region: str):
        elbv2_client = AWSFacadeUtils.get_client('elbv2', self.session, region)
        try:
            load_balancer['attributes'] = await run_concurrently(
                lambda: elbv2_client.describe_load_balancer_attributes(
                    LoadBalancerArn=load_balancer['LoadBalancerArn'])['Attributes']
            )
        except Exception as e:
            print_exception(f'Failed to describe ELBv2 attributes: {e}')

    async def _get_and_set_load_balancer_tags(self, load_balancer: dict, region: str):
        elbv2_client = AWSFacadeUtils.get_client('elbv2', self.session, region)
        try:
            load_balancer['Tags'] = await run_concurrently(
                lambda: elbv2_client.describe_tags(
                    ResourceArns=[load_balancer['LoadBalancerArn']])['TagDescriptions'][0]['Tags']
            )
        except Exception as e:
            if 'LoadBalancerNotFound' in e:
                print_warning(f'Failed to describe ELBv2 tags: {e}')
            else:
                print_exception(f'Failed to describe ELBv2 tags: {e}')

    async def get_listeners(self, region: str, load_balancer_arn: str):
        return await AWSFacadeUtils.get_all_pages(
            'elbv2', region, self.session, 'describe_listeners', 'Listeners', LoadBalancerArn=load_balancer_arn)
