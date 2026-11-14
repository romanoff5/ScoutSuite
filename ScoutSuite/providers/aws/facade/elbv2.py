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

    async def get_target_group_inventory(self, region, load_balancer_arn):
        """Registered instance/IP targets of the LB; UNKNOWN on denied or truncated API."""
        client = AWSFacadeUtils.get_client('elbv2', self.session, region)
        if client is None:
            return 'unknown', []
        try:
            def collect():
                groups, marker, seen = [], None, set()
                for _ in range(20):
                    args = {'LoadBalancerArn': load_balancer_arn, 'PageSize': 100}
                    if marker:
                        args['Marker'] = marker
                    response = client.describe_target_groups(**args)
                    page = response.get('TargetGroups') if isinstance(response, dict) else None
                    if not isinstance(page, list) or any(not isinstance(g, dict) for g in page):
                        raise ValueError('MalformedTargetGroups')
                    groups.extend(page)
                    token = response.get('NextMarker')
                    if not token:
                        break
                    if not isinstance(token, str) or token in seen:
                        raise ValueError('InvalidTargetGroupsPagination')
                    seen.add(token)
                    marker = token
                else:
                    raise ValueError('TargetGroupPageLimit')
                if len(groups) > 1000:
                    raise ValueError('TargetGroupCountLimit')
                out = []
                for group in groups:
                    arn = group.get('TargetGroupArn')
                    if not isinstance(arn, str) or not arn:
                        raise ValueError('MalformedTargetGroupArn')
                    detail = client.describe_target_health(TargetGroupArn=arn)
                    rows = detail.get('TargetHealthDescriptions') if isinstance(detail, dict) else None
                    if not isinstance(rows, list) or len(rows) > 10000:
                        raise ValueError('MalformedTargetHealth')
                    for row in rows:
                        if not isinstance(row, dict) or not isinstance(row.get('Target'), dict):
                            raise ValueError('MalformedTargetDescription')
                    out.append({'arn': arn, 'target_type': group.get('TargetType'),
                                'port': group.get('Port'), 'registered_targets': [
                                    {'id': row['Target'].get('Id'),
                                     'port': row['Target'].get('Port'),
                                     'health_state': (row.get('TargetHealth') or {}).get('State')}
                                    for row in rows]})
                return out
            result = await run_concurrently(collect)
            return 'complete', result
        except Exception as error:
            AWSFacadeUtils.record_listing_failure('elbv2', error, 'DescribeTargetGroupsOrHealth')
            print_exception('Unable to verify ELBv2 target groups: ' + type(error).__name__)
            return 'unknown', []

    async def get_listener_certificate_inventory(self, region, listener_arn):
        """All HTTPS listener certificates, including non-default SNI attachments."""
        client = AWSFacadeUtils.get_client('elbv2', self.session, region)
        if client is None:
            return 'unknown', []
        try:
            def collect():
                arns, marker, seen = [], None, set()
                for _ in range(20):
                    args = {'ListenerArn': listener_arn, 'PageSize': 100}
                    if marker:
                        args['Marker'] = marker
                    result = client.describe_listener_certificates(**args)
                    rows = result.get('Certificates') if isinstance(result, dict) else None
                    if not isinstance(rows, list):
                        raise ValueError('MalformedListenerCertificates')
                    for item in rows:
                        arn = item.get('CertificateArn') if isinstance(item, dict) else None
                        if not isinstance(arn, str) or not arn:
                            raise ValueError('MalformedListenerCertificateArn')
                        if arn not in arns:
                            arns.append(arn)
                    token = result.get('NextMarker')
                    if not token:
                        return arns
                    if not isinstance(token, str) or token in seen:
                        raise ValueError('InvalidListenerCertificatePagination')
                    seen.add(token)
                    marker = token
                raise ValueError('ListenerCertificatePageLimit')
            data = await run_concurrently(collect)
            return 'complete', data
        except Exception as error:
            AWSFacadeUtils.record_listing_failure('elbv2', error, 'DescribeListenerCertificates')
            print_exception('Unable to verify listener certificates: ' + type(error).__name__)
            return 'unknown', []
