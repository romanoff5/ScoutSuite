from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSCompositeResources
from ScoutSuite.providers.utils import get_non_provider_id
from .listeners import Listeners
from .waf_exposure import cdn_catalog


class LoadBalancers(AWSCompositeResources):
    _children = [
        (Listeners, 'listeners')
    ]

    def __init__(self, facade: AWSFacade, region: str, vpc: str):
        super().__init__(facade)
        self.region = region
        self.vpc = vpc

    async def fetch_all(self):
        raw_load_balancers = await self.facade.elbv2.get_load_balancers(self.region, self.vpc)
        for raw_load_balancer in raw_load_balancers:
            id, load_balancer = self._parse_load_balancer(raw_load_balancer)
            self[id] = load_balancer

        await self._fetch_children_of_all_resources(
            resources=self,
            scopes={load_balancer_id: {'region': self.region, 'load_balancer_arn': load_balancer['arn']}
                    for (load_balancer_id, load_balancer) in self.items()}
        )

        # P3-B: independently collect registered targets. Incomplete AWS APIs are
        # UNKNOWN and will never be interpreted as an absent backend.
        for load_balancer in self.values():
            if load_balancer.get('Type') == 'application':
                status, groups = await self.facade.elbv2.get_target_group_inventory(
                    self.region, load_balancer['arn'])
                load_balancer['target_group_inventory_status'] = status
                load_balancer['target_groups'] = groups

        # RC9: AWS WAF association per internet-facing ALB; origin exposure is classified
        # in preprocessing once security groups are resolved from the EC2 inventory.
        prefix_lists = None
        for load_balancer in self.values():
            if load_balancer.get('Type') == 'application' and load_balancer.get('Scheme') == 'internet-facing':
                if prefix_lists is None:
                    prefix_lists = await self.facade.elbv2.get_prefix_list_names(
                        self.region, sorted(cdn_catalog()[2])) or {}
                    unreadable = self.facade.elbv2.__dict__.get('_prefix_list_names', {}).get(self.region) is None
                status, acl = await self.facade.elbv2.get_web_acl_for_load_balancer(self.region, load_balancer['arn'])
                load_balancer['waf_web_acl_status'] = status
                load_balancer['waf_web_acl'] = acl
                load_balancer['cdn_prefix_lists'] = None if unreadable else prefix_lists

        # After loading the listener information, map the protocols used in a new field for easier usage in rules
        for lb_id in self.keys():
            if lb_id is not None and len(self[lb_id]['listeners']) > 0:
                protocols = [x['Protocol'] for x in list(self[lb_id]['listeners'].values())]
                self[lb_id]['listener_protocols'] = protocols

    def _parse_load_balancer(self, load_balancer):
        load_balancer['arn'] = load_balancer.pop('LoadBalancerArn')
        load_balancer['name'] = load_balancer.pop('LoadBalancerName')
        load_balancer['security_groups'] = []
        load_balancer['listener_protocols'] = []
        load_balancer['isNetwork'] = load_balancer["Type"] == "network"

        if 'SecurityGroups' in load_balancer:
            for sg in load_balancer['SecurityGroups']:
                load_balancer['security_groups'].append({'GroupId': sg})
            load_balancer.pop('SecurityGroups')

        if 'Tags' in load_balancer and load_balancer['Tags']:
            load_balancer['tags'] = {x['Key']: x['Value'] for x in load_balancer['Tags']}
            load_balancer.pop('Tags')

        return get_non_provider_id(load_balancer['name']), load_balancer
