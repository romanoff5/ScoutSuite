from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources


class Listeners(AWSResources):
    def __init__(self, facade: AWSFacade, region: str, load_balancer_arn: str):
        super().__init__(facade)
        self.region = region
        self.load_balancer_arn = load_balancer_arn

    async def fetch_all(self):
        listeners = await self.facade.elbv2.get_listeners(self.region, self.load_balancer_arn)
        for raw_listener in listeners:
            # Preserve ARN for the SNI inventory before the legacy parser pops it.
            arn = raw_listener.get('ListenerArn')
            protocol = raw_listener.get('Protocol')
            id, listener = self._parse_listener(raw_listener)
            if protocol in ('HTTPS', 'TLS'):
                if not isinstance(arn, str) or not arn:
                    status, certificates = 'unknown', []
                else:
                    status, certificates = await self.facade.elbv2.get_listener_certificate_inventory(
                        self.region, arn)
                listener['certificate_inventory_status'] = status
                listener['certificate_arns'] = certificates
            else:
                listener['certificate_inventory_status'] = 'not_applicable'
                listener['certificate_arns'] = []
            self[id] = listener

    def _parse_listener(self, raw_listener):
            raw_listener.pop('ListenerArn')
            raw_listener.pop('LoadBalancerArn')
            port = raw_listener.pop('Port')
            return port, raw_listener
