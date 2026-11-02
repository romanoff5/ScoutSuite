"""ECR private registry-level scanning configuration per selected region."""
from ScoutSuite.providers.aws.resources.base import AWSResources


class RegistryScanning(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        result = await self.facade.ecr.get_registry_scanning(self.region)
        if result is not None:
            self[self.region] = {
                'id': self.region,
                'name': 'Registry scanning ' + self.region,
                'region': self.region,
                'registry_id': result['registry_id'],
                'scan_type': result['scan_type'],
                'rules': result['rules'],
            }
