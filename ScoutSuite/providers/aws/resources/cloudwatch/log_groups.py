"""CloudWatch Logs group retention and optional customer-managed KMS evidence.

CloudWatch Logs encrypts data at rest with AWS-managed encryption even when
kmsKeyId is absent. Therefore this is a CMK governance review, not plaintext.
"""
from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class LogGroups(AWSResources):
    def __init__(self, facade: AWSFacade, region: str):
        super().__init__(facade)
        self.region = region

    async def fetch_all(self):
        raw = await self.facade.cloudwatch.get_log_groups(self.region)
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            name = entry.get('logGroupName')
            if not isinstance(name, str) or not name:
                continue
            retention = entry.get('retentionInDays')
            kms = entry.get('kmsKeyId')
            status = ('unlimited' if retention is None
                      else 'configured' if type(retention) is int and retention > 0
                      else 'unknown')
            kms_status = ('customer_kms' if isinstance(kms, str) and kms
                          else 'aws_managed' if kms is None
                          else 'unknown')
            key = get_non_provider_id(name)
            self[key] = {
                'id': key, 'name': name,
                'arn': entry.get('arn') or entry.get('logGroupArn'),
                'region': self.region,
                'retention_days': retention,
                'retention_status': status,
                'customer_kms_status': kms_status,
                'kms_key_arn': kms if isinstance(kms, str) else None,
            }
