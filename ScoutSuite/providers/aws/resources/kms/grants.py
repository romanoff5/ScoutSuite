from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.utils import format_arn


class Grants(AWSResources):
    def __init__(self, facade: AWSFacade, region: str, key_id: str):
        super().__init__(facade)
        self.region = region
        self.key_id = key_id
        self.partition = facade.partition
        self.service = 'kms'
        self.resource_type = 'grant'

    async def fetch_all(self):
        collector = getattr(self.facade.kms, 'get_grants_with_status', None)
        if collector is not None:
            raw_grants, status = await collector(self.region, self.key_id)
        else:
            # Older/fake facade cannot prove paginator completeness.
            raw_grants = await self.facade.kms.get_grants(self.region, self.key_id)
            status = 'unknown'
        if not isinstance(raw_grants, list):
            raw_grants, status = [], 'partial'
        for raw_grant in raw_grants:
            if (not isinstance(raw_grant, dict)
                    or not isinstance(raw_grant.get('GrantId'), str)
                    or not raw_grant['GrantId'] or raw_grant['GrantId'] in self):
                status = 'partial'
                continue
            ident, grant = self._parse_grant(raw_grant)
            self[ident] = grant
        census = getattr(self.facade.kms, 'grants_collection_status', None)
        if not isinstance(census, dict):
            census = {}
            self.facade.kms.grants_collection_status = census
        census[(self.region, self.key_id)] = status

    def _parse_grant(self, raw_grant):
        issuer = raw_grant.get('IssuingAccount')
        if isinstance(issuer, str) and issuer.startswith('arn:'):
            account_parts = issuer.split(':', 5)
            account = account_parts[4] if len(account_parts) == 6 else None
        else:
            account = issuer if isinstance(issuer, str) else None
        if not isinstance(account, str) or not account.isdigit() or len(account) != 12:
            account = None
        grant_dict = {
            'key_id': raw_grant.get('KeyId'),
            'grant_id': raw_grant.get('GrantId'),
            'name': raw_grant.get('Name'),
            'create_date': raw_grant.get('CreationDate'),
            'grantee_principal': raw_grant.get('GranteePrincipal'),
            'retiring_principal': raw_grant.get('RetiringPrincipal'),
            'issuing_account': raw_grant.get('IssuingAccount'),
            'operations': raw_grant.get('Operations'),
            'constraints': raw_grant.get('Constraints'),
            'arn': (format_arn(self.partition, self.service, self.region,
                               account, raw_grant.get('GrantId'), self.resource_type)
                    if account is not None else None)
        }
        return grant_dict['grant_id'], grant_dict
