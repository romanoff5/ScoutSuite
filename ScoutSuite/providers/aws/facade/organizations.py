"""M10-C: read-only, partition-aware AWS Organizations inventory.

Global service endpoint: commercial us-east-1, GovCloud us-gov-west-1,
China cn-northwest-1. No cross-account traversal or policy-document access.
"""
import asyncio

from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently


HOME_REGIONS = {
    'aws': 'us-east-1',
    'aws-us-gov': 'us-gov-west-1',
    'aws-cn': 'cn-northwest-1',
}
MAX_ACCOUNTS = 100000
MAX_ROOTS = 10000
MAX_ACCOUNT_PAGES = 5000
MAX_ROOT_PAGES = 500
PAGE_SIZE = 20

_ACCESS_DENIED = frozenset(('AccessDenied', 'AccessDeniedException',
                             'UnauthorizedOperation', 'AWSOrganizationsNotInUseException'))
_UNSUPPORTED = frozenset(('UnsupportedOperation', 'UnsupportedOperationException',
                          'UnknownOperationException'))


class OrganizationsFacade(AWSBaseFacade):
    def __init__(self, session, partition, owner_id=None):
        super().__init__(session)
        self.partition = partition
        self.owner_id = owner_id

    @staticmethod
    def _issue(status, reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue(status, 'organizations', reason)

    @staticmethod
    def _error_status(error):
        if isinstance(error, ClientError):
            code = error.response.get('Error', {}).get('Code', '')
            if code == 'AWSOrganizationsNotInUseException':
                return 'unsupported', 'NotInOrganization'
            if code in _ACCESS_DENIED:
                return 'denied', 'AccessDenied'
            if code in _UNSUPPORTED:
                return 'unsupported', 'UnsupportedOperation'
        return 'failed', 'APIError'

    async def _list(self, client, operation, result_key, max_pages, max_items):
        rows = []
        seen_tokens = set()
        seen_ids = set()
        next_token = None
        status = 'complete'
        for _ in range(max_pages):
            params = {'MaxResults': PAGE_SIZE}
            if next_token is not None:
                params['NextToken'] = next_token
            try:
                response = await run_concurrently(
                    lambda params=params: getattr(client, operation)(**params))
            except Exception as error:
                status, reason = self._error_status(error)
                if rows:
                    status = 'partial'
                self._issue(status, operation + reason)
                break

            batch = response.get(result_key) if isinstance(response, dict) else None
            if not isinstance(batch, list) or any(not isinstance(row, dict) for row in batch):
                status = 'partial' if rows else 'failed'
                self._issue(status, operation + 'MalformedPage')
                break

            bad_page = False
            for row in batch:
                identifier = row.get('Id')
                if not isinstance(identifier, str) or not identifier:
                    self._issue('partial', operation + 'InvalidIdentifier')
                    bad_page = True
                    break
                if identifier in seen_ids:
                    self._issue('partial', operation + 'DuplicateIdentifier')
                    bad_page = True
                    break
                if len(rows) >= max_items:
                    self._issue('partial', operation + 'ItemLimit')
                    bad_page = True
                    break
                seen_ids.add(identifier)
                rows.append(row)
            if bad_page:
                status = 'partial'
                break

            next_token = response.get('NextToken')
            # AWS Organizations can return an empty page WITH a valid token.
            if next_token is None:
                break
            if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
                status = 'partial'
                self._issue('partial', operation + 'InvalidToken')
                break
            seen_tokens.add(next_token)
        else:
            status = 'partial'
            self._issue('partial', operation + 'PageLimit')

        return rows, status

    async def get_organization_inventory(self):
        result = {
            'organization': None, 'roots': [], 'accounts': [],
            'collection': {'organization': 'unavailable',
                           'roots': 'not_collected', 'accounts': 'not_collected'},
        }
        region = HOME_REGIONS.get(self.partition)
        if region is None:
            self._issue('unsupported', 'UnknownPartition')
            return result

        client = AWSFacadeUtils.get_client('organizations', self.session, region)
        if client is None:
            self._issue('failed', 'ClientConstruction')
            return result

        try:
            response = await run_concurrently(client.describe_organization)
        except Exception as error:
            status, reason = self._error_status(error)
            self._issue(status, 'DescribeOrganization' + reason)
            result['collection']['organization'] = status
            return result

        organization = response.get('Organization') if isinstance(response, dict) else None
        if not isinstance(organization, dict) or not isinstance(organization.get('Id'), str):
            self._issue('failed', 'DescribeOrganizationMalformed')
            result['collection']['organization'] = 'failed'
            return result
        result['organization'] = organization
        result['collection']['organization'] = 'complete'

        for operation, field, pages, limit, label in (
            ('list_roots', 'Roots', MAX_ROOT_PAGES, MAX_ROOTS, 'roots'),
            ('list_accounts', 'Accounts', MAX_ACCOUNT_PAGES, MAX_ACCOUNTS, 'accounts'),
        ):
            rows, status = await self._list(client, operation, field, pages, limit)
            result[label] = rows
            result['collection'][label] = status
        return result


    async def get_account_region_inventory(self, accounts, management_id=None):
        """M10-R. Per-account Region status; never assume roles or mutate accounts.

        account:ListRegions requires organizational trusted access and read
        permissions for member AccountId. Its denial is recorded as unknown.
        Bounded concurrency, pagination, account count, and token detection.
        """
        MAX_REGION_ACCOUNTS = 2000
        MAX_REGION_PAGES = 20
        result = {}
        if not isinstance(accounts, dict):
            return result
        active = [(account_id, account) for account_id, account in sorted(accounts.items())
                  if isinstance(account, dict) and account.get('state') not in
                  ('SUSPENDED', 'CLOSED', 'PENDING_CLOSURE')]
        region = HOME_REGIONS.get(self.partition)
        if not region:
            self._issue('unsupported', 'AccountRegionsUnknownPartition')
            return result
        client = AWSFacadeUtils.get_client('account', self.session, region)
        if client is None:
            self._issue('failed', 'AccountRegionsClientUnavailable')
            return result

        semaphore = asyncio.Semaphore(8)

        async def one(account_id):
            async with semaphore:
                record = {'regions': {}, 'collection_status': 'complete'}
                # AWS forbids specifying management AccountId explicitly;
                # delegated admins also cannot query it as a member account.
                if account_id == management_id and self.owner_id != management_id:
                    record['collection_status'] = 'not_collected'
                    self._issue('partial', 'AccountRegionsManagementRequiresManagementCredentials')
                    return account_id, record
                params = {'MaxResults': 50}
                if account_id != self.owner_id:
                    params['AccountId'] = account_id
                visited = set()
                for _ in range(MAX_REGION_PAGES):
                    try:
                        response = await run_concurrently(
                            lambda params=dict(params): client.list_regions(**params))
                    except Exception as error:
                        status, reason = self._error_status(error)
                        record['collection_status'] = status
                        self._issue(status, 'AccountListRegions' + reason + ':' + account_id)
                        break
                    batch = response.get('Regions') if isinstance(response, dict) else None
                    if not isinstance(batch, list):
                        record['collection_status'] = 'partial'
                        self._issue('partial', 'AccountListRegionsMalformed:' + account_id)
                        break
                    bad = False
                    for item in batch:
                        if not isinstance(item, dict):
                            bad = True
                            break
                        name, status = item.get('RegionName'), item.get('RegionOptStatus')
                        if (not isinstance(name, str) or not name
                                or status not in ('ENABLED', 'DISABLED', 'ENABLING',
                                                  'DISABLING', 'ENABLED_BY_DEFAULT')
                                or name in record['regions']):
                            bad = True
                            break
                        record['regions'][name] = status
                    if bad:
                        record['collection_status'] = 'partial'
                        self._issue('partial', 'AccountListRegionsInvalidRow:' + account_id)
                        break
                    token = response.get('NextToken')
                    if token is None:
                        break
                    if not isinstance(token, str) or not token or token in visited:
                        record['collection_status'] = 'partial'
                        self._issue('partial', 'AccountListRegionsInvalidToken:' + account_id)
                        break
                    visited.add(token)
                    params['NextToken'] = token
                else:
                    record['collection_status'] = 'partial'
                    self._issue('partial', 'AccountListRegionsPageLimit:' + account_id)
                return account_id, record

        # Do not silently omit accounts beyond the explicit collection bound.
        for account_id, _ in active[MAX_REGION_ACCOUNTS:]:
            result[account_id] = {'regions': {}, 'collection_status': 'not_collected'}
        if len(active) > MAX_REGION_ACCOUNTS:
            self._issue('partial', 'AccountListRegionsAccountLimit')
        for account_id, record in await asyncio.gather(
                *(one(account_id) for account_id, _ in active[:MAX_REGION_ACCOUNTS])):
            result[account_id] = record
        return result
