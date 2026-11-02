"""M10-C: read-only, partition-aware AWS Organizations inventory.

Global service endpoint: commercial us-east-1, GovCloud us-gov-west-1,
China cn-northwest-1. No cross-account traversal or policy-document access.
"""
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
MAX_ACCOUNTS = 5000
MAX_ROOTS = 100
MAX_ACCOUNT_PAGES = 250
MAX_ROOT_PAGES = 10
PAGE_SIZE = 20

_ACCESS_DENIED = frozenset(('AccessDenied', 'AccessDeniedException',
                             'UnauthorizedOperation', 'AWSOrganizationsNotInUseException'))
_UNSUPPORTED = frozenset(('UnsupportedOperation', 'UnsupportedOperationException',
                          'UnknownOperationException'))


class OrganizationsFacade(AWSBaseFacade):
    def __init__(self, session, partition):
        super().__init__(session)
        self.partition = partition

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
