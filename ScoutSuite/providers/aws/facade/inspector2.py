"""Bounded, read-only Amazon Inspector2 status and coverage (M10-D)."""
from botocore.exceptions import ClientError
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently

# EC2/ECR are required by the Inspector2 ResourceState response model.
# Remaining resource categories are optional and absent means UNKNOWN, not DISABLED.
SCAN_TYPES = ('ec2', 'ecr', 'lambda', 'lambdaCode', 'codeRepository')
REQUIRED_SCAN_TYPES = frozenset(('ec2', 'ecr'))
VALID_SCAN_STATES = frozenset((
    'ENABLING', 'ENABLED', 'DISABLING', 'DISABLED', 'SUSPENDING', 'SUSPENDED',
))
# 200 is the AWS ListCoverage maximum page size. At 2,500 pages this
# supports 500,000 records per account and Region rather than only 500.
# Limits are circuit breakers, NEVER a successful/complete collection.
MAX_PAGES = 2500
PAGE_SIZE = 200
MAX_COVERED_RESOURCES = MAX_PAGES * PAGE_SIZE
MAX_STATISTICS_PAGES = 20
MAX_TOKEN_LENGTH = 1000000
_DENIED = ('AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation')
_UNSUPPORTED = ('UnsupportedOperationException', 'UnknownOperationException')


class CoverageRows(list):
    """List-compatible collection carrying explicit pagination completeness."""

    def __init__(self, records=(), complete=False, pages=0, status='failed'):
        super().__init__(records)
        self.complete = complete
        self.pages = pages
        self.status = status


class Inspector2Facade(AWSBaseFacade):
    def __init__(self, session, owner_id):
        super().__init__(session)
        self.owner_id = owner_id
        self.coverage_collections = {}

    @staticmethod
    def _issue(status, reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue(status, 'inspector2', reason)

    def _client(self, region):
        try:
            client = AWSFacadeUtils.get_client('inspector2', self.session, region)
        except Exception:
            self._issue('failed', 'ClientConstruction')
            return None
        if client is None:
            self._issue('failed', 'ClientConstruction')
        return client

    def _error(self, error, operation, partial=False):
        if isinstance(error, ClientError):
            code = error.response.get('Error', {}).get('Code', '')
            state = 'denied' if code in _DENIED else 'unsupported' if code in _UNSUPPORTED else 'failed'
        else:
            state = 'failed'
        self._issue('partial' if partial else state, operation + state.capitalize())
        return 'partial' if partial else state

    def _account_valid(self):
        valid = (isinstance(self.owner_id, str) and len(self.owner_id) == 12
                 and self.owner_id.isascii() and self.owner_id.isdigit())
        if not valid:
            self._issue('failed', 'InvalidAccountId')
        return valid

    async def get_accounts(self, region):
        if not self._account_valid():
            return []
        client = self._client(region)
        if client is None:
            return []
        try:
            response = await run_concurrently(
                lambda: client.batch_get_account_status(accountIds=[self.owner_id]))
        except Exception as error:
            self._error(error, 'BatchGetAccountStatus')
            return []
        accounts = response.get('accounts') if isinstance(response, dict) else None
        failures = response.get('failedAccounts', []) if isinstance(response, dict) else None
        if not isinstance(accounts, list) or not isinstance(failures, list):
            self._issue('failed', 'MalformedAccountStatus')
            return []
        if failures:
            # Even when a partial account object is also returned, the status
            # response is not authoritative. Never promote that object to PASS.
            self._issue('partial' if accounts else 'failed', 'FailedAccountStatus')
            return []
        if len(accounts) != 1 or not isinstance(accounts[0], dict) or accounts[0].get('accountId') != self.owner_id:
            self._issue('partial' if accounts else 'failed', 'MissingOrUnexpectedAccount')
            return []
        raw = accounts[0]
        state = raw.get('state')
        if not isinstance(state, dict) or not isinstance(state.get('status'), str):
            self._issue('partial', 'MalformedAccountState')
            return []
        resources = raw.get('resourceState')
        if not isinstance(resources, dict):
            self._issue('partial', 'MalformedResourceState')
            resources = {}
        resource_states = {}
        for name in SCAN_TYPES:
            resource_state = resources.get(name)
            if resource_state is None:
                resource_states[name] = None
                if name in REQUIRED_SCAN_TYPES:
                    self._issue('partial', 'MissingRequiredScanType')
                continue
            if not isinstance(resource_state, dict):
                resource_states[name] = None
                self._issue('partial', 'MalformedScanType')
                continue
            status = resource_state.get('status')
            if not isinstance(status, str) or status not in VALID_SCAN_STATES:
                resource_states[name] = None
                self._issue('partial', 'InvalidScanTypeStatus')
                continue
            resource_states[name] = status
        # Preserve original resource_states field for existing JSON/SQLite
        # consumers. Add scan_types at the normalized resource layer.
        return [{'account_id': self.owner_id, 'status': state['status'],
                 'resource_states': resource_states}]

    def _finish_coverage(self, region, rows, pages=0, status='failed'):
        """Preserve evidence and explicit collection state separately from resource rows."""
        complete = status == 'complete'
        result = CoverageRows(rows, complete=complete, pages=pages, status=status)
        self.coverage_collections[region] = {
            'status': status, 'complete': complete, 'pages': pages,
            'items': len(result), 'account_id': self.owner_id,
        }
        return result

    async def get_coverage(self, region):
        """Fully paginate own-account coverage; preserve partial rows on failure."""
        if not self._account_valid():
            return self._finish_coverage(region, [], status='failed')
        client = self._client(region)
        if client is None:
            return self._finish_coverage(region, [], status='failed')
        collected, seen_tokens, seen_resources = [], set(), set()
        token = None
        incomplete = False
        for page_index in range(MAX_PAGES):
            params = {'maxResults': PAGE_SIZE,
                      'filterCriteria': {'accountId': [
                          {'comparison': 'EQUALS', 'value': self.owner_id}]}}
            if token is not None:
                params['nextToken'] = token
            try:
                response = await run_concurrently(
                    lambda params=params: client.list_coverage(**params))
            except Exception as error:
                state = self._error(error, 'ListCoverage', partial=bool(collected))
                return self._finish_coverage(region, collected, page_index, state)
            pages = page_index + 1
            rows = response.get('coveredResources') if isinstance(response, dict) else None
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                self._issue('partial' if collected else 'failed', 'MalformedCoveragePage')
                return self._finish_coverage(region, collected, pages, 'partial' if collected else 'failed')
            if len(rows) > PAGE_SIZE:
                self._issue('partial', 'CoveragePageLimit')
                return self._finish_coverage(region, collected, pages, 'partial')
            for raw in rows:
                if len(collected) >= MAX_COVERED_RESOURCES:
                    self._issue('partial', 'CoverageLimit')
                    return self._finish_coverage(region, collected, pages, 'partial')
                if raw.get('accountId') != self.owner_id:
                    self._issue('partial', 'UnexpectedAccount')
                    incomplete = True
                    continue
                key = (raw.get('resourceType'), raw.get('resourceId'), raw.get('scanType'))
                if any(not isinstance(value, str) or not value for value in key):
                    self._issue('partial', 'MalformedCoveredResource')
                    incomplete = True
                    continue
                if key in seen_resources:
                    self._issue('partial', 'DuplicateCoveredResource')
                    incomplete = True
                    continue
                seen_resources.add(key)
                scan = raw.get('scanStatus')
                if not isinstance(scan, dict):
                    self._issue('partial', 'MalformedCoverageStatus')
                    incomplete = True
                    scan = {}
                elif scan.get('statusCode') not in ('ACTIVE', 'INACTIVE'):
                    self._issue('partial', 'UnknownCoverageStatus')
                    incomplete = True
                collected.append({
                    'account_id': self.owner_id, 'resource_type': key[0],
                    'resource_id': key[1], 'scan_type': key[2],
                    'scan_status': scan.get('statusCode'),
                    'scan_reason': scan.get('reason'),
                    'last_scanned_at': raw.get('lastScannedAt'),
                    'provider': raw.get('provider'),
                    'provider_region': raw.get('providerRegion'),
                    'provider_account_id': raw.get('providerAccountId'),
                    'provider_org_id': raw.get('providerOrgId'),
                    'scan_mode': raw.get('scanMode'),
                })
            following = response.get('nextToken')
            if following is None or following == '':
                return self._finish_coverage(
                    region, collected, pages, 'partial' if incomplete else 'complete')
            if (not isinstance(following, str) or not following
                    or len(following) > MAX_TOKEN_LENGTH or following in seen_tokens):
                self._issue('partial', 'InvalidPaginationToken')
                return self._finish_coverage(region, collected, pages, 'partial')
            seen_tokens.add(following)
            token = following
        self._issue('partial', 'CoveragePageLimit')
        return self._finish_coverage(region, collected, MAX_PAGES, 'partial')

    async def get_coverage_statistics(self, region):
        """Independent Inspector inventory count for consistency, NOT EC2/ECR census."""
        result = {'status': 'failed', 'total_count': None, 'by_status': {},
                  'pages': 0, 'scope': 'inspector_inventory_only'}
        if not self._account_valid():
            return result
        client = self._client(region)
        if client is None:
            return result
        token, seen = None, set()
        for index in range(MAX_STATISTICS_PAGES):
            args = {'filterCriteria': {'accountId': [
                {'comparison': 'EQUALS', 'value': self.owner_id}]},
                'groupBy': 'SCAN_STATUS_CODE'}
            if token is not None:
                args['nextToken'] = token
            try:
                page = await run_concurrently(
                    lambda args=args: client.list_coverage_statistics(**args))
            except Exception as error:
                result['status'] = self._error(
                    error, 'ListCoverageStatistics', partial=index > 0)
                return result
            result['pages'] += 1
            total = page.get('totalCounts') if isinstance(page, dict) else None
            rows = page.get('countsByGroup', []) if isinstance(page, dict) else None
            if (type(total) is not int or total < 0 or not isinstance(rows, list)):
                self._issue('partial', 'MalformedCoverageStatistics')
                result['status'] = 'partial'
                return result
            if result['total_count'] is not None and total != result['total_count']:
                self._issue('partial', 'InconsistentStatisticsTotal')
                result['status'] = 'partial'
                return result
            result['total_count'] = total
            for row in rows:
                if (not isinstance(row, dict) or not isinstance(row.get('groupKey'), str)
                        or type(row.get('count')) is not int or row['count'] < 0
                        or row['groupKey'] in result['by_status']):
                    self._issue('partial', 'InvalidStatisticsGroup')
                    result['status'] = 'partial'
                    return result
                result['by_status'][row['groupKey']] = row['count']
            following = page.get('nextToken')
            if following is None or following == '':
                if result['by_status'] and sum(result['by_status'].values()) != total:
                    self._issue('partial', 'StatisticsCountMismatch')
                    result['status'] = 'partial'
                else:
                    result['status'] = 'complete'
                return result
            if (not isinstance(following, str) or not following
                    or len(following) > MAX_TOKEN_LENGTH or following in seen):
                self._issue('partial', 'StatisticsPaginationToken')
                result['status'] = 'partial'
                return result
            seen.add(following)
            token = following
        self._issue('partial', 'StatisticsPageLimit')
        result['status'] = 'partial'
        return result
