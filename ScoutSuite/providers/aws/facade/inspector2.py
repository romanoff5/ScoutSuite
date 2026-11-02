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
MAX_PAGES = 5
PAGE_SIZE = 100
MAX_COVERED_RESOURCES = 500
_DENIED = ('AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation')
_UNSUPPORTED = ('UnsupportedOperationException', 'UnknownOperationException')


class Inspector2Facade(AWSBaseFacade):
    def __init__(self, session, owner_id):
        super().__init__(session)
        self.owner_id = owner_id

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
            state = resources.get(name)
            if state is None:
                resource_states[name] = None
                if name in REQUIRED_SCAN_TYPES:
                    self._issue('partial', 'MissingRequiredScanType')
                continue
            if not isinstance(state, dict):
                resource_states[name] = None
                self._issue('partial', 'MalformedScanType')
                continue
            status = state.get('status')
            if status not in VALID_SCAN_STATES:
                resource_states[name] = None
                self._issue('partial', 'InvalidScanTypeStatus')
                continue
            resource_states[name] = status
        # Preserve original resource_states field for existing JSON/SQLite
        # consumers. Add scan_types at the normalized resource layer.
        return [{'account_id': self.owner_id, 'status': state['status'],
                 'resource_states': resource_states}]

    async def get_coverage(self, region):
        if not self._account_valid():
            return []
        client = self._client(region)
        if client is None:
            return []
        collected, seen_tokens, seen_resources = [], set(), set()
        token = None
        for _ in range(MAX_PAGES):
            params = {'maxResults': PAGE_SIZE,
                      'filterCriteria': {'accountId': [
                          {'comparison': 'EQUALS', 'value': self.owner_id}]}}
            if token is not None:
                params['nextToken'] = token
            try:
                response = await run_concurrently(
                    lambda params=params: client.list_coverage(**params))
            except Exception as error:
                self._error(error, 'ListCoverage', partial=bool(collected))
                return collected
            rows = response.get('coveredResources') if isinstance(response, dict) else None
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                self._issue('partial' if collected else 'failed', 'MalformedCoveragePage')
                return collected
            if len(rows) > PAGE_SIZE or len(rows) + len(collected) > MAX_COVERED_RESOURCES:
                self._issue('partial', 'CoverageLimit')
                return collected
            for raw in rows:
                if raw.get('accountId') != self.owner_id:
                    self._issue('partial', 'UnexpectedAccount')
                    continue
                key = (raw.get('resourceType'), raw.get('resourceId'), raw.get('scanType'))
                if any(not isinstance(s, str) or not s for s in key):
                    self._issue('partial', 'MalformedCoveredResource')
                    continue
                if key in seen_resources:
                    self._issue('partial', 'DuplicateCoveredResource')
                    continue
                seen_resources.add(key)
                scan = raw.get('scanStatus')
                if not isinstance(scan, dict):
                    self._issue('partial', 'MalformedCoverageStatus')
                    scan = {}
                collected.append({'account_id': self.owner_id, 'resource_type': key[0],
                                  'resource_id': key[1], 'scan_type': key[2],
                                  'scan_status': scan.get('statusCode'),
                                  'scan_reason': scan.get('reason')})
            following = response.get('nextToken')
            if following is None or following == '':
                return collected
            if not isinstance(following, str) or following in seen_tokens or len(following) > 4096:
                self._issue('partial', 'InvalidPaginationToken')
                return collected
            seen_tokens.add(following)
            token = following
        self._issue('partial', 'CoveragePageLimit')
        return collected
