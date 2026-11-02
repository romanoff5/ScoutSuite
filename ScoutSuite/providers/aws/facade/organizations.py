"""M10-C: read-only, partition-aware AWS Organizations inventory.

Global service endpoint: commercial us-east-1, GovCloud us-gov-west-1,
China cn-northwest-1. No cross-account traversal or policy-document access.
"""
import json

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
    def __init__(self, session, partition):
        super().__init__(session)
        self.partition = partition
        self._scp_context_cache = {}

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

    async def get_scp_context(self, accounts, roots):
        """Read account -> OU -> root SCP attachments; never claim effective IAM access.

        Partial for missing account hierarchy, denied APIs, malformed policies and
        limits. SCPs constrain authorization, but are not an IAM permission grant.
        """
        ids = tuple(sorted({row['Id'] for row in accounts
                            if isinstance(row, dict) and isinstance(row.get('Id'), str)}))
        if ids in self._scp_context_cache:
            return self._scp_context_cache[ids]
        result = {'accounts': {}, 'collection_status': 'complete',
                  'effective_permissions_verified': False}
        if len(ids) > 5000:
            self._issue('partial', 'SCPAccountLimit')
            result['collection_status'] = 'partial'
            result['account_limit'] = 5000
            ids = ids[:5000]
        region = HOME_REGIONS.get(self.partition)
        if not region:
            result['collection_status'] = 'partial'
            return result
        client = AWSFacadeUtils.get_client('organizations', self.session, region)
        if client is None:
            self._issue('failed', 'SCPClientConstruction')
            result['collection_status'] = 'partial'
            return result
        known_roots = {root['Id'] for root in roots
                       if isinstance(root, dict) and isinstance(root.get('Id'), str)}
        parent_cache, policy_cache, document_cache = {}, {}, {}
        async def target_parents(target):
            if target not in parent_cache:
                try:
                    response = await run_concurrently(
                        lambda target=target: client.list_parents(ChildId=target))
                    rows = response.get('Parents') if isinstance(response, dict) else None
                    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict) or (
                            rows[0].get('Type') not in ('ROOT', 'ORGANIZATIONAL_UNIT')
                            or not isinstance(rows[0].get('Id'), str)):
                        raise ValueError('MalformedParents')
                    parent_cache[target] = (rows[0]['Id'], 'complete')
                except Exception as error:
                    status, reason = self._error_status(error)
                    self._issue('partial', 'ListParents' + reason)
                    parent_cache[target] = (None, 'partial')
            return parent_cache[target]
        async def policies(target):
            if target not in policy_cache:
                try:
                    rows, status, token, seen = [], 'complete', None, set()
                    for _ in range(500):
                        kwargs = {'TargetId': target, 'Filter': 'SERVICE_CONTROL_POLICY',
                                  'MaxResults': PAGE_SIZE}
                        if token:
                            kwargs['NextToken'] = token
                        response = await run_concurrently(
                            lambda kwargs=kwargs: client.list_policies_for_target(**kwargs))
                        page = response.get('Policies') if isinstance(response, dict) else None
                        if not isinstance(page, list) or any(not isinstance(p, dict) or
                                not isinstance(p.get('Id'), str) for p in page):
                            status = 'partial'
                            break
                        rows.extend(page)
                        if len(rows) > 10000:
                            rows = rows[:10000]
                            status = 'partial'
                            break
                        token = response.get('NextToken')
                        if not token:
                            break
                        if not isinstance(token, str) or token in seen:
                            status = 'partial'
                            break
                        seen.add(token)
                    else:
                        status = 'partial'
                except Exception as error:
                    _, reason = self._error_status(error)
                    self._issue('partial', 'ListPoliciesForTarget' + reason)
                    rows, status = [], 'partial'
                policy_cache[target] = (rows, status)
            return policy_cache[target]
        async def document(identifier):
            if identifier not in document_cache:
                try:
                    response = await run_concurrently(
                        lambda identifier=identifier: client.describe_policy(PolicyId=identifier))
                    policy = response.get('Policy', {}) if isinstance(response, dict) else {}
                    content = policy.get('Content')
                    if not isinstance(content, str):
                        raise ValueError('MissingPolicyDocument')
                    parsed = json.loads(content)
                    if not isinstance(parsed, dict):
                        raise ValueError('InvalidPolicyDocument')
                    document_cache[identifier] = (parsed, 'complete')
                except Exception as error:
                    _, reason = self._error_status(error)
                    self._issue('partial', 'DescribePolicy' + reason)
                    document_cache[identifier] = (None, 'partial')
            return document_cache[identifier]
        try:
            for account_id in ids:
                chain, visited, state = [account_id], {account_id}, 'complete'
                for depth in range(33):
                    current = chain[-1]
                    if current in known_roots:
                        break
                    parent, parent_state = await target_parents(current)
                    if parent_state != 'complete' or not parent or parent in visited:
                        state = 'partial'
                        break
                    chain.append(parent)
                    visited.add(parent)
                else:
                    state = 'partial'
                    self._issue('partial', 'SCPAncestorDepthLimit')
                attachments, documents = {}, {}
                for target in chain:
                    rows, status = await policies(target)
                    if status != 'complete':
                        state = 'partial'
                    attachments[target] = []
                    for row in rows:
                        pid = row['Id']
                        attachments[target].append({
                            'id': pid, 'name': row.get('Name'),
                            'arn': row.get('Arn'), 'description': row.get('Description')})
                        body, doc_status = await document(pid)
                        if doc_status != 'complete':
                            state = 'partial'
                        else:
                            documents[pid] = body
                result['accounts'][account_id] = {
                    'account_id': account_id, 'ancestor_path': chain,
                    'attached_policies_by_target': attachments,
                    'policy_documents': documents, 'collection_status': state,
                    'effective_permissions_verified': False}
                if state != 'complete':
                    result['collection_status'] = 'partial'
        finally:
            close = getattr(client, 'close', None)
            if callable(close):
                close()
        self._scp_context_cache[ids] = result
        return result
