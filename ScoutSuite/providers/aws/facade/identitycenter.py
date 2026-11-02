"""M10-L: IAM Identity Center read-only inventory and assignment evidence.

Collection completeness is explicit at every API boundary. This is configuration
evidence, not an IAM policy simulator or proof of effective authorization.
"""
import json

from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently


MAX_PAGES = 10000
DENIED = {'AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation'}
UNSUPPORTED = {'UnknownOperationException', 'UnsupportedOperationException'}


class IdentityCenterFacade(AWSBaseFacade):
    def __init__(self, session, account_id):
        super().__init__(session)
        self.account_id = account_id

    @staticmethod
    def _issue(status, reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue(status, 'identitycenter', reason)

    @staticmethod
    def _status(error):
        if isinstance(error, ClientError):
            code = error.response.get('Error', {}).get('Code', '')
            if code in DENIED:
                return 'denied'
            if code in UNSUPPORTED:
                return 'unsupported'
        return 'failed'

    def _client(self, service, region):
        try:
            client = AWSFacadeUtils.get_client(service, self.session, region)
            if client is None:
                raise ValueError('NoClient')
            return client
        except Exception:
            self._issue('failed', service + 'ClientConstruction')
            return None

    async def _pages(self, client, operation, key, params=None):
        """Collect every page, including empty intermediate pages; reject loops."""
        rows, seen, token = [], set(), None
        for page in range(MAX_PAGES):
            kwargs = dict(params or {})
            if token is not None:
                kwargs['NextToken'] = token
            try:
                response = await run_concurrently(
                    lambda kwargs=kwargs: getattr(client, operation)(**kwargs))
            except Exception as error:
                status = 'partial' if rows else self._status(error)
                self._issue(status, operation + self._status(error).capitalize())
                return rows, status
            values = response.get(key) if isinstance(response, dict) else None
            if not isinstance(values, list):
                self._issue('partial', operation + 'MalformedPage')
                return rows, 'partial'
            rows.extend(values)
            following = response.get('NextToken')
            if following is None or following == '':
                return rows, 'complete'
            if (not isinstance(following, str) or len(following) > 2048
                    or following in seen):
                self._issue('partial', operation + 'InvalidToken')
                return rows, 'partial'
            seen.add(following)
            token = following
        self._issue('partial', operation + 'PageLimit')
        return rows, 'partial'

    async def _one(self, client, operation, key, params, *, missing_ok=False):
        try:
            response = await run_concurrently(lambda: getattr(client, operation)(**params))
        except Exception as error:
            if (missing_ok and isinstance(error, ClientError)
                    and error.response.get('Error', {}).get('Code') == 'ResourceNotFoundException'):
                return None, 'complete'
            status = self._status(error)
            self._issue(status, operation + status.capitalize())
            return None, status
        value = response.get(key) if isinstance(response, dict) else None
        if value is None and not missing_ok:
            self._issue('partial', operation + 'MalformedResponse')
            return None, 'partial'
        return value, 'complete'

    async def _identities(self, region, identity_store_id):
        client = self._client('identitystore', region)
        data = {'users': {}, 'groups': {}, 'collection': {}}
        if client is None:
            data['collection'] = {'users': 'failed', 'groups': 'failed', 'memberships': 'failed'}
            return data
        try:
            for operation, key, kind, id_key in (
                ('list_users', 'Users', 'users', 'UserId'),
                ('list_groups', 'Groups', 'groups', 'GroupId'),
            ):
                records, status = await self._pages(
                    client, operation, key, {'IdentityStoreId': identity_store_id})
                data['collection'][kind] = status
                for raw in records:
                    identifier = raw.get(id_key) if isinstance(raw, dict) else None
                    if not isinstance(identifier, str) or not identifier or identifier in data[kind]:
                        data['collection'][kind] = 'partial'
                        self._issue('partial', 'InvalidOrDuplicate' + id_key)
                        continue
                    if kind == 'users':
                        emails = [item.get('Value') for item in raw.get('Emails', [])
                                  if isinstance(item, dict) and isinstance(item.get('Value'), str)]
                        data[kind][identifier] = {
                            'id': identifier, 'name': raw.get('DisplayName') or raw.get('UserName') or identifier,
                            'user_name': raw.get('UserName'), 'display_name': raw.get('DisplayName'),
                            'emails': emails, 'primary_email': next((
                                item.get('Value') for item in raw.get('Emails', [])
                                if isinstance(item, dict) and item.get('Primary')
                                and isinstance(item.get('Value'), str)), emails[0] if emails else None),
                            'external_ids': raw.get('ExternalIds', []), 'active': raw.get('Active'),
                        }
                    else:
                        data[kind][identifier] = {
                            'id': identifier, 'name': raw.get('DisplayName') or identifier,
                            'description': raw.get('Description'), 'external_ids': raw.get('ExternalIds', []),
                            'members': {}, 'member_emails': [],
                        }
            membership_status = 'complete'
            for identifier, group in data['groups'].items():
                memberships, status = await self._pages(
                    client, 'list_group_memberships', 'GroupMemberships',
                    {'IdentityStoreId': identity_store_id, 'GroupId': identifier})
                if status != 'complete':
                    membership_status = 'partial'
                for membership in memberships:
                    user_id = (membership.get('MemberId', {}).get('UserId')
                               if isinstance(membership, dict) and isinstance(membership.get('MemberId'), dict)
                               else None)
                    membership_id = membership.get('MembershipId') if isinstance(membership, dict) else None
                    if not user_id or not membership_id or membership_id in group['members']:
                        membership_status = 'partial'
                        self._issue('partial', 'InvalidGroupMembership')
                        continue
                    user = data['users'].get(user_id)
                    if user is None:
                        membership_status = 'partial'
                        self._issue('partial', 'UnresolvedGroupMember')
                    group['members'][membership_id] = {
                        'id': membership_id, 'user_id': user_id,
                        'user_name': user.get('name') if user else None,
                        'emails': user.get('emails', []) if user else [],
                    }
                    if user:
                        group['member_emails'].extend(user.get('emails', []))
                group['member_emails'] = sorted(set(group['member_emails']))
            data['collection']['memberships'] = membership_status if (
                data['collection'].get('groups') == 'complete' and
                data['collection'].get('users') == 'complete') else 'partial'
            return data
        finally:
            # Boto clients are intentionally not shared beyond this region request.
            close = getattr(client, 'close', None)
            if callable(close):
                close()

    async def get_region(self, region):
        result = {'instances': {}, 'collection': {'instances': 'not_collected'}}
        client = self._client('sso-admin', region)
        if client is None:
            result['collection']['instances'] = 'failed'
            return result
        try:
            instances, status = await self._pages(client, 'list_instances', 'Instances')
            result['collection']['instances'] = status
            for raw in instances:
                arn = raw.get('InstanceArn') if isinstance(raw, dict) else None
                store_id = raw.get('IdentityStoreId') if isinstance(raw, dict) else None
                if (not isinstance(arn, str) or not arn.startswith('arn:')
                        or not isinstance(store_id, str) or not store_id
                        or arn in result['instances']):
                    self._issue('partial', 'InvalidOrDuplicateInstance')
                    result['collection']['instances'] = 'partial'
                    continue
                instance = {
                    'id': arn, 'name': raw.get('Name') or arn, 'arn': arn, 'region': region,
                    'identity_store_id': store_id, 'owner_account_id': raw.get('OwnerAccountId'),
                    'status': raw.get('Status'), 'created_date': raw.get('CreatedDate'),
                    'permission_sets': {}, 'collection': {'permission_sets': 'not_collected'},
                }
                result['instances'][arn] = instance
                sets, state = await self._pages(
                    client, 'list_permission_sets', 'PermissionSets', {'InstanceArn': arn})
                instance['collection']['permission_sets'] = state
                for ps_arn in sets:
                    if not isinstance(ps_arn, str) or not ps_arn.startswith('arn:'):
                        self._issue('partial', 'InvalidPermissionSetArn')
                        instance['collection']['permission_sets'] = 'partial'
                        continue
                    if ps_arn in instance['permission_sets']:
                        self._issue('partial', 'DuplicatePermissionSet')
                        instance['collection']['permission_sets'] = 'partial'
                        continue
                    params = {'InstanceArn': arn, 'PermissionSetArn': ps_arn}
                    details, d_status = await self._one(
                        client, 'describe_permission_set', 'PermissionSet', params)
                    policies, m_status = await self._pages(
                        client, 'list_managed_policies_in_permission_set',
                        'AttachedManagedPolicies', params)
                    customer, c_status = await self._pages(
                        client, 'list_customer_managed_policy_references_in_permission_set',
                        'CustomerManagedPolicyReferences', params)
                    inline, i_status = await self._one(
                        client, 'get_inline_policy_for_permission_set', 'InlinePolicy', params,
                        missing_ok=True)
                    boundary, b_status = await self._one(
                        client, 'get_permissions_boundary_for_permission_set',
                        'PermissionsBoundary', params, missing_ok=True)
                    account_ids, a_status = await self._pages(
                        client, 'list_accounts_for_provisioned_permission_set',
                        'AccountIds', params)
                    assignments = {}
                    for account_id in account_ids:
                        if not isinstance(account_id, str) or len(account_id) != 12 or not account_id.isdigit():
                            a_status = 'partial'
                            self._issue('partial', 'InvalidProvisionedAccountId')
                            continue
                        rows, row_status = await self._pages(
                            client, 'list_account_assignments', 'AccountAssignments',
                            {**params, 'AccountId': account_id})
                        if row_status != 'complete':
                            a_status = 'partial'
                        for row in rows:
                            if (not isinstance(row, dict) or row.get('AccountId') != account_id
                                    or row.get('PermissionSetArn') != ps_arn
                                    or row.get('PrincipalType') not in ('USER', 'GROUP')
                                    or not isinstance(row.get('PrincipalId'), str)):
                                a_status = 'partial'
                                self._issue('partial', 'MalformedAccountAssignment')
                                continue
                            key = account_id + ':' + row['PrincipalType'] + ':' + row['PrincipalId']
                            if key in assignments:
                                a_status = 'partial'
                                self._issue('partial', 'DuplicateAccountAssignment')
                            assignments[key] = {
                                'id': key, 'account_id': account_id,
                                'principal_type': row['PrincipalType'], 'principal_id': row['PrincipalId'],
                                'permission_set_arn': ps_arn, 'instance_arn': arn, 'region': region,
                            }
                    parsed_inline = None
                    if inline:
                        try:
                            parsed_inline = json.loads(inline)
                            if not isinstance(parsed_inline, dict):
                                raise ValueError('InlinePolicyNotObject')
                        except (ValueError, TypeError):
                            i_status = 'partial'
                            self._issue('partial', 'MalformedInlinePolicy')
                    ps_details = details if isinstance(details, dict) else {}
                    statuses = {
                        'details': d_status, 'managed_policies': m_status,
                        'customer_managed_policies': c_status, 'inline_policy': i_status,
                        'permissions_boundary': b_status, 'assignments': a_status,
                    }
                    instance['permission_sets'][ps_arn] = {
                        'id': ps_arn, 'name': ps_details.get('Name') or ps_arn, 'arn': ps_arn,
                        'description': ps_details.get('Description'),
                        'session_duration': ps_details.get('SessionDuration'),
                        'relay_state': ps_details.get('RelayState'),
                        'created_date': ps_details.get('CreatedDate'),
                        'managed_policies': policies, 'customer_managed_policies': customer,
                        'inline_policy': parsed_inline, 'inline_policy_raw': inline,
                        'permissions_boundary': boundary, 'provisioned_account_ids': account_ids,
                        'assignments': assignments, 'collection': statuses,
                    }
                identities = await self._identities(region, store_id)
                instance['users'] = identities['users']
                instance['groups'] = identities['groups']
                instance['collection'].update(identities['collection'])
            return result
        finally:
            close = getattr(client, 'close', None)
            if callable(close):
                close()
