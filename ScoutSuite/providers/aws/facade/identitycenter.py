"""M10-L: read-only IAM Identity Center account assignment and principal inventory."""
from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently

PAGE_SIZE = 100
MAX_PAGES = 1000
MAX_ITEMS = 100000
DENIED = {'AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation'}
UNSUPPORTED = {'UnsupportedOperationException', 'UnknownOperationException'}


def _date(value):
    return value.isoformat() if hasattr(value, 'isoformat') else value


class IdentityCenterFacade(AWSBaseFacade):
    """SSO account access, including identity-store lookups, without authentication writes."""

    @staticmethod
    def issue(status, reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue(status, 'identitycenter', reason)

    @classmethod
    def failure(cls, action, error):
        if isinstance(error, ClientError):
            code = error.response.get('Error', {}).get('Code', '')
            status = 'denied' if code in DENIED else (
                'unsupported' if code in UNSUPPORTED else 'failed')
        else:
            status = 'failed'
        cls.issue(status, action + status.capitalize())

    async def _call(self, method, params, name):
        try:
            return await run_concurrently(lambda: method(**params)), True
        except Exception as error:
            self.failure(name, error)
            return None, False

    async def _pages(self, method, params, field, name):
        """Return (items, complete); any failed enumeration stays incomplete."""
        rows, tokens = [], set()
        token = None
        for _ in range(MAX_PAGES):
            args = dict(params, MaxResults=PAGE_SIZE)
            if token is not None:
                args['NextToken'] = token
            page, ok = await self._call(method, args, name)
            if not ok:
                return rows, False
            batch = page.get(field) if isinstance(page, dict) else None
            if (not isinstance(batch, list) or len(batch) > PAGE_SIZE
                    or any(not isinstance(item, (str, dict)) for item in batch)):
                self.issue('partial', name + 'MalformedPage')
                return rows, False
            if len(rows) + len(batch) > MAX_ITEMS:
                self.issue('partial', name + 'ItemLimit')
                return rows + batch[:MAX_ITEMS - len(rows)], False
            rows.extend(batch)
            next_token = page.get('NextToken')
            if next_token in (None, ''):
                return rows, True
            if (not isinstance(next_token, str) or len(next_token) > 2048
                    or next_token in tokens):
                self.issue('partial', name + 'InvalidPaginationToken')
                return rows, False
            tokens.add(next_token)
            token = next_token
        self.issue('partial', name + 'PageLimit')
        return rows, False

    @staticmethod
    def _instance_id_valid(row):
        if not isinstance(row, dict):
            return False
        arn, store = row.get('InstanceArn'), row.get('IdentityStoreId')
        if not isinstance(arn, str) or not isinstance(store, str) or not store:
            return False
        parts = arn.split(':', 5)
        return (len(parts) == 6 and parts[0] == 'arn'
                and parts[2:5] == ['sso', '', '']
                and parts[5].startswith('instance/') and len(parts[5]) > 9)

    @staticmethod
    def _email(user):
        emails = user.get('Emails', []) if isinstance(user, dict) else []
        if not isinstance(emails, list):
            return None
        ordered = [row for row in emails if isinstance(row, dict)]
        candidate = next((x for x in ordered if x.get('Primary') is True), None)
        candidate = candidate or next((x for x in ordered if x.get('Value')), None)
        return candidate.get('Value') if candidate else None

    async def _identity(self, client, store, kind, identifier, cache):
        key = (store, kind, identifier)
        if key in cache:
            return cache[key]
        if client is None:
            item = {'principal_id': identifier, 'principal_type': kind,
                    'resolution_status': 'unknown'}
            cache[key] = item
            return item
        method = client.describe_user if kind == 'USER' else client.describe_group
        response, ok = await self._call(
            method, {'IdentityStoreId': store,
                     'UserId' if kind == 'USER' else 'GroupId': identifier},
            'Describe' + ('User' if kind == 'USER' else 'Group'))
        if not ok or not isinstance(response, dict) or response.get(
                'UserId' if kind == 'USER' else 'GroupId') != identifier:
            if ok:
                self.issue('partial', 'PrincipalIdentityMismatch')
            item = {'principal_id': identifier, 'principal_type': kind,
                    'resolution_status': 'unknown'}
        else:
            item = {'principal_id': identifier, 'principal_type': kind,
                    'resolution_status': 'resolved',
                    'principal_arn': response.get('UserArn' if kind == 'USER' else 'GroupArn'),
                    'revision': response.get('Revision'),
                    'name': response.get('DisplayName') or response.get('UserName'),
                    'username': response.get('UserName'),
                    'email': self._email(response) if kind == 'USER' else None,
                    'emails': response.get('Emails', []) if kind == 'USER' else [],
                    'description': response.get('Description') if kind == 'GROUP' else None,
                    'external_ids': response.get('ExternalIds', [])}
        cache[key] = item
        return item

    async def _group_members(self, client, store, group_id, identity_cache, membership_cache):
        key = (store, group_id)
        if key in membership_cache:
            return membership_cache[key]
        if client is None:
            result = {'members': [], 'members_complete': False}
            membership_cache[key] = result
            return result
        rows, complete = await self._pages(
            client.list_group_memberships, {'IdentityStoreId': store, 'GroupId': group_id},
            'GroupMemberships', 'ListGroupMemberships')
        members, ids = [], set()
        for row in rows:
            identifier = row.get('MemberId', {}).get('UserId') if isinstance(row, dict) else None
            if not isinstance(identifier, str) or not identifier or identifier in ids:
                self.issue('partial', 'InvalidOrDuplicateGroupMember')
                complete = False
                continue
            ids.add(identifier)
            user = await self._identity(client, store, 'USER', identifier, identity_cache)
            if user['resolution_status'] != 'resolved':
                complete = False
            membership_id = row.get('MembershipId')
            if (not isinstance(membership_id, str) or not membership_id
                    or row.get('GroupId') != group_id or row.get('IdentityStoreId') != store):
                self.issue('partial', 'GroupMembershipIdentityIncomplete')
                complete = False
            members.append(dict(user, membership_id=membership_id,
                                membership_arn=row.get('MembershipArn'), group_id=group_id))
        result = {'members': members, 'members_complete': complete}
        membership_cache[key] = result
        return result

    async def _permission_set(self, sso, store_client, instance, arn, identity_cache, membership_cache):
        inst_arn, store = instance['instance_arn'], instance['identity_store_id']
        args = {'InstanceArn': inst_arn, 'PermissionSetArn': arn}
        record = {'permission_set_arn': arn, 'name': arn, 'managed_policies': [],
                  'customer_managed_policies': [], 'inline_policy_present': None,
                  'permission_boundary': None, 'policy_collection_complete': False,
                  'assignment_collection_complete': False, 'account_ids': [], 'assignments': []}
        detail, ok = await self._call(sso.describe_permission_set, args, 'DescribePermissionSet')
        info = detail.get('PermissionSet') if isinstance(detail, dict) else None
        if ok and isinstance(info, dict) and info.get('PermissionSetArn') == arn:
            record.update(name=info.get('Name') or arn, description=info.get('Description'),
                          session_duration=info.get('SessionDuration'),
                          relay_state=info.get('RelayState'), created_date=_date(info.get('CreatedDate')))
        else:
            self.issue('partial', 'PermissionSetDetailIncomplete')
        managed, managed_ok = await self._pages(
            sso.list_managed_policies_in_permission_set, args,
            'AttachedManagedPolicies', 'ListManagedPoliciesInPermissionSet')
        customer, customer_ok = await self._pages(
            sso.list_customer_managed_policy_references_in_permission_set, args,
            'CustomerManagedPolicyReferences', 'ListCustomerManagedPolicyReferences')
        record['managed_policies'] = [x for x in managed if isinstance(x, dict)]
        record['customer_managed_policies'] = [x for x in customer if isinstance(x, dict)]
        managed_arns = [x.get('Arn') for x in record['managed_policies']]
        customer_refs = [(x.get('Name'), x.get('Path')) for x in record['customer_managed_policies']]
        invalid_managed = (len(record['managed_policies']) != len(managed)
                           or any(not isinstance(arn, str) or not arn.startswith('arn:')
                                  for arn in managed_arns)
                           or len(managed_arns) != len(set(managed_arns)))
        invalid_customer = (len(record['customer_managed_policies']) != len(customer)
                            or any(not isinstance(name, str) or not name
                                   or not isinstance(path, str) or not path.startswith('/')
                                   for name, path in customer_refs)
                            or len(customer_refs) != len(set(customer_refs)))
        if invalid_managed or invalid_customer:
            self.issue('partial', 'MalformedOrDuplicatePolicyReference')
            managed_ok = managed_ok and not invalid_managed
            customer_ok = customer_ok and not invalid_customer
        inline, inline_ok = await self._call(
            sso.get_inline_policy_for_permission_set, args, 'GetInlinePolicyForPermissionSet')
        if inline_ok and isinstance(inline, dict) and isinstance(inline.get('InlinePolicy', ''), str):
            # Policy text may contain credentials in mistakes; never persist raw JSON policy content.
            record['inline_policy_present'] = bool(inline.get('InlinePolicy'))
        else:
            inline_ok = False
            self.issue('partial', 'InlinePolicyStatusIncomplete')
        boundary, boundary_ok = await self._call(
            sso.get_permissions_boundary_for_permission_set, args, 'GetPermissionsBoundaryForPermissionSet')
        if boundary_ok and isinstance(boundary, dict):
            record['permission_boundary'] = boundary.get('PermissionsBoundary')
        else:
            boundary_ok = False
            self.issue('partial', 'PermissionsBoundaryIncomplete')
        record['policy_collection_complete'] = all(
            (ok, managed_ok, customer_ok, inline_ok, boundary_ok))
        accounts, accounts_ok = await self._pages(
            sso.list_accounts_for_provisioned_permission_set, args,
            'AccountIds', 'ListAccountsForProvisionedPermissionSet')
        account_ids = set()
        complete = accounts_ok
        for account in accounts:
            if (not isinstance(account, str) or len(account) != 12 or not account.isascii()
                    or not account.isdigit() or account in account_ids):
                self.issue('partial', 'InvalidOrDuplicateProvisionedAccount')
                complete = False
                continue
            account_ids.add(account)
            record['account_ids'].append(account)
            assignments, assignment_ok = await self._pages(
                sso.list_account_assignments, dict(args, AccountId=account),
                'AccountAssignments', 'ListAccountAssignments')
            if not assignment_ok:
                complete = False
            for assignment in assignments:
                if (not isinstance(assignment, dict) or assignment.get('AccountId') != account
                        or assignment.get('PermissionSetArn') != arn
                        or assignment.get('PrincipalType') not in ('USER', 'GROUP')
                        or not isinstance(assignment.get('PrincipalId'), str)
                        or not assignment['PrincipalId']):
                    self.issue('partial', 'InvalidAccountAssignment')
                    complete = False
                    continue
                kind, principal = assignment['PrincipalType'], assignment['PrincipalId']
                identity = await self._identity(store_client, store, kind, principal, identity_cache)
                members = {'members': [], 'members_complete': True}
                if kind == 'GROUP':
                    members = await self._group_members(
                        store_client, store, principal, identity_cache, membership_cache)
                record['assignments'].append({
                    'account_id': account, 'permission_set_arn': arn,
                    'permission_set_name': record['name'],
                    'principal_id': principal, 'principal_type': kind,
                    'principal_arn': identity.get('principal_arn'),
                    'principal_revision': identity.get('revision'),
                    'principal_name': identity.get('name'),
                    'principal_username': identity.get('username'),
                    'principal_email': identity.get('email'),
                    'principal_emails': identity.get('emails', []),
                    'principal_external_ids': identity.get('external_ids'),
                    'identity_resolution_status': identity['resolution_status'],
                    'group_members': members['members'],
                    'group_members_complete': members['members_complete'],
                    'managed_policies': record['managed_policies'],
                    'customer_managed_policies': record['customer_managed_policies'],
                    'inline_policy_present': record['inline_policy_present'],
                    'permission_boundary': record['permission_boundary'],
                    'policy_collection_complete': record['policy_collection_complete'],
                    'administrator_access_managed_policy': any(
                        isinstance(item.get('Arn'), str) and
                        item['Arn'].split(':', 5)[-1] == 'policy/AdministratorAccess'
                        and ':iam::aws:' in item['Arn'] for item in record['managed_policies']),
                })
        record['assignment_collection_complete'] = complete
        return record

    async def get_instances(self, region):
        sso = AWSFacadeUtils.get_client('sso-admin', self.session, region)
        if sso is None:
            self.issue('failed', 'SSOAdminClientUnavailable')
            return []
        instances, complete = await self._pages(sso.list_instances, {}, 'Instances', 'ListInstances')
        results, seen = [], set()
        identity_client = None
        identity_cache, membership_cache = {}, {}
        for item in instances:
            if not self._instance_id_valid(item):
                self.issue('partial', 'InvalidInstanceIdentity')
                continue
            arn, store = item['InstanceArn'], item['IdentityStoreId']
            if arn in seen:
                self.issue('partial', 'DuplicateInstance')
                continue
            seen.add(arn)
            if identity_client is None:
                identity_client = AWSFacadeUtils.get_client('identitystore', self.session, region)
                if identity_client is None:
                    self.issue('partial', 'IdentityStoreClientUnavailable')
            record = {
                'instance_arn': arn, 'identity_store_id': store,
                'owner_account_id': item.get('OwnerAccountId'),
                'name': item.get('Name') or arn, 'region': region,
                'status': item.get('Status'), 'status_reason': item.get('StatusReason'),
                'created_date': _date(item.get('CreatedDate')),
                'instance_enumeration_complete': complete,
                'permission_sets': [], 'assignments': [],
                'permission_sets_complete': False,
            }
            sets, sets_ok = await self._pages(
                sso.list_permission_sets, {'InstanceArn': arn},
                'PermissionSets', 'ListPermissionSets')
            record['permission_sets_complete'] = sets_ok
            seen_sets = set()
            for ps in sets:
                if not isinstance(ps, str) or ps in seen_sets:
                    self.issue('partial', 'InvalidOrDuplicatePermissionSet')
                    record['permission_sets_complete'] = False
                    continue
                if not ps.startswith(arn.replace(':instance/', ':permissionSet/') + '/'):
                    self.issue('partial', 'ForeignPermissionSet')
                    record['permission_sets_complete'] = False
                    continue
                seen_sets.add(ps)
                detail = await self._permission_set(
                    sso, identity_client, record, ps, identity_cache, membership_cache)
                record['permission_sets'].append(detail)
                record['assignments'].extend(detail['assignments'])
                if not detail['assignment_collection_complete'] or not detail['policy_collection_complete']:
                    record['permission_sets_complete'] = False
            results.append(record)
        return results
