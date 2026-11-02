"""M10-L: Identity Center region, identity, permission set and assignment analysis."""
from collections import defaultdict

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.aws.resources.regions import Regions


def _risk(permission_set):
    """Candidate risks, not claims of effective privilege after SCPs/boundaries."""
    statuses = permission_set.get('collection', {})
    required = ('details', 'managed_policies', 'customer_managed_policies',
                'inline_policy', 'permissions_boundary', 'assignments')
    complete = all(statuses.get(key) == 'complete' for key in required)
    managed = permission_set.get('managed_policies', [])
    names = {p.get('Arn', '').rsplit('/', 1)[-1] for p in managed if isinstance(p, dict)}
    admin = 'AdministratorAccess' in names
    broad = bool(names.intersection({'AdministratorAccess', 'PowerUserAccess', 'IAMFullAccess'}))
    policy = permission_set.get('inline_policy')
    statements = policy.get('Statement', []) if isinstance(policy, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    if policy is not None and not isinstance(statements, list):
        complete = False
        statements = []
    for statement in statements:
        if not isinstance(statement, dict):
            complete = False
            continue
        if statement.get('Effect') != 'Allow':
            continue
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        if not isinstance(actions, list):
            complete = False
            continue
        if 'NotAction' in statement:
            broad = True
        for action in actions:
            if not isinstance(action, str):
                complete = False
                continue
            normalized = action.lower()
            if normalized == '*':
                resources = statement.get('Resource')
                if isinstance(resources, str):
                    resources = [resources]
                # Action '*' constrained to specific ARNs is still broad,
                # but is not the same as unrestricted AdministratorAccess.
                if isinstance(resources, list) and '*' in resources and not statement.get('Condition'):
                    admin = True
                broad = True
            elif normalized in ('iam:*', 'organizations:*', 'sso:*', 'sts:*') or normalized.endswith(':*'):
                broad = True
    # Customer-managed policies are references, not policy documents. Their
    # permissions cannot be classified without access to each target account.
    if permission_set.get('customer_managed_policies'):
        complete = False
    return admin, broad, complete


class Instances(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region
        self.collection = {}

    async def fetch_all(self):
        raw = await self.facade.identitycenter.get_region(self.region)
        self.collection = raw.get('collection', {})
        for arn, instance in raw.get('instances', {}).items():
            value = dict(instance)
            value['id'] = arn
            value['name'] = instance.get('name') or arn
            sets = {}
            for ps_arn, ps in instance.get('permission_sets', {}).items():
                item = dict(ps)
                admin, broad, complete = _risk(item)
                item['admin_candidate'] = admin
                item['broad_permissions_candidate'] = broad
                item['policy_analysis_complete'] = complete
                item['collection_complete'] = complete
                assignments = {}
                for key, assignment in ps.get('assignments', {}).items():
                    data = dict(assignment)
                    user = instance.get('users', {}).get(data['principal_id'], {}) if (
                        data['principal_type'] == 'USER') else {}
                    group = instance.get('groups', {}).get(data['principal_id'], {}) if (
                        data['principal_type'] == 'GROUP') else {}
                    principal = user or group
                    data['name'] = principal.get('name') or data['principal_id']
                    data['principal_name'] = data['name']
                    data['emails'] = user.get('emails', []) if user else group.get('member_emails', [])
                    data['member_user_ids'] = [
                        member['user_id'] for member in group.get('members', {}).values()]
                    data['admin_candidate'] = admin
                    data['broad_permissions_candidate'] = broad
                    data['policy_analysis_complete'] = complete
                    data['principal_resolved'] = bool(principal)
                    if not principal:
                        item['collection_complete'] = False
                        ctx = get_current_run_context()
                        if ctx is not None:
                            ctx.record_collection_issue('partial', 'identitycenter', 'UnresolvedAssignmentPrincipal')
                    assignments[key] = data
                item['assignments'] = assignments
                item['assignments_count'] = len(assignments)
                sets[ps_arn] = item
            value['permission_sets'] = sets
            value['permission_sets_count'] = len(sets)
            value['users_count'] = len(value.get('users', {}))
            value['groups_count'] = len(value.get('groups', {}))
            value['collection_complete'] = (
                all(status == 'complete' for status in value.get('collection', {}).values())
                and all(ps['collection_complete'] for ps in sets.values()))
            self[arn] = value


class IdentityCenter(Regions):
    _children = [(Instances, 'instances')]

    def __init__(self, facade):
        super().__init__('sso-admin', facade)

    async def fetch_all(self, **kwargs):
        await super().fetch_all(**kwargs)
        # DescribeOrganization can succeed for a member; ListAccounts verifies
        # organization-scale visibility. Delegated admins without full roster
        # access are deliberately reported partial, never assumed complete.
        organization = await self.facade.organizations.get_organization_inventory()
        org = organization.get('organization') or {}
        collection = organization.get('collection', {})
        owner = self.facade.owner_id
        admin_verified = bool(
            (org.get('ManagementAccountId') or org.get('MasterAccountId')) == owner
            and collection.get('accounts') == 'complete')
        accounts = {a.get('Id'): a for a in organization.get('accounts', [])
                    if isinstance(a, dict) and isinstance(a.get('Id'), str)}
        self['organization_coverage'] = {
            'status': 'complete' if admin_verified else 'partial',
            'management_account_verified': admin_verified,
            'management_account_id': org.get('ManagementAccountId') or org.get('MasterAccountId'),
            'scanned_account_id': owner,
            'organization_id': org.get('Id'),
            'account_roster_status': collection.get('accounts', 'not_collected'),
            'accounts': {k: {'id': k, 'name': v.get('Name') or k, 'email': v.get('Email'),
                             'state': v.get('State'), 'arn': v.get('Arn')}
                         for k, v in accounts.items()},
            'account_count': len(accounts),
            'effective_permissions_verified': False,
        }
        if not admin_verified:
            ctx = get_current_run_context()
            if ctx is not None:
                ctx.record_collection_issue('partial', 'identitycenter', 'OrganizationManagementScopeUnverified')
        cross = defaultdict(set)
        user_cross = defaultdict(set)
        unknown_accounts = set()
        for region in self.get('regions', {}).values():
            for instance in region.get('instances', {}).values():
                for ps in instance.get('permission_sets', {}).values():
                    for assignment in ps.get('assignments', {}).values():
                        account_id = assignment['account_id']
                        if admin_verified and account_id not in accounts:
                            unknown_accounts.add(account_id)
                        if not assignment['admin_candidate']:
                            continue
                        key = (instance['arn'], assignment['principal_type'],
                               assignment['principal_id'])
                        cross[key].add(account_id)
                        if assignment['principal_type'] == 'USER':
                            user_ids = [assignment['principal_id']]
                        else:
                            group = instance.get('groups', {}).get(assignment['principal_id'], {})
                            user_ids = [member['user_id'] for member in
                                        group.get('members', {}).values()]
                        for user_id in user_ids:
                            user_cross[(instance['arn'], user_id)].add(account_id)
        if unknown_accounts:
            self['organization_coverage']['status'] = 'partial'
            self['organization_coverage']['unrecognized_assignment_account_ids'] = (
                sorted(unknown_accounts))
            admin_verified = False
            ctx = get_current_run_context()
            if ctx is not None:
                ctx.record_collection_issue('partial', 'identitycenter', 'AssignmentAccountOutsideVerifiedRoster')
        total_complete = admin_verified and bool(self.get('regions'))
        if not self.get('regions'):
            ctx = get_current_run_context()
            if ctx is not None:
                ctx.record_collection_issue('partial', 'identitycenter', 'NoRegionsEnumerated')
        for region in self.get('regions', {}).values():
            # Region is partial if any Identity Center API is denied or if an
            # instance is visible without a complete identity/assignment census.
            region_complete = bool(region.get('instances') is not None)
            for instance in region.get('instances', {}).values():
                instance['organization_coverage_status'] = self['organization_coverage']['status']
                for ps in instance.get('permission_sets', {}).values():
                    for assignment in ps.get('assignments', {}).values():
                        key = (instance['arn'], assignment['principal_type'], assignment['principal_id'])
                        account = accounts.get(assignment['account_id'], {})
                        assignment['account_name'] = account.get('Name')
                        assignment['account_email'] = account.get('Email')
                        if assignment['principal_type'] == 'USER':
                            members = [assignment['principal_id']]
                        else:
                            members = assignment.get('member_user_ids', [])
                        user_ids = [uid for uid in members if len(
                            user_cross[(instance['arn'], uid)]) > 1]
                        assignment['cross_account_admin_user_ids'] = sorted(user_ids)
                        assignment['cross_account_admin_candidate'] = (
                            assignment['admin_candidate']
                            and (len(cross[key]) > 1 or bool(user_ids)))
                        linked_accounts = set(cross[key])
                        for uid in members:
                            linked_accounts.update(user_cross[(instance['arn'], uid)])
                        assignment['admin_account_ids'] = sorted(linked_accounts)
                        assignment['organization_coverage_status'] = (
                            self['organization_coverage']['status'])
                        assignment['effective_permissions_verified'] = False
                region_complete = region_complete and instance['collection_complete']
            # Non-successful ListInstances must be observed even with zero rows.
            state = getattr(self.facade.identitycenter, 'region_statuses', {}).get(region['id'], {})
            region['collection'] = state
            region_complete = region_complete and state.get('instances') == 'complete'
            region['collection_status'] = 'complete' if region_complete else 'partial'
            total_complete = total_complete and region_complete
        self['collection_status'] = 'complete' if total_complete else 'partial'
