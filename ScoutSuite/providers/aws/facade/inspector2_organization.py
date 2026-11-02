"""Read-only Inspector2 delegated-administrator account coverage inventory.

This is intentionally not an AWS Organizations census: only Inspector's known
member relationships and account scan states can be verified here.
"""
from datetime import datetime

from botocore.exceptions import ClientError
from ScoutSuite.providers.utils import run_concurrently


MEMBER_PAGE_SIZE = 50
MAX_MEMBER_PAGES = 1000
MAX_MEMBERS = MAX_MEMBER_PAGES * MEMBER_PAGE_SIZE
ACCOUNT_BATCH_SIZE = 100
VALID_ACCOUNT_STATES = frozenset((
    'ENABLING', 'ENABLED', 'DISABLING', 'DISABLED', 'SUSPENDING', 'SUSPENDED'))
VALID_RELATIONSHIP_STATES = frozenset((
    'CREATED', 'INVITED', 'DISABLED', 'ENABLED', 'REMOVED', 'RESIGNED',
    'DELETED', 'EMAIL_VERIFICATION_IN_PROGRESS', 'EMAIL_VERIFICATION_FAILED',
    'REGION_DISABLED', 'ACCOUNT_SUSPENDED', 'CANNOT_CREATE_DETECTOR_IN_ORG_MASTER'))


def _account_id(value):
    return isinstance(value, str) and len(value) == 12 and value.isascii() and value.isdigit()


def _timestamp(value):
    return value.isoformat() if isinstance(value, datetime) else value


class Inspector2OrganizationMixin:
    """Mix into the existing Inspector2Facade, not a second AWS service facade."""

    async def get_organization_context(self, region):
        report = {
            'status': 'unknown', 'role': 'unknown',
            'delegated_admin_account_id': None, 'delegated_admin_relationship_status': None,
            'members': {}, 'members_count': 0, 'members_complete': False,
            'member_statuses_complete': False, 'configuration_complete': False,
            'auto_enable': {}, 'max_account_limit_reached': None,
            'organization_roster_verified': False,
            'scope': 'inspector_member_relationships_only',
        }
        if not self._account_valid():
            report['status'] = 'failed'
            return report
        client = self._client(region)
        if client is None:
            report['status'] = 'failed'
            return report
        try:
            response = await run_concurrently(client.get_delegated_admin_account)
        except ClientError as error:
            if error.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                report['status'] = 'not_configured'
                report['role'] = 'standalone_or_unconfigured'
                return report
            report['status'] = self._error(error, 'GetDelegatedAdminAccount')
            return report
        except Exception as error:
            report['status'] = self._error(error, 'GetDelegatedAdminAccount')
            return report
        admin = response.get('delegatedAdmin') if isinstance(response, dict) else None
        if not isinstance(admin, dict) or not _account_id(admin.get('accountId')):
            self._issue('partial', 'MalformedDelegatedAdmin')
            report['status'] = 'partial'
            return report
        report['delegated_admin_account_id'] = admin['accountId']
        relationship = admin.get('relationshipStatus')
        report['delegated_admin_relationship_status'] = relationship
        if relationship not in VALID_RELATIONSHIP_STATES:
            self._issue('partial', 'InvalidDelegatedAdminStatus')
            report['status'] = 'partial'
            return report
        if admin['accountId'] != self.owner_id:
            report['role'] = 'member_or_management'
            report['status'] = 'not_authorized_as_admin'
            return report
        report['role'] = 'delegated_admin'
        report['status'] = 'partial'
        if relationship != 'ENABLED':
            self._issue('partial', 'DelegatedAdminInactive')
            return report

        await self._collect_members(client, report)
        await self._collect_organization_configuration(client, report)
        if report['members']:
            await self._collect_member_states(client, report)
        else:
            report['member_statuses_complete'] = report['members_complete']
        if (report['members_complete'] and report['member_statuses_complete']
                and report['configuration_complete']):
            report['status'] = 'complete'
        return report

    async def _collect_members(self, client, report):
        members, tokens, token = report['members'], set(), None
        for index in range(MAX_MEMBER_PAGES):
            args = {'maxResults': MEMBER_PAGE_SIZE, 'onlyAssociated': False}
            if token is not None:
                args['nextToken'] = token
            try:
                page = await run_concurrently(lambda args=args: client.list_members(**args))
            except Exception as error:
                self._error(error, 'ListMembers', partial=index > 0)
                return
            rows = page.get('members') if isinstance(page, dict) else None
            if (not isinstance(rows, list) or len(rows) > MEMBER_PAGE_SIZE
                    or any(not isinstance(row, dict) for row in rows)):
                self._issue('partial', 'MalformedMemberPage')
                return
            for row in rows:
                account = row.get('accountId')
                if not _account_id(account) or account in members or account == self.owner_id:
                    self._issue('partial', 'InvalidOrDuplicateMember')
                    return
                delegated = row.get('delegatedAdminAccountId')
                if delegated is not None and delegated != self.owner_id:
                    self._issue('partial', 'UnexpectedDelegatedAdmin')
                    return
                if len(members) >= MAX_MEMBERS:
                    self._issue('partial', 'MemberLimit')
                    return
                relationship = row.get('relationshipStatus')
                if relationship not in VALID_RELATIONSHIP_STATES:
                    self._issue('partial', 'InvalidMemberRelationship')
                    return
                members[account] = {
                    'id': account, 'name': account, 'account_id': account,
                    'delegated_admin_account_id': self.owner_id,
                    'relationship_status': relationship,
                    'updated_at': _timestamp(row.get('updatedAt')),
                    'account_status': 'UNKNOWN', 'inactive': False,
                    'scan_types': {},
                }
            report['members_count'] = len(members)
            following = page.get('nextToken')
            if following is None or following == '':
                report['members_complete'] = True
                return
            if (not isinstance(following, str) or not following
                    or len(following) > 1000000 or following in tokens):
                self._issue('partial', 'InvalidMemberPaginationToken')
                return
            tokens.add(following)
            token = following
        self._issue('partial', 'MemberPageLimit')

    async def _collect_organization_configuration(self, client, report):
        try:
            response = await run_concurrently(client.describe_organization_configuration)
        except Exception as error:
            self._error(error, 'DescribeOrganizationConfiguration')
            return
        settings = response.get('autoEnable') if isinstance(response, dict) else None
        if not isinstance(settings, dict):
            self._issue('partial', 'MalformedOrganizationConfiguration')
            return
        flags = {}
        for name in ('ec2', 'ecr', 'lambda', 'lambdaCode', 'codeRepository'):
            value = settings.get(name)
            if name in ('ec2', 'ecr') and type(value) is not bool:
                self._issue('partial', 'MissingRequiredAutoEnable')
                return
            if value is not None and type(value) is not bool:
                self._issue('partial', 'InvalidAutoEnable')
                return
            flags[name] = value
        maxed = response.get('maxAccountLimitReached')
        if maxed is not None and type(maxed) is not bool:
            self._issue('partial', 'InvalidAccountLimitState')
            return
        report['auto_enable'] = flags
        report['max_account_limit_reached'] = maxed
        report['configuration_complete'] = True

    async def _collect_member_states(self, client, report):
        """BatchGetAccountStatus <=100 IDs; unknown records never count as enabled."""
        members = report['members']
        accounts = sorted(members)
        success = report['members_complete']
        for index in range(0, len(accounts), ACCOUNT_BATCH_SIZE):
            batch = accounts[index:index + ACCOUNT_BATCH_SIZE]
            try:
                response = await run_concurrently(
                    lambda batch=batch: client.batch_get_account_status(accountIds=batch))
            except Exception as error:
                self._error(error, 'BatchGetMemberStatus', partial=index > 0)
                success = False
                continue
            records = response.get('accounts') if isinstance(response, dict) else None
            failed = response.get('failedAccounts', []) if isinstance(response, dict) else None
            if not isinstance(records, list) or not isinstance(failed, list):
                self._issue('partial', 'MalformedMemberStatusBatch')
                success = False
                continue
            failed_ids = set()
            for failure in failed:
                fid = failure.get('accountId') if isinstance(failure, dict) else None
                if fid not in batch or fid in failed_ids:
                    self._issue('partial', 'UnexpectedMemberStatusFailure')
                    success = False
                    continue
                failed_ids.add(fid)
                success = False
                self._issue('partial', 'FailedMemberAccountStatus')
            seen = set()
            for row in records:
                if not isinstance(row, dict):
                    self._issue('partial', 'MalformedMemberStatus')
                    success = False
                    continue
                account = row.get('accountId')
                if not _account_id(account) or account not in batch or account in seen or account in failed_ids:
                    self._issue('partial', 'UnexpectedMemberStatus')
                    success = False
                    continue
                seen.add(account)
                state = row.get('state')
                status = state.get('status') if isinstance(state, dict) else None
                if status not in VALID_ACCOUNT_STATES:
                    self._issue('partial', 'InvalidMemberAccountStatus')
                    success = False
                    continue
                members[account]['account_status'] = status
                members[account]['inactive'] = status in ('DISABLED', 'SUSPENDED')
                resource_states = row.get('resourceState')
                if not isinstance(resource_states, dict):
                    self._issue('partial', 'MissingMemberResourceStates')
                    success = False
                    continue
                for name in ('ec2', 'ecr', 'lambda', 'lambdaCode', 'codeRepository'):
                    resource = resource_states.get(name)
                    value = resource.get('status') if isinstance(resource, dict) else None
                    if value not in VALID_ACCOUNT_STATES:
                        if name in ('ec2', 'ecr') or resource is not None:
                            self._issue('partial', 'InvalidMemberScanType')
                            success = False
                        value = 'UNKNOWN'
                    members[account]['scan_types'][name] = value
            missing = set(batch) - seen - failed_ids
            if missing:
                self._issue('partial', 'MissingMemberAccountStatus')
                success = False
        report['member_statuses_complete'] = success
