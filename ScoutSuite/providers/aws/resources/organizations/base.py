"""M10-C global Organizations account and policy diagnostics (no secret values)."""
from datetime import datetime

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources


class Organizations(AWSResources):
    def __init__(self, facade):
        super().__init__(facade)
        self.service = 'organizations'

    @staticmethod
    def _issue(reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue('partial', 'organizations', reason)

    @classmethod
    def _organization(cls, raw):
        if not isinstance(raw, dict):
            return None
        feature_set = raw.get('FeatureSet')
        if feature_set not in ('ALL', 'CONSOLIDATED_BILLING'):
            cls._issue('UnknownFeatureSet')
        return {
            'id': raw.get('Id'), 'name': raw.get('Id'), 'arn': raw.get('Arn'),
            'feature_set': feature_set if feature_set in
                           ('ALL', 'CONSOLIDATED_BILLING') else 'UNKNOWN',
            'management_account_id': raw.get('ManagementAccountId') or raw.get('MasterAccountId'),
            'management_account_arn': raw.get('ManagementAccountArn') or raw.get('MasterAccountArn'),
            'management_account_email': raw.get('ManagementAccountEmail') or raw.get('MasterAccountEmail'),
            # Deprecated on AWS; retained for diagnostic completeness, never used for root SCP evaluation.
            'available_policy_types': [
                {'type': item.get('Type'), 'status': item.get('Status')}
                for item in (raw.get('AvailablePolicyTypes') or [])
                if isinstance(item, dict)
            ],
        }

    @classmethod
    def _root(cls, raw, feature_set):
        identifier = raw['Id']
        policy_types = raw.get('PolicyTypes')
        state = 'UNKNOWN'
        if isinstance(policy_types, list):
            scps = [item for item in policy_types if isinstance(item, dict)
                    and item.get('Type') == 'SERVICE_CONTROL_POLICY']
            if len(scps) > 1:
                cls._issue('DuplicateSCPPolicyType')
            elif scps:
                state = scps[0].get('Status') or 'UNKNOWN'
            elif feature_set == 'ALL':
                state = 'NOT_ENABLED'
            elif feature_set == 'CONSOLIDATED_BILLING':
                state = 'NOT_APPLICABLE'
        else:
            cls._issue('InvalidRootPolicyTypes')
        if state not in ('ENABLED', 'DISABLED', 'NOT_ENABLED', 'NOT_APPLICABLE'):
            state = 'UNKNOWN'
            cls._issue('UnknownRootSCPState')
        return {
            'id': identifier, 'name': raw.get('Name') or identifier,
            'arn': raw.get('Arn'), 'scp_status': state,
            'scp_enabled': state == 'ENABLED' if state not in
                           ('UNKNOWN', 'NOT_APPLICABLE') else None,
            'policy_types': [
                {'type': item.get('Type'), 'status': item.get('Status')}
                for item in policy_types if isinstance(item, dict)
            ] if isinstance(policy_types, list) else [],
        }

    @classmethod
    def _account(cls, raw):
        state = raw.get('State')
        if state not in ('PENDING_ACTIVATION', 'ACTIVE', 'SUSPENDED',
                         'PENDING_CLOSURE', 'CLOSED'):
            state = 'UNKNOWN'
            cls._issue('UnknownAccountState')
        identifier = raw['Id']
        joined_at = raw.get('JoinedTimestamp')
        if isinstance(joined_at, datetime):
            joined_at = joined_at.isoformat()
        return {
            'id': identifier, 'name': raw.get('Name') or identifier,
            'arn': raw.get('Arn'), 'email': raw.get('Email'),
            'state': state, 'legacy_status': raw.get('Status'),
            'joined_method': raw.get('JoinedMethod'), 'joined_timestamp': joined_at,
        }

    async def fetch_all(self, **kwargs):
        collected = await self.facade.organizations.get_organization_inventory()
        raw_org = collected.get('organization')
        organization = self._organization(raw_org)
        feature_set = organization['feature_set'] if organization is not None else 'UNKNOWN'
        self['organizations'] = {organization['id']: organization} if organization is not None else {}
        self['organizations_count'] = len(self['organizations'])
        self['roots'] = {root['Id']: self._root(root, feature_set)
                         for root in collected.get('roots', [])}
        self['roots_count'] = len(self['roots'])
        self['accounts'] = {account['Id']: self._account(account)
                            for account in collected.get('accounts', [])}
        self['accounts_count'] = len(self['accounts'])
        self['collection'] = dict(collected['collection'])
