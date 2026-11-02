"""Preserve resource identities and group emails in confidential local reports."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.resources.base import AWSResources
from ScoutSuite.providers.utils import get_non_provider_id


class Instances(AWSResources):
    def __init__(self, facade, region):
        super().__init__(facade)
        self.region = region

    @staticmethod
    def issue(reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue('partial', 'identitycenter', reason)

    async def fetch_all(self):
        for source in await self.facade.identitycenter.get_instances(self.region):
            if not isinstance(source, dict) or not isinstance(source.get('instance_arn'), str):
                self.issue('InvalidIdentityCenterRecord')
                continue
            key = get_non_provider_id(source['instance_arn'])
            if key in self:
                self.issue('DuplicateIdentityCenterRecord')
                continue
            permissions, assignments = {}, {}
            for ps in source.get('permission_sets', []):
                if not isinstance(ps, dict) or not isinstance(ps.get('permission_set_arn'), str):
                    self.issue('InvalidPermissionSetRecord')
                    continue
                pskey = get_non_provider_id(ps['permission_set_arn'])
                if pskey in permissions:
                    self.issue('DuplicatePermissionSetRecord')
                    continue
                permissions[pskey] = dict(ps, id=pskey)
            for item in source.get('assignments', []):
                if not isinstance(item, dict) or any(
                        not isinstance(item.get(field), str) or not item[field]
                        for field in ('permission_set_arn', 'account_id', 'principal_id', 'principal_type')):
                    self.issue('InvalidAccountAssignmentRecord')
                    continue
                identity = ':'.join((
                    source['instance_arn'], item['permission_set_arn'], item['account_id'],
                    item['principal_type'], item['principal_id']))
                aid = get_non_provider_id(identity)
                if aid in assignments:
                    self.issue('DuplicateAccountAssignmentRecord')
                    continue
                assignments[aid] = dict(item, id=aid, name=(
                    item.get('principal_name') or item.get('principal_id')))
            self[key] = {
                'id': key, 'name': source.get('name'), 'region': self.region,
                'instance_arn': source['instance_arn'],
                'identity_store_id': source.get('identity_store_id'),
                'owner_account_id': source.get('owner_account_id'),
                'status': source.get('status'),
                'status_reason': source.get('status_reason'),
                'created_date': source.get('created_date'),
                'instance_enumeration_complete': source.get('instance_enumeration_complete'),
                'permission_sets_complete': source.get('permission_sets_complete'),
                'permission_sets_count': len(permissions),
                'assignments_count': len(assignments),
                'permission_sets': permissions,
                'assignments': assignments,
            }
