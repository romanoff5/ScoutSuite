"""M10-L strict offline IAM Identity Center API, normalization, and incomplete evidence tests."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.exceptions import ClientError
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import (
    classify_identitycenter_admin, classify_identitycenter_broad,
    classify_identitycenter_cross_account)
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.identitycenter import IdentityCenterFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.identitycenter.base import IdentityCenter, _risk


INSTANCE = 'arn:aws:sso:::instance/ssoins-1111111111111111'
PS = 'arn:aws:sso:::permissionSet/ssoins-1111111111111111/ps-2222222222222222'
STORE = 'd-1234567890'
USER = '11111111-1111-1111-1111-111111111111'
GROUP = '22222222-2222-2222-2222-222222222222'
ACCOUNTS = ('111111111111', '222222222222')
ROOT = Path(__file__).resolve().parents[1]


def failure(code='AccessDeniedException'):
    return ClientError({'Error': {'Code': code, 'Message': 'synthetic error'}}, 'ListAccountAssignments')


def ps_record():
    return {
        'id': PS, 'name': 'Admin', 'arn': PS,
        'managed_policies': [{'Name': 'AdministratorAccess',
                              'Arn': 'arn:aws:iam::aws:policy/AdministratorAccess'}],
        'customer_managed_policies': [],
        'inline_policy': {'Statement': [{'Effect': 'Allow', 'Action': 'ec2:Describe*',
                                         'Resource': '*'}]},
        'permissions_boundary': None, 'provisioned_account_ids': list(ACCOUNTS),
        'collection': {name: 'complete' for name in (
            'details', 'managed_policies', 'customer_managed_policies',
            'inline_policy', 'permissions_boundary', 'assignments')},
        'assignments': {
            account + ':GROUP:' + GROUP: {
                'id': account + ':GROUP:' + GROUP, 'account_id': account,
                'principal_id': GROUP, 'principal_type': 'GROUP',
                'permission_set_arn': PS, 'instance_arn': INSTANCE, 'region': 'eu-west-1'}
            for account in ACCOUNTS},
    }


def region_inventory():
    return {
        'collection': {'instances': 'complete'},
        'instances': {
            INSTANCE: {
                'arn': INSTANCE, 'name': 'Organization SSO', 'identity_store_id': STORE,
                'permission_sets': {PS: ps_record()},
                'users': {
                    USER: {'id': USER, 'name': '<test-user>', 'emails': ['person@example.invalid']}},
                'groups': {
                    GROUP: {'id': GROUP, 'name': '<Administrators>',
                            'member_emails': ['person@example.invalid'],
                            'members': {'mem-1': {'user_id': USER, 'emails': ['person@example.invalid']}}},
                },
                'collection': {'permission_sets': 'complete', 'users': 'complete',
                               'groups': 'complete', 'memberships': 'complete'},
            },
        },
    }


def organization(management=True, accounts_complete=True):
    return {
        'organization': {'Id': 'o-demo12345',
                         'ManagementAccountId': ACCOUNTS[0] if management else ACCOUNTS[1]},
        'accounts': [{'Id': a, 'Name': 'AWS-' + a, 'Email': a + '@example.invalid',
                      'State': 'ACTIVE'} for a in ACCOUNTS],
        'collection': {'accounts': 'complete' if accounts_complete else 'denied'},
    }


def test_aws_sdk_service_models_and_operation_input_output_shapes():
    models = get_session()
    sso = models.get_service_model('sso-admin')
    identity = models.get_service_model('identitystore')
    for name, key in [
        ('ListInstances', 'Instances'), ('ListPermissionSets', 'PermissionSets'),
        ('ListManagedPoliciesInPermissionSet', 'AttachedManagedPolicies'),
        ('ListCustomerManagedPolicyReferencesInPermissionSet', 'CustomerManagedPolicyReferences'),
        ('ListAccountsForProvisionedPermissionSet', 'AccountIds'),
        ('ListAccountAssignments', 'AccountAssignments'),
    ]:
        op = sso.operation_model(name)
        assert key in op.output_shape.members
        assert 'NextToken' in op.output_shape.members
    for name, key in [('ListUsers', 'Users'), ('ListGroups', 'Groups'),
                      ('ListGroupMemberships', 'GroupMemberships')]:
        op = identity.operation_model(name)
        assert key in op.output_shape.members
        assert 'NextToken' in op.output_shape.members
    assert 'PermissionSet' in sso.operation_model('DescribePermissionSet').output_shape.members
    assert 'InlinePolicy' in sso.operation_model('GetInlinePolicyForPermissionSet').output_shape.members
    assert 'PermissionsBoundary' in sso.operation_model('GetPermissionsBoundaryForPermissionSet').output_shape.members


def test_stubber_real_sdk_model_empty_intermediate_page_and_pagination():
    async def run():
        client = boto3.client('sso-admin', region_name='eu-west-1',
                              aws_access_key_id='synthetic', aws_secret_access_key='synthetic')
        try:
            with Stubber(client) as stub:
                stub.add_response('list_instances',
                                  {'Instances': [], 'NextToken': 'next'},
                                  {})
                stub.add_response('list_instances',
                                  {'Instances': [{'InstanceArn': INSTANCE,
                                                  'IdentityStoreId': STORE}]},
                                  {'NextToken': 'next'})
                rows, state = await IdentityCenterFacade(object(), ACCOUNTS[0])._pages(
                    client, 'list_instances', 'Instances')
                stub.assert_no_pending_responses()
            assert state == 'complete'
            assert rows[0]['IdentityStoreId'] == STORE
        finally:
            client.close()
    asyncio.run(run())


def test_full_inventory_with_group_emails_and_cross_account_admin():
    async def run():
        sso = Mock()
        store = Mock()
        sso.list_instances.return_value = {
            'Instances': [{'InstanceArn': INSTANCE, 'IdentityStoreId': STORE,
                           'OwnerAccountId': ACCOUNTS[0], 'Name': '<SSO>'}]}
        sso.list_permission_sets.return_value = {'PermissionSets': [PS]}
        sso.describe_permission_set.return_value = {'PermissionSet': {'Name': '<Admin>'}}
        sso.list_managed_policies_in_permission_set.return_value = {
            'AttachedManagedPolicies': [{'Name': 'AdministratorAccess',
                                          'Arn': 'arn:aws:iam::aws:policy/AdministratorAccess'}]}
        sso.list_customer_managed_policy_references_in_permission_set.return_value = {
            'CustomerManagedPolicyReferences': []}
        sso.get_inline_policy_for_permission_set.return_value = {
            'InlinePolicy': '{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}'}
        sso.get_permissions_boundary_for_permission_set.return_value = {'PermissionsBoundary': None}
        sso.list_accounts_for_provisioned_permission_set.return_value = {
            'AccountIds': list(ACCOUNTS)}
        sso.list_account_assignments.side_effect = [
            {'AccountAssignments': [{
                'AccountId': a, 'PermissionSetArn': PS, 'PrincipalId': GROUP,
                'PrincipalType': 'GROUP'}]} for a in ACCOUNTS]
        store.list_users.return_value = {'Users': [{
            'UserId': USER, 'UserName': '<user>',
            'Emails': [{'Value': 'private@example.invalid', 'Primary': True}]}]}
        store.list_groups.return_value = {
            'Groups': [{'GroupId': GROUP, 'DisplayName': '<administrators>'}]}
        store.list_group_memberships.return_value = {
            'GroupMemberships': [{'MembershipId': 'mem1', 'GroupId': GROUP,
                                   'MemberId': {'UserId': USER}}]}
        facade = IdentityCenterFacade(object(), ACCOUNTS[0])
        with patch.object(AWSFacadeUtils, 'get_client',
                          side_effect=lambda service, *_: sso if service == 'sso-admin' else store):
            data = await facade.get_region('eu-west-1')
        instance = data['instances'][INSTANCE]
        assert instance['users'][USER]['primary_email'] == 'private@example.invalid'
        assert instance['groups'][GROUP]['member_emails'] == ['private@example.invalid']
        assert len(instance['permission_sets'][PS]['assignments']) == 2
        assert data['collection']['instances'] == 'complete'
        assert facade.region_statuses['eu-west-1']['instances'] == 'complete'
        public = SimpleNamespace(
            owner_id=ACCOUNTS[0],
            identitycenter=SimpleNamespace(
                region_statuses=facade.region_statuses,
                get_region=AsyncMock(return_value=data)),
            organizations=SimpleNamespace(get_organization_inventory=AsyncMock(
                return_value=organization())))
        async def region_list(*args, **kwargs):
            return ['eu-west-1']
        public.build_region_list = region_list
        resources = IdentityCenter(public)
        await resources.fetch_all()
        ps = resources['regions']['eu-west-1']['instances'][INSTANCE]['permission_sets'][PS]
        assert ps['admin_candidate'] is True
        assert ps['broad_permissions_candidate'] is True
        assert all(row['cross_account_admin_candidate'] for row in ps['assignments'].values())
        assert all(row['account_email'] for row in ps['assignments'].values())
        assert all(row['emails'] == ['private@example.invalid'] for row in ps['assignments'].values())
        assert resources['collection_status'] == 'complete'
        assert 'private@example.invalid' in json.dumps(dict(resources))
    asyncio.run(run())


def test_cross_account_admin_via_membership_in_distinct_groups():
    async def run():
        second_group = '33333333-3333-3333-3333-333333333333'
        data = region_inventory()
        instance = data['instances'][INSTANCE]
        first = instance['permission_sets'][PS]['assignments']
        first.clear()
        for account, group_id in zip(ACCOUNTS, (GROUP, second_group)):
            key = account + ':GROUP:' + group_id
            first[key] = {'id': key, 'account_id': account, 'principal_type': 'GROUP',
                          'principal_id': group_id, 'permission_set_arn': PS,
                          'instance_arn': INSTANCE, 'region': 'eu-west-1'}
        instance['groups'][second_group] = {
            'id': second_group, 'name': 'Other admin group',
            'member_emails': ['person@example.invalid'],
            'members': {'mem2': {'user_id': USER, 'emails': ['person@example.invalid']}}}
        facade = SimpleNamespace(
            owner_id=ACCOUNTS[0], identitycenter=SimpleNamespace(
                get_region=AsyncMock(return_value=data),
                region_statuses={'eu-west-1': {'instances': 'complete'}}),
            organizations=SimpleNamespace(
                get_organization_inventory=AsyncMock(return_value=organization())),
            build_region_list=AsyncMock(return_value=['eu-west-1']))
        resource = IdentityCenter(facade)
        await resource.fetch_all()
        assignments = resource['regions']['eu-west-1']['instances'][INSTANCE][
            'permission_sets'][PS]['assignments']
        assert all(row['cross_account_admin_candidate'] for row in assignments.values())
        assert all(row['cross_account_admin_user_ids'] == [USER] for row in assignments.values())
        assert all(row['admin_account_ids'] == list(ACCOUNTS) for row in assignments.values())
    asyncio.run(run())


def test_wildcard_scoped_to_one_resource_is_broad_but_not_administrator():
    record = ps_record()
    record['managed_policies'] = []
    record['inline_policy'] = {
        'Statement': [{'Effect': 'Allow', 'Action': '*',
                       'Resource': 'arn:aws:s3:::one-bucket'}]}
    assert _risk(record) == (False, True, True)


def test_missing_organization_admin_never_passes_even_with_visible_assignments():
    async def run():
        public = SimpleNamespace(
            owner_id=ACCOUNTS[0],
            identitycenter=SimpleNamespace(
                region_statuses={'eu-west-1': {'instances': 'complete'}},
                get_region=AsyncMock(return_value=region_inventory())),
            organizations=SimpleNamespace(get_organization_inventory=AsyncMock(
                return_value=organization(management=False, accounts_complete=False))))
        public.build_region_list = AsyncMock(return_value=['eu-west-1'])
        ctx = RunContext('aws').setup()
        try:
            resources = IdentityCenter(public)
            await resources.fetch_all()
            assert resources['collection_status'] == 'partial'
            assert resources['organization_coverage']['status'] == 'partial'
            assert any(x['reason_code'] == 'OrganizationManagementScopeUnverified'
                       for x in ctx.collection_issues)
            rows = resources['regions']['eu-west-1']['instances'][INSTANCE][
                'permission_sets'][PS]['assignments'].values()
            for item in rows:
                assert item['organization_coverage_status'] == 'partial'
            assert classify_identitycenter_admin({
                'admin_candidate': False, 'policy_analysis_complete': True,
                'principal_resolved': True, 'organization_coverage_status': 'partial'}) == 'unknown'
            assert classify_identitycenter_cross_account({
                'cross_account_admin_candidate': False, 'policy_analysis_complete': True,
                'principal_resolved': True, 'organization_coverage_status': 'partial'}) == 'unknown'
        finally:
            await ctx.aclose()
    asyncio.run(run())


def test_api_denied_preserves_partial_pages_and_does_not_invent_empty_inventory():
    async def run():
        client = Mock()
        client.list_account_assignments.side_effect = [
            {'AccountAssignments': [{'AccountId': ACCOUNTS[0]}], 'NextToken': 'more'},
            failure()]
        ctx = RunContext('aws').setup()
        try:
            rows, status = await IdentityCenterFacade(object(), ACCOUNTS[0])._pages(
                client, 'list_account_assignments', 'AccountAssignments', {})
            assert rows == [{'AccountId': ACCOUNTS[0]}]
            assert status == 'partial'
            assert any(x['status'] == 'partial' for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
    asyncio.run(run())


def test_repeated_token_missing_fields_and_permission_policy_ambiguity():
    async def run():
        fac = IdentityCenterFacade(object(), ACCOUNTS[0])
        client = Mock()
        client.list_users.side_effect = [
            {'Users': [], 'NextToken': 'duplicate'}, {'Users': [], 'NextToken': 'duplicate'}]
        ctx = RunContext('aws').setup()
        try:
            assert (await fac._pages(client, 'list_users', 'Users'))[1] == 'partial'
            assert (await fac._pages(Mock(list_users=Mock(return_value={})),
                                     'list_users', 'Users'))[1] == 'partial'
            assert len(ctx.collection_issues) >= 2
        finally:
            await ctx.aclose()
    asyncio.run(run())
    obj = ps_record()
    obj['managed_policies'] = []
    obj['customer_managed_policies'] = [{'Name': 'AuditAdmin', 'Path': '/'}]
    assert _risk(obj) == (False, False, False)
    obj['customer_managed_policies'] = []
    obj['inline_policy'] = {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}
    assert _risk(obj) == (True, True, True)
    obj['inline_policy'] = {'Statement': [{'Effect': 'Deny', 'Action': '*', 'Resource': '*'}]}
    assert _risk(obj) == (False, False, True)
    assert classify_identitycenter_admin({'admin_candidate': True}) == 'insecure'
    assert classify_identitycenter_broad({'broad_permissions_candidate': True}) == 'insecure'
    assert classify_identitycenter_cross_account({'cross_account_admin_candidate': True}) == 'insecure'


def test_default_rules_evidence_status_unknown_on_unverified_scope(tmp_path):
    names = ('identitycenter-admin-assignment.json', 'identitycenter-broad-permissions.json',
             'identitycenter-cross-account-admin.json')
    ruleset_path = tmp_path / 'rules.json'
    ruleset_path.write_text(json.dumps({
        'about': 'Synthetic identity-center assignment rules',
        'rules': {name: [{'enabled': True, 'level': 'danger'}] for name in names}}))
    candidate = {'admin_candidate': True, 'broad_permissions_candidate': True,
                 'cross_account_admin_candidate': True, 'principal_resolved': True,
                 'policy_analysis_complete': True,
                 'organization_coverage_status': 'partial'}
    unknown = {'admin_candidate': False, 'broad_permissions_candidate': False,
               'cross_account_admin_candidate': False, 'principal_resolved': False,
               'policy_analysis_complete': False,
               'organization_coverage_status': 'partial'}
    data = {'regions': {'eu-west-1': {'instances': {
        'one': {'permission_sets': {'ps': {'assignments': {
            'assigned': candidate, 'unresolved': unknown}}}}}}}}
    provider = SimpleNamespace(services={'identitycenter': data}, service_list=['identitycenter'])
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(ruleset_path))).run(provider)
        for name in names:
            rule = data['findings'][name[:-5]]
            assert rule['flagged_items'] == 1
            assert rule['assessment_status'] == 'incomplete'
            assert rule['evaluation_summary']['counts']['unknown'] == 1
    finally:
        asyncio.run(ctx.aclose())


def test_report_partials_escape_untrusted_usernames_and_contact_emails():
    partials = ROOT / 'ScoutSuite/output/data/html/partials/aws'
    paths = [
        partials / 'services.identitycenter.regions.id.instances.id.permission_sets.html',
        partials / 'services.identitycenter.regions.id.instances.id.permission_sets.id.assignments.html',
    ]
    for path in paths:
        content = path.read_text(encoding='utf-8')
        assert '{{{' not in content
        assert 'innerHTML' not in content
        assert 'eval(' not in content
        assert '{{name}}' in content
    assert '{{account_email}}' in paths[1].read_text(encoding='utf-8')
