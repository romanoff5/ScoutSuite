"""M10-L: SSO account assignments, group emails and unknown-safe evidence."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_identitycenter_admin_assignment
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.identitycenter import IdentityCenterFacade, PAGE_SIZE
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.provider import AWSProvider
from ScoutSuite.providers.aws.resources.identitycenter.base import IdentityCenter

ROOT = Path(__file__).resolve().parents[1]
REGION = 'us-east-1'
INSTANCE = 'arn:aws:sso:::instance/ssoins-1234567890abcdef'
PERMISSION = 'arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-1234567890abcdef'
ACCOUNT = '000000000000'
GROUP = '11111111-1111-1111-1111-111111111111'
USER = '22222222-2222-2222-2222-222222222222'
MEMBERSHIP = '33333333-3333-3333-3333-333333333333'
STORE = 'd-1234567890'
ADMIN = 'arn:aws:iam::aws:policy/AdministratorAccess'


def client(name):
    return boto3.client(name, region_name=REGION,
                        aws_access_key_id='synthetic', aws_secret_access_key='synthetic')


def test_model_has_required_read_operations():
    sso = get_session().get_service_model('sso-admin')
    identity = get_session().get_service_model('identitystore')
    sso_ops = (
        'ListInstances', 'ListPermissionSets', 'DescribePermissionSet',
        'ListManagedPoliciesInPermissionSet', 'ListCustomerManagedPolicyReferencesInPermissionSet',
        'GetInlinePolicyForPermissionSet', 'GetPermissionsBoundaryForPermissionSet',
        'ListAccountsForProvisionedPermissionSet', 'ListAccountAssignments')
    for name in sso_ops:
        assert name in sso.operation_names
    for name in ('DescribeUser', 'DescribeGroup', 'ListGroupMemberships'):
        assert name in identity.operation_names
    assert 'AccountId' in sso.operation_model('ListAccountAssignments').input_shape.required_members
    assert 'IdentityStoreId' in identity.operation_model('ListGroupMemberships').input_shape.required_members


def test_sdk_stubber_reconstructs_group_to_account_admin_access_with_email():
    async def scenario():
        sso, directory = client('sso-admin'), client('identitystore')
        try:
            with Stubber(sso) as a, Stubber(directory) as b:
                a.add_response('list_instances', {'Instances': [{
                    'InstanceArn': INSTANCE, 'IdentityStoreId': STORE,
                    'OwnerAccountId': ACCOUNT, 'Name': 'synthetic-instance',
                    'Status': 'ACTIVE'}]}, {'MaxResults': PAGE_SIZE})
                a.add_response('list_permission_sets', {'PermissionSets': [PERMISSION]},
                               {'InstanceArn': INSTANCE, 'MaxResults': PAGE_SIZE})
                a.add_response('describe_permission_set', {'PermissionSet': {
                    'Name': 'Admin', 'PermissionSetArn': PERMISSION,
                    'SessionDuration': 'PT1H'}},
                    {'InstanceArn': INSTANCE, 'PermissionSetArn': PERMISSION})
                a.add_response('list_managed_policies_in_permission_set', {
                    'AttachedManagedPolicies': [{'Name': 'AdministratorAccess', 'Arn': ADMIN}]},
                    {'InstanceArn': INSTANCE, 'PermissionSetArn': PERMISSION,
                     'MaxResults': PAGE_SIZE})
                a.add_response('list_customer_managed_policy_references_in_permission_set', {
                    'CustomerManagedPolicyReferences': []},
                    {'InstanceArn': INSTANCE, 'PermissionSetArn': PERMISSION,
                     'MaxResults': PAGE_SIZE})
                a.add_response('get_inline_policy_for_permission_set', {},
                               {'InstanceArn': INSTANCE, 'PermissionSetArn': PERMISSION})
                a.add_response('get_permissions_boundary_for_permission_set', {
                    'PermissionsBoundary': {'ManagedPolicyArn':
                                            'arn:aws:iam::aws:policy/ReadOnlyAccess'}},
                    {'InstanceArn': INSTANCE, 'PermissionSetArn': PERMISSION})
                a.add_response('list_accounts_for_provisioned_permission_set', {
                    'AccountIds': [ACCOUNT]}, {'InstanceArn': INSTANCE,
                                               'PermissionSetArn': PERMISSION,
                                               'MaxResults': PAGE_SIZE})
                a.add_response('list_account_assignments', {
                    'AccountAssignments': [{
                        'AccountId': ACCOUNT, 'PermissionSetArn': PERMISSION,
                        'PrincipalId': GROUP, 'PrincipalType': 'GROUP'}]},
                    {'InstanceArn': INSTANCE, 'PermissionSetArn': PERMISSION,
                     'AccountId': ACCOUNT, 'MaxResults': PAGE_SIZE})
                b.add_response('describe_group', {
                    'GroupId': GROUP, 'DisplayName': 'Security Administrators',
                    'GroupArn': 'arn:aws:identitystore:::group/' + GROUP,
                    'Revision': '2', 'IdentityStoreId': STORE}, {'IdentityStoreId': STORE, 'GroupId': GROUP})
                b.add_response('list_group_memberships', {'GroupMemberships': [{
                    'MembershipId': MEMBERSHIP,
                    'MembershipArn': 'arn:aws:identitystore:::membership/' + MEMBERSHIP,
                    'IdentityStoreId': STORE, 'GroupId': GROUP,
                    'MemberId': {'UserId': USER}}]},
                    {'IdentityStoreId': STORE, 'GroupId': GROUP, 'MaxResults': PAGE_SIZE})
                b.add_response('describe_user', {
                    'UserId': USER, 'IdentityStoreId': STORE,
                    'UserArn': 'arn:aws:identitystore:::user/' + USER,
                    'Revision': '3',
                    'UserName': 'synthetic-admin', 'DisplayName': '<admin & member>',
                    'Emails': [{'Value': 'admin@example.test', 'Primary': True},
                               {'Value': 'secondary@example.test', 'Primary': False}]},
                    {'IdentityStoreId': STORE, 'UserId': USER})
                with patch.object(AWSFacadeUtils, 'get_client',
                                  side_effect=lambda svc, session, region: (
                                      sso if svc == 'sso-admin' else directory)):
                    facade = IdentityCenterFacade(object())
                    result = await facade.get_instances(REGION)
                a.assert_no_pending_responses()
                b.assert_no_pending_responses()
        finally:
            sso.close()
            directory.close()
        assert len(result) == 1
        assert result[0]['owner_account_id'] == ACCOUNT
        assert result[0]['permission_sets_complete'] is True
        assert result[0]['permission_sets'][0]['policy_collection_complete'] is True
        raw = result[0]['assignments'][0]
        assert raw['administrator_access_managed_policy'] is True
        assert raw['principal_name'] == 'Security Administrators'
        assert raw['group_members_complete'] is True
        assert raw['group_members'][0]['email'] == 'admin@example.test'
        assert raw['group_members'][0]['emails'][1]['Value'] == 'secondary@example.test'
        assert raw['group_members'][0]['membership_id'] == MEMBERSHIP
        assert raw['group_members'][0]['membership_arn'].endswith(MEMBERSHIP)
        assert raw['group_members'][0]['principal_arn'].endswith(USER)
        assert raw['permission_boundary']['ManagedPolicyArn'].endswith('ReadOnlyAccess')
        assert raw['account_id'] == ACCOUNT and raw['permission_set_arn'] == PERMISSION
        source = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]),
            identitycenter=SimpleNamespace(get_instances=AsyncMock(return_value=result)))
        resources = IdentityCenter(source)
        await resources.fetch_all(regions=[REGION])
        assert resources['regions_count'] == 1
        assert resources['instances_count'] == 1
        item = next(iter(resources['regions'][REGION]['instances'].values()))
        assert item['permission_sets_count'] == 1 and item['assignments_count'] == 1
        assert 'assignments' not in next(iter(item['permission_sets'].values()))
        mapped = next(iter(item['assignments'].values()))
        assert mapped['group_members'][0]['email'] == 'admin@example.test'
        assert mapped['id'].startswith('scoutid-')
    asyncio.run(scenario())


def test_pagination_token_cycle_and_deny_dont_claim_complete():
    async def scenario():
        sdk = Mock()
        sdk.list_instances.side_effect = [
            {'Instances': [], 'NextToken': 'repeat'},
            {'Instances': [], 'NextToken': 'repeat'}]
        context = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                result = await IdentityCenterFacade(object()).get_instances(REGION)
            assert result == []
            assert sdk.list_instances.call_count == 2
            assert any(x['reason_code'] == 'ListInstancesInvalidPaginationToken'
                       for x in context.collection_issues)
        finally:
            await context.aclose()
    asyncio.run(scenario())


def test_policy_missing_or_directory_denial_is_not_verified_safe():
    async def scenario():
        sso = Mock()
        sso.list_instances.return_value = {
            'Instances': [{'InstanceArn': INSTANCE, 'IdentityStoreId': STORE}]}
        sso.list_permission_sets.return_value = {'PermissionSets': [PERMISSION]}
        sso.describe_permission_set.return_value = {'PermissionSet': {
            'Name': 'PolicyReview', 'PermissionSetArn': PERMISSION}}
        sso.list_managed_policies_in_permission_set.side_effect = RuntimeError('blocked')
        sso.list_customer_managed_policy_references_in_permission_set.return_value = {
            'CustomerManagedPolicyReferences': []}
        sso.get_inline_policy_for_permission_set.return_value = {}
        sso.get_permissions_boundary_for_permission_set.return_value = {}
        sso.list_accounts_for_provisioned_permission_set.return_value = {'AccountIds': [ACCOUNT]}
        sso.list_account_assignments.return_value = {'AccountAssignments': [{
            'AccountId': ACCOUNT, 'PermissionSetArn': PERMISSION,
            'PrincipalId': USER, 'PrincipalType': 'USER'}]}
        directory = Mock()
        directory.describe_user.side_effect = RuntimeError('denied')
        context = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client',
                              side_effect=lambda svc, session, region: (
                                  sso if svc == 'sso-admin' else directory)):
                records = await IdentityCenterFacade(object()).get_instances(REGION)
            assert len(records) == 1
            assert records[0]['permission_sets_complete'] is False
            assignment = records[0]['assignments'][0]
            assert assignment['identity_resolution_status'] == 'unknown'
            assert assignment['policy_collection_complete'] is False
            assert classify_identitycenter_admin_assignment(assignment) == 'unknown'
            assert any(x['scope'] == 'identitycenter' for x in context.collection_issues)
        finally:
            await context.aclose()
    asyncio.run(scenario())


def test_admin_assignment_rule_uses_confirmed_managed_policy_only(tmp_path):
    assert classify_identitycenter_admin_assignment({
        'administrator_access_managed_policy': True,
        'policy_collection_complete': True}) == 'insecure'
    assert classify_identitycenter_admin_assignment({
        'administrator_access_managed_policy': False,
        'policy_collection_complete': True}) == 'not_applicable'
    assert classify_identitycenter_admin_assignment({
        'administrator_access_managed_policy': False,
        'policy_collection_complete': False}) == 'unknown'
    assert classify_identitycenter_admin_assignment(None) == 'unknown'
    rules = {'about': 'synthetic', 'rules': {
        'identitycenter-aws-admin-policy-assignment.json': [
            {'enabled': True, 'level': 'warning'}]}}
    file = tmp_path / 'rules.json'
    file.write_text(json.dumps(rules), encoding='utf-8')
    assigned = {
        'admin': {'administrator_access_managed_policy': True,
                  'policy_collection_complete': True, 'principal_id': GROUP},
        'other': {'administrator_access_managed_policy': False,
                  'policy_collection_complete': True, 'principal_id': USER},
        'unknown': {'administrator_access_managed_policy': False,
                    'policy_collection_complete': False, 'principal_id': USER}}
    provider = SimpleNamespace(services={'identitycenter': {'regions': {REGION: {
        'instances': {'test': {'assignments': assigned}}}}}}, service_list=['identitycenter'])
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(file))).run(provider)
        result = provider.services['identitycenter']['findings'][
            'identitycenter-aws-admin-policy-assignment']
        assert result['flagged_items'] == 1
        assert result['assessment_status'] == 'incomplete'
        assert result['evaluation_summary']['counts'] == {
            'secure': 0, 'insecure': 1, 'unknown': 1, 'not_applicable': 1}
    finally:
        ctx.cleanup()


def test_default_selection_and_escaped_confidential_report_fields():
    creds = SimpleNamespace(session=object())
    with patch('ScoutSuite.providers.aws.provider.get_partition_name', return_value='aws'), \
         patch('ScoutSuite.providers.aws.provider.get_aws_account_id', return_value=ACCOUNT), \
         patch('ScoutSuite.providers.aws.provider.AWSServicesConfig',
               side_effect=lambda c: SimpleNamespace(credentials=c, identitycenter={}, iam={}, s3={})):
        default = AWSProvider(credentials=creds)
        chosen = AWSProvider(credentials=creds, services=['identitycenter'])
        skipped = AWSProvider(credentials=creds, skipped_services=['identitycenter'])
    assert 'identitycenter' in default.service_list
    assert chosen.service_list == ['identitycenter']
    assert 'identitycenter' not in skipped.service_list
    metadata = json.loads((ROOT / 'ScoutSuite/providers/aws/metadata.json').read_text())
    assert metadata['security']['identitycenter']['resources']['instances']['path'] == (
        'services.identitycenter.regions.id.instances')
    template = (ROOT / 'ScoutSuite/output/data/html/partials/aws/'
                'services.identitycenter.regions.id.instances.html').read_text()
    for expected in ('{{instance_arn}}', '{{principal_id}}', '{{email}}',
                     '{{permission_set_arn}}', '{{principal_email}}'):
        assert expected in template
    assert '{{{' not in template
    assert 'onclick=' not in template
    assert 'javascript:' not in template


def test_missing_identitystore_client_preserves_assignment_and_marks_unknown():
    async def scenario():
        sso = Mock()
        sso.list_instances.return_value = {
            'Instances': [{'InstanceArn': INSTANCE, 'IdentityStoreId': STORE}]}
        sso.list_permission_sets.return_value = {'PermissionSets': [PERMISSION]}
        sso.describe_permission_set.return_value = {'PermissionSet': {
            'Name': 'Admin', 'PermissionSetArn': PERMISSION}}
        sso.list_managed_policies_in_permission_set.return_value = {
            'AttachedManagedPolicies': [{'Name': 'AdministratorAccess', 'Arn': ADMIN}]}
        sso.list_customer_managed_policy_references_in_permission_set.return_value = {
            'CustomerManagedPolicyReferences': []}
        sso.get_inline_policy_for_permission_set.return_value = {}
        sso.get_permissions_boundary_for_permission_set.return_value = {}
        sso.list_accounts_for_provisioned_permission_set.return_value = {'AccountIds': [ACCOUNT]}
        sso.list_account_assignments.return_value = {'AccountAssignments': [{
            'AccountId': ACCOUNT, 'PermissionSetArn': PERMISSION,
            'PrincipalId': GROUP, 'PrincipalType': 'GROUP'}]}
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client',
                              side_effect=lambda svc, session, region: (
                                  sso if svc == 'sso-admin' else None)):
                records = await IdentityCenterFacade(object()).get_instances(REGION)
            assert len(records) == 1
            assert len(records[0]['assignments']) == 1
            assert records[0]['assignments'][0]['principal_id'] == GROUP
            assert records[0]['assignments'][0]['identity_resolution_status'] == 'unknown'
            assert records[0]['assignments'][0]['group_members_complete'] is False
            assert any(issue['reason_code'] == 'IdentityStoreClientUnavailable'
                       for issue in ctx.collection_issues)
        finally:
            await ctx.aclose()
    asyncio.run(scenario())
