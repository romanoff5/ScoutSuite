import asyncio
import functools

from botocore.exceptions import ClientError

from ScoutSuite.core.console import print_exception, print_warning
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import get_non_provider_id, run_concurrently, get_and_set_concurrently


class IAMFacade(AWSBaseFacade):
    async def get_security_alternate_contact_status(self, partition='aws'):
        """Read-only account:GetAlternateContact, never store contact PII."""
        from ScoutSuite.core.run_context import get_current_run_context
        home = {'aws': 'us-east-1', 'aws-us-gov': 'us-gov-west-1',
                'aws-cn': 'cn-north-1'}.get(partition)
        if home is None:
            return 'unknown'
        client = AWSFacadeUtils.get_client('account', self.session, home)
        if client is None:
            return 'unknown'
        try:
            response = await run_concurrently(
                lambda: client.get_alternate_contact(AlternateContactType='SECURITY'))
            contact = response.get('AlternateContact') if isinstance(response, dict) else None
            if not isinstance(contact, dict):
                return 'unknown'
            address = contact.get('EmailAddress')
            return 'configured' if isinstance(address, str) and address.strip() else 'unknown'
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code in ('ResourceNotFoundException', 'ResourceNotFound'):
                return 'missing'
            AWSFacadeUtils.record_listing_failure('iam', exc, 'GetSecurityAlternateContact')
        except Exception as exc:
            AWSFacadeUtils.record_listing_failure('iam', exc, 'GetSecurityAlternateContact')
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue('partial', 'iam', 'SecurityContactUnverified')
        return 'unknown'

    async def get_credential_reports(self):
        client = AWSFacadeUtils.get_client('iam', self.session)
        # When no credential report exists, we first need to initiate the creation of a new report by calling
        # client.generate_credential_report and then check for COMPLETE status before trying to download it:
        report_generated, n_attempts = False, 3
        try:
            while not report_generated and n_attempts > 0:
                response = await run_concurrently(client.generate_credential_report)
                if response['State'] == 'COMPLETE':
                    report_generated = True
                else:
                    n_attempts -= 1
                    await asyncio.sleep(0.1)  # Wait for 100ms before doing a new attempt.
        except Exception as e:
            print_exception(f'Failed to generate credential report: {e}')
            return []
        if not report_generated and n_attempts == 0:
            print_exception(f'Failed to complete credential report generation in {n_attempts} attempts')
            return []

        try:
            report = await run_concurrently(lambda: client.get_credential_report()['Content'])

            # The report is a CSV string. The first row contains the name of each column. The next rows
            # each represent an individual account. This algorithm provides a simple initial parsing.
            lines = report.splitlines()
            keys = lines[0].decode('utf-8').split(',')

            credential_reports = []
            for line in lines[1:]:
                credential_report = {}
                values = line.decode('utf-8').split(',')
                for key, value in zip(keys, values):
                    credential_report[key] = value

                credential_reports.append(credential_report)

            return credential_reports
        except Exception as e:
            if 'ReportNotPresent' in e:
                print_warning(f'Failed to download credential report: {e}')
            else:
                print_exception(f'Failed to download credential report: {e}')
            return []

    async def get_groups(self):
        groups = await AWSFacadeUtils.get_all_pages('iam', None, self.session, 'list_groups', 'Groups')
        await get_and_set_concurrently(
            [self._get_and_set_group_users,
             functools.partial(self._get_and_set_inline_policies, iam_resource_type='group'),
             functools.partial(self._get_and_set_p4b2_managed_attachments,
                               entity_type='group')], groups)
        return groups

    async def get_policies(self):
        policies = await AWSFacadeUtils.get_all_pages(
            'iam', None, self.session, 'list_policies', 'Policies', OnlyAttached=True)
        await get_and_set_concurrently([self._get_and_set_policy_details], policies)
        return policies

    async def _get_and_set_policy_details(self, policy):
        client = AWSFacadeUtils.get_client('iam', self.session)
        try:
            policy_version = await run_concurrently(
                lambda: client.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId']))
            policy['PolicyDocument'] = policy_version['PolicyVersion']['Document']
        except Exception as e:
            print_exception(f'Failed to get policy version: {e}')
        else:
            policy['attached_to'] = {}
            attached_entities = await AWSFacadeUtils.get_multiple_entities_from_all_pages(
                'iam', None, self.session, 'list_entities_for_policy', ['PolicyGroups', 'PolicyRoles', 'PolicyUsers'],
                PolicyArn=policy['Arn'])

            for entity_type in attached_entities:
                resource_type = entity_type.replace('Policy', '').lower()
                if len(attached_entities[entity_type]):
                    policy['attached_to'][resource_type] = []

                for entity in attached_entities[entity_type]:
                    name_field = entity_type.replace('Policy', '')[
                                 :-1] + 'Name'
                    resource_name = entity[name_field]
                    id_field = entity_type.replace('Policy', '')[:-1] + 'Id'
                    resource_id = entity[id_field]
                    policy['attached_to'][resource_type].append(
                        {'name': resource_name, 'id': resource_id})

    async def get_users(self):
        users = await AWSFacadeUtils.get_all_pages('iam', None, self.session, 'list_users', 'Users')
        await get_and_set_concurrently(
            [functools.partial(self._get_and_set_inline_policies, iam_resource_type='user'),
             self._get_and_set_p4b2_user_groups,
             self._get_and_set_p4b2_user_details,
             functools.partial(self._get_and_set_p4b2_managed_attachments,
                               entity_type='user'),
             self._get_and_set_user_tags,
             self._get_and_set_user_login_profile,
             self._get_and_set_user_access_keys,
             self._get_and_set_user_mfa_devices],
            users)
        return users


    async def _get_and_set_p4b2_user_groups(self, user):
        """Exact, bounded group membership. Never infer empty on API failure."""
        user['p4b2_membership_status'] = 'unknown'
        user['groups'] = []
        client = AWSFacadeUtils.get_client('iam', self.session)
        if client is None:
            return
        try:
            def collect():
                result = []
                pages = client.get_paginator('list_groups_for_user').paginate(
                    UserName=user['UserName'])
                for idx, page in enumerate(pages):
                    if idx >= 25:
                        raise ValueError('P4B2GroupMembershipPageCap')
                    rows = page.get('Groups') if isinstance(page, dict) else None
                    if not isinstance(rows, list):
                        raise ValueError('P4B2GroupMembershipMalformed')
                    for row in rows:
                        name = row.get('GroupName') if isinstance(row, dict) else None
                        if not isinstance(name, str) or not name:
                            raise ValueError('P4B2GroupMembershipInvalidName')
                        result.append(name)
                        if len(result) > 1500:
                            raise ValueError('P4B2GroupMembershipItemCap')
                return sorted(set(result))
            user['groups'] = await run_concurrently(collect)
            user['p4b2_membership_status'] = 'complete'
        except Exception as exc:
            AWSFacadeUtils.record_listing_failure('iam', exc, 'P4B2ListGroupsForUser')

    async def _get_and_set_p4b2_user_details(self, user):
        """Read user's boundary; ListUsers is not authoritative for this field."""
        user['p4b2_boundary_status'] = 'unknown'
        user['p4b2_boundary'] = None
        client = AWSFacadeUtils.get_client('iam', self.session)
        if client is None:
            return
        try:
            response = await run_concurrently(
                lambda: client.get_user(UserName=user['UserName']))
            item = response.get('User') if isinstance(response, dict) else None
            if not isinstance(item, dict) or item.get('Arn') != user.get('Arn'):
                raise ValueError('P4B2GetUserMalformed')
            boundary = item.get('PermissionsBoundary')
            if boundary is not None and (
                    not isinstance(boundary, dict) or
                    not isinstance(boundary.get('PermissionsBoundaryArn'), str)):
                raise ValueError('P4B2GetUserBoundaryMalformed')
            user['p4b2_boundary'] = boundary
            user['p4b2_boundary_status'] = 'complete'
        except Exception as exc:
            AWSFacadeUtils.record_listing_failure('iam', exc, 'P4B2GetUser')

    async def _get_and_set_p4b2_managed_attachments(self, entity, entity_type):
        """Explicit role-independent IAM principal attachment census."""
        entity['p4b2_managed_status'] = 'unknown'
        entity['p4b2_managed_arns'] = []
        if entity_type not in ('user', 'group'):
            return
        client = AWSFacadeUtils.get_client('iam', self.session)
        if client is None:
            return
        name_key = 'UserName' if entity_type == 'user' else 'GroupName'
        op = 'list_attached_' + entity_type + '_policies'
        try:
            def collect():
                arns = set()
                pages = client.get_paginator(op).paginate(**{
                    name_key: entity[name_key]})
                for index, page in enumerate(pages):
                    if index >= 20:
                        raise ValueError('P4B2ManagedAttachmentPageCap')
                    rows = page.get('AttachedPolicies') if isinstance(page, dict) else None
                    if not isinstance(rows, list):
                        raise ValueError('P4B2ManagedAttachmentMalformed')
                    for row in rows:
                        arn = row.get('PolicyArn') if isinstance(row, dict) else None
                        if not isinstance(arn, str) or ':policy/' not in arn:
                            raise ValueError('P4B2ManagedAttachmentInvalidArn')
                        arns.add(arn)
                        if len(arns) > 500:
                            raise ValueError('P4B2ManagedAttachmentItemCap')
                return sorted(arns)
            entity['p4b2_managed_arns'] = await run_concurrently(collect)
            entity['p4b2_managed_status'] = 'complete'
        except Exception as exc:
            AWSFacadeUtils.record_listing_failure('iam', exc,
                                                   'P4B2ListAttachedPolicies')

    async def validate_p4b2_role_trusts(self, roles, partition='aws'):
        """Advisory Access Analyzer ValidatePolicy, never effective-authorization proof.

        No raw analyzer finding details or role trust policies are persisted in
        result metadata; the trust document is sent only to AWS validation API.
        """
        import json
        regions = {'aws': 'us-east-1', 'aws-us-gov': 'us-gov-west-1',
                   'aws-cn': 'cn-north-1'}
        region = regions.get(partition)
        if region is None or not isinstance(roles, dict):
            return {}
        targets = [(arn, role) for arn, role in sorted(roles.items())
                   if isinstance(role, dict) and role.get('p4b2_oidc_claims_status')
                   not in (None, 'not_applicable')]
        if not targets:
            return {}
        client = AWSFacadeUtils.get_client('accessanalyzer', self.session, region)
        results = {arn: {'status': 'unknown', 'issue_codes': []}
                   for arn, _ in targets}
        if client is None:
            return results
        for arn, role in targets[:25]:
            try:
                wrapper = role.get('assume_role_policy')
                doc = wrapper.get('PolicyDocument') if isinstance(wrapper, dict) else None
                if not isinstance(doc, dict):
                    continue
                document = json.dumps(doc, sort_keys=True)
                def validate():
                    response = client.validate_policy(
                        policyDocument=document, policyType='RESOURCE_POLICY',
                        validatePolicyResourceType='AWS::IAM::AssumeRolePolicyDocument',
                        maxResults=100)
                    findings = []
                    for index in range(5):
                        if not isinstance(response, dict) or not isinstance(
                                response.get('findings'), list):
                            raise ValueError('P4B2ValidatePolicyMalformed')
                        findings.extend(response['findings'])
                        token = response.get('nextToken')
                        if not token:
                            break
                        if index == 4:
                            raise ValueError('P4B2ValidatePolicyPageCap')
                        response = client.validate_policy(
                            policyDocument=document, policyType='RESOURCE_POLICY',
                            validatePolicyResourceType='AWS::IAM::AssumeRolePolicyDocument',
                            maxResults=100, nextToken=token)
                    return findings
                findings = await run_concurrently(validate)
                issue_codes = sorted({
                    x['issueCode'] for x in findings
                    if isinstance(x, dict) and x.get('findingType')
                    in ('ERROR', 'SECURITY_WARNING')
                    and isinstance(x.get('issueCode'), str)})[:12]
                types = {x.get('findingType') for x in findings
                         if isinstance(x, dict)}
                status = ('error' if 'ERROR' in types else
                          'security_warning' if 'SECURITY_WARNING' in types else
                          'validated')
                results[arn] = {'status': status, 'issue_codes': issue_codes}
            except Exception as exc:
                AWSFacadeUtils.record_listing_failure('iam', exc,
                                                       'P4B2AccessAnalyzerValidatePolicy')
        return results

    async def _get_and_set_user_login_profile(self, user: {}):
        client = AWSFacadeUtils.get_client('iam', self.session)
        try:
            user['LoginProfile'] = await run_concurrently(
                lambda: client.get_login_profile(UserName=user['UserName'])['LoginProfile'])
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                #  If the user has not been assigned a password, the operation returns a 404 (NoSuchEntity ) error.
                pass
            else:
                print_exception(f'Failed to get login profile: {e}')
        except Exception as e:
            print_exception(f'Failed to get login profile: {e}')

    async def _get_and_set_user_groups(self, user: {}):
        groups = await AWSFacadeUtils.get_all_pages(
            'iam', None, self.session, 'list_groups_for_user', 'Groups', UserName=user['UserName'])
        user['groups'] = [group['GroupName'] for group in groups]

    async def _get_and_set_user_tags(self, user: {}):
        client = AWSFacadeUtils.get_client('iam', self.session)
        user['tags'] = client.list_user_tags(UserName=user['UserName'])

    async def get_roles(self):
        roles = await AWSFacadeUtils.get_all_pages('iam', None, self.session, 'list_roles', 'Roles')
        for role in roles:
            role['instances_count'] = 'N/A'
            # Get trust relationship
            role['assume_role_policy'] = {}
            role['assume_role_policy']['PolicyDocument'] = role.pop(
                'AssumeRolePolicyDocument')
        # P4-B needs explicit per-role completeness. ListRoles omits the
        # permissions boundary and policy attachment inventory; denied reads
        # must not silently become "no boundary" or "no managed policies".
        await get_and_set_concurrently(
            [functools.partial(self._get_and_set_inline_policies, iam_resource_type='role'),
             self._get_and_set_role_profiles,
             self._get_and_set_role_tags,
             self._get_and_set_p4b_role_details,
             self._get_and_set_p4b_attached_policies], roles)

        return roles


    async def _get_and_set_p4b_role_details(self, role):
        """Read GetRole for boundary (not returned by ListRoles); fail closed."""
        role['role_boundary_collection_status'] = 'unknown'
        role['permissions_boundary'] = None
        client = AWSFacadeUtils.get_client('iam', self.session)
        if client is None:
            return
        try:
            response = await run_concurrently(
                lambda: client.get_role(RoleName=role['RoleName']))
            details = response.get('Role') if isinstance(response, dict) else None
            if not isinstance(details, dict) or details.get('Arn') != role.get('Arn'):
                raise ValueError('P4BMalformedGetRole')
            boundary = details.get('PermissionsBoundary')
            if boundary is not None and (
                    not isinstance(boundary, dict) or
                    not isinstance(boundary.get('PermissionsBoundaryArn'), str) or
                    not boundary['PermissionsBoundaryArn']):
                raise ValueError('P4BMalformedPermissionsBoundary')
            role['permissions_boundary'] = boundary
            role['role_boundary_collection_status'] = 'complete'
        except Exception as error:
            AWSFacadeUtils.record_listing_failure('iam', error, 'P4BGetRole')

    async def _get_and_set_p4b_attached_policies(self, role):
        """Bounded exact role attachment census; no missing=empty ambiguity."""
        role['attached_managed_policy_collection_status'] = 'unknown'
        role['attached_managed_policy_arns'] = []
        client = AWSFacadeUtils.get_client('iam', self.session)
        if client is None:
            return
        try:
            def fetch():
                result, names = [], set()
                pages = client.get_paginator('list_attached_role_policies').paginate(
                    RoleName=role['RoleName'])
                for index, page in enumerate(pages):
                    if index >= 20:
                        raise ValueError('P4BAttachedPoliciesPageCap')
                    rows = page.get('AttachedPolicies') if isinstance(page, dict) else None
                    if not isinstance(rows, list):
                        raise ValueError('P4BAttachedPoliciesMalformedPage')
                    for item in rows:
                        arn = item.get('PolicyArn') if isinstance(item, dict) else None
                        if not isinstance(arn, str) or ':policy/' not in arn:
                            raise ValueError('P4BAttachedPoliciesMalformedArn')
                        if arn in names:
                            raise ValueError('P4BAttachedPoliciesDuplicateArn')
                        names.add(arn)
                        result.append(arn)
                        if len(result) > 500:
                            raise ValueError('P4BAttachedPoliciesResourceCap')
                return sorted(result)
            policies = await run_concurrently(fetch)
            role['attached_managed_policy_arns'] = policies
            role['attached_managed_policy_collection_status'] = 'complete'
        except Exception as error:
            AWSFacadeUtils.record_listing_failure('iam', error,
                                                   'P4BListAttachedRolePolicies')

    async def _get_and_set_role_tags(self, role: {}):
        client = AWSFacadeUtils.get_client('iam', self.session)
        role['tags'] = client.list_role_tags(RoleName=role['RoleName'])

    async def _get_and_set_role_profiles(self, role: {}):
        profiles = await AWSFacadeUtils.get_all_pages(
            'iam', None, self.session, 'list_instance_profiles_for_role', 'InstanceProfiles',
            RoleName=role['RoleName'])
        role.setdefault('instance_profiles', {})
        for profile in profiles:
            profile_id = profile['InstanceProfileId']
            role['instance_profiles'].setdefault(profile_id, {})
            role['instance_profiles'][profile_id].setdefault(
                'arn', profile['Arn'])
            role['instance_profiles'][profile_id].setdefault(
                'name', profile['InstanceProfileName'])

    async def get_password_policy(self):
        client = AWSFacadeUtils.get_client('iam', self.session)
        try:
            return (await run_concurrently(client.get_account_password_policy))['PasswordPolicy']
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                print_exception(f'Failed to get account password policy: {e}')
            return None

    async def _get_and_set_user_access_keys(self, user: {}):
        client = AWSFacadeUtils.get_client('iam', self.session)
        try:
            user['AccessKeys'] = await run_concurrently(
                lambda: client.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata'])
        except Exception as e:
            print_exception(f'Failed to list access keys: {e}')

    async def _get_and_set_user_mfa_devices(self, user: {}):
        user['MFADevices'] = await self.get_user_mfa_devices(user['UserName'])

    async def get_user_mfa_devices(self, username: str):
        client = AWSFacadeUtils.get_client('iam', self.session)
        try:
            return await run_concurrently(
                lambda: client.list_mfa_devices(UserName=username)['MFADevices'])
        except Exception as e:
            print_exception(f'Failed to list MFA devices for user: {e}')

    async def get_virtual_mfa_devices(self):
        client = AWSFacadeUtils.get_client('iam', self.session)
        try:
            return await run_concurrently(
                lambda: client.list_virtual_mfa_devices().get('VirtualMFADevices', []))
        except Exception as e:
            print_exception(f'Failed to list virtual MFA devices: {e}')
            return []

    async def _get_and_set_group_users(self, group: {}):
        client = AWSFacadeUtils.get_client('iam', self.session)
        try:
            users = await run_concurrently(lambda: client.get_group(GroupName=group['GroupName'])['Users'])
            group['Users'] = [user['UserId'] for user in users]
        except Exception as e:
            print_exception('Failed to get IAM group {}: {}'.format(group['GroupName'], e))

    async def _get_and_set_inline_policies(self, resource, iam_resource_type):
        """Complete IAM inline policy census, with explicit failure status.

        A denied or truncated IAM List*Policies/Get*Policy must never be
        mistaken for a verified empty identity policy set.
        """
        client = AWSFacadeUtils.get_client('iam', self.session)
        resource['inline_policy_collection_status'] = 'unknown'
        resource['inline_policies'] = {}
        if client is None:
            return
        resource_name = resource[iam_resource_type.title() + 'Name']
        args = {iam_resource_type.title() + 'Name': resource_name}
        list_policy_method = getattr(client, 'list_' + iam_resource_type + '_policies')
        get_policy_method = getattr(client, 'get_' + iam_resource_type + '_policy')
        try:
            def enumerate_names():
                names, marker = set(), None
                for _ in range(20):
                    kwargs = dict(args)
                    if marker is not None:
                        kwargs['Marker'] = marker
                    page = list_policy_method(**kwargs)
                    rows = page.get('PolicyNames') if isinstance(page, dict) else None
                    if not isinstance(rows, list) or any(not isinstance(n, str) for n in rows):
                        raise ValueError('IAMInlinePolicyMalformedPage')
                    names.update(rows)
                    if len(names) > 500:
                        raise ValueError('IAMInlinePolicyItemCap')
                    if not page.get('IsTruncated', False):
                        return sorted(names)
                    marker = page.get('Marker')
                    if not isinstance(marker, str) or not marker:
                        raise ValueError('IAMInlinePolicyMissingMarker')
                raise ValueError('IAMInlinePolicyPageCap')
            names = await run_concurrently(enumerate_names)
            for name in names:
                document = await run_concurrently(
                    lambda name=name: get_policy_method(
                        **dict(args, PolicyName=name)))
                if not isinstance(document, dict) or not isinstance(
                        document.get('PolicyDocument'), dict):
                    raise ValueError('IAMInlinePolicyMalformedDocument')
                policy_id = get_non_provider_id(name)
                resource['inline_policies'][policy_id] = {
                    'PolicyDocument': self._normalize_statements(
                        document['PolicyDocument']), 'name': name}
            resource['inline_policies_count'] = len(resource['inline_policies'])
            resource['inline_policy_collection_status'] = 'complete'
        except Exception as exc:
            AWSFacadeUtils.record_listing_failure('iam', exc,
                                                   'IAMInlinePolicyInventory')

    def _normalize_statements(self, policy_document):
        if policy_document:
            if type(policy_document['Statement']) == list:
                pass
                # for statement in policy_document['Statement']:
                #     statement = self._normalize_single_statement(statement)
            elif type(policy_document['Statement']) == dict:
                policy_document['Statement'] = self._normalize_single_statement(policy_document['Statement'])
            else:
                print_exception('Failed to normalize policy document')
        return policy_document

    def _normalize_single_statement(self, statement):
        # Action or NotAction
        action_string = 'Action' if 'Action' in statement else 'NotAction'
        if type(statement[action_string]) != list:
            statement[action_string] = [statement[action_string]]
        # Resource or NotResource
        resource_string = 'Resource' if 'Resource' in statement else 'NotResource'
        if type(statement[resource_string]) != list:
            statement[resource_string] = [statement[resource_string]]
        # Result
        return statement

