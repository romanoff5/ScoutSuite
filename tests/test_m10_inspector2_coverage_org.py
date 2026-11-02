"""M10-E: account inventory completeness, independent statistics and delegated-admin tests.

No live credentials, AWS HTTP requests or customer data.
"""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.output.result_encoder import ScoutResultEncoder
from ScoutSuite.providers.aws.facade.inspector2 import Inspector2Facade, PAGE_SIZE
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.inspector2.base import Inspector2


ACCOUNT = '000000000000'
MEMBER_A = '111111111111'
MEMBER_B = '222222222222'
REGION = 'eu-central-1'
ROOT = Path(__file__).resolve().parents[1]
FILTER = {'accountId': [{'comparison': 'EQUALS', 'value': ACCOUNT}]}


def sdk():
    return boto3.client('inspector2', region_name=REGION,
                        aws_access_key_id='synthetic', aws_secret_access_key='synthetic')


def row(index):
    return {'resourceType': 'AWS_EC2_INSTANCE',
            'resourceId': 'i-' + str(index).zfill(17),
            'accountId': ACCOUNT, 'scanType': 'PACKAGE',
            'scanStatus': {'statusCode': 'ACTIVE', 'reason': 'SUCCESSFUL'}}


def status(status):
    return {'status': status, 'errorCode': 'ALREADY_ENABLED',
            'errorMessage': 'SYNTHETIC_SECRETS_NEVER_LOGGED'}


def member_account(account, state='ENABLED'):
    return {'accountId': account, 'state': status(state),
            'resourceState': {'ec2': status('ENABLED'), 'ecr': status('ENABLED')}}


def run(scenario):
    return asyncio.run(scenario())


def test_listcoverage_retrieves_more_than_500_items_and_reports_complete():
    async def scenario():
        client = Mock()
        client.list_coverage.side_effect = [
            {'coveredResources': [row(i) for i in range(0, 200)], 'nextToken': 'a'},
            {'coveredResources': [row(i) for i in range(200, 400)], 'nextToken': 'b'},
            {'coveredResources': [row(i) for i in range(400, 600)], 'nextToken': 'c'},
            {'coveredResources': [row(i) for i in range(600, 650)]},
        ]
        with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
            facade = Inspector2Facade(object(), ACCOUNT)
            records = await facade.get_coverage(REGION)
        assert len(records) == 650
        assert records.complete
        assert records.pages == 4
        assert facade.coverage_collections[REGION]['status'] == 'complete'
        assert client.list_coverage.call_count == 4
        assert all(call.kwargs['maxResults'] == 200 for call in client.list_coverage.call_args_list)
        assert all(call.kwargs['filterCriteria'] == FILTER for call in client.list_coverage.call_args_list)
        assert records[0]['resource_id'] == 'i-00000000000000000'
        assert records[-1]['resource_id'] == 'i-00000000000000649'
    run(scenario)


def test_safety_cap_and_repeated_token_explicitly_incomplete():
    async def scenario():
        client = Mock()
        client.list_coverage.side_effect = [
            {'coveredResources': [row(i) for i in range(200)], 'nextToken': 'a'},
            {'coveredResources': [row(i) for i in range(200, 400)], 'nextToken': 'b'},
        ]
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client), \
                 patch('ScoutSuite.providers.aws.facade.inspector2.MAX_COVERED_RESOURCES', 250):
                records = await Inspector2Facade(object(), ACCOUNT).get_coverage(REGION)
            assert len(records) == 250
            assert records.status == 'partial' and not records.complete
            assert any(x['reason_code'] == 'CoverageLimit' for x in ctx.collection_issues)
        finally:
            await ctx.aclose()

        client = Mock()
        client.list_coverage.side_effect = [
            {'coveredResources': [row(1)], 'nextToken': 'repeat'},
            {'coveredResources': [row(2)], 'nextToken': 'repeat'},
        ]
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                records = await Inspector2Facade(object(), ACCOUNT).get_coverage(REGION)
            assert len(records) == 2 and not records.complete
            assert any(x['reason_code'] == 'InvalidPaginationToken' for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
    run(scenario)


def test_coverage_statistics_sdk_contract_and_comparison():
    async def scenario():
        client = sdk()
        try:
            with Stubber(client) as stub:
                stub.add_response('list_coverage_statistics',
                                  {'totalCounts': 3, 'countsByGroup': [
                                      {'groupKey': 'ACTIVE', 'count': 2},
                                      {'groupKey': 'INACTIVE', 'count': 1}]},
                                  {'filterCriteria': FILTER, 'groupBy': 'SCAN_STATUS_CODE'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    stats = await Inspector2Facade(object(), ACCOUNT).get_coverage_statistics(REGION)
                stub.assert_no_pending_responses()
            assert stats['status'] == 'complete'
            assert stats['total_count'] == 3
            assert stats['by_status'] == {'ACTIVE': 2, 'INACTIVE': 1}
        finally:
            client.close()
    run(scenario)


def test_independent_report_discloses_mismatch_and_empty_statistics():
    async def scenario():
        upstream = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]),
            inspector2=SimpleNamespace(
                get_accounts=AsyncMock(return_value=[]),
                get_coverage=AsyncMock(return_value=[
                    {'account_id': ACCOUNT, 'resource_type': 'AWS_EC2_INSTANCE',
                     'resource_id': 'i-00000000000000001', 'scan_type': 'PACKAGE',
                     'scan_status': 'ACTIVE'}]),
                get_coverage_statistics=AsyncMock(return_value={
                    'status': 'complete', 'total_count': 2,
                    'by_status': {'ACTIVE': 2}}),
                get_organization_context=AsyncMock(return_value={
                    'role': 'member_or_management', 'status': 'not_authorized_as_admin',
                    'members': {}, 'members_count': 0,
                    'organization_roster_verified': False}),
                coverage_collections={REGION: {'status': 'complete', 'complete': True, 'pages': 1}}))
        ctx = RunContext('aws').setup()
        try:
            data = Inspector2(upstream)
            await data.fetch_all(regions=[REGION])
            report = data['regions'][REGION]['coverage_summary']
            assert report['status'] == 'partial'
            assert report['collected_records'] == 1
            assert report['inspector_reported_records'] == 2
            assert report['aws_resource_inventory_compared'] is False
            assert any(x['reason_code'] == 'CoverageCountMismatch' for x in ctx.collection_issues)
            assert ScoutResultEncoder.to_dict(data)['regions'][REGION]['coverage_summary'] == report
        finally:
            await ctx.aclose()
    run(scenario)


def test_admin_members_config_status_stubber_and_no_customer_payload():
    async def scenario():
        client = sdk()
        try:
            with Stubber(client) as stub:
                stub.add_response('get_delegated_admin_account',
                                  {'delegatedAdmin': {'accountId': ACCOUNT,
                                                      'relationshipStatus': 'ENABLED'}}, {})
                stub.add_response('list_members', {'members': [
                    {'accountId': MEMBER_A, 'relationshipStatus': 'ENABLED',
                     'delegatedAdminAccountId': ACCOUNT},
                    {'accountId': MEMBER_B, 'relationshipStatus': 'DISABLED',
                     'delegatedAdminAccountId': ACCOUNT}]},
                    {'maxResults': 50, 'onlyAssociated': False})
                stub.add_response('describe_organization_configuration',
                                  {'autoEnable': {'ec2': True, 'ecr': False,
                                                  'lambda': True},
                                   'maxAccountLimitReached': False}, {})
                stub.add_response('batch_get_account_status',
                                  {'accounts': [member_account(MEMBER_A),
                                                member_account(MEMBER_B, 'SUSPENDED')],
                                   'failedAccounts': []},
                                  {'accountIds': [MEMBER_A, MEMBER_B]})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    result = await Inspector2Facade(object(), ACCOUNT).get_organization_context(REGION)
                stub.assert_no_pending_responses()
            assert result['status'] == 'complete'
            assert result['role'] == 'delegated_admin'
            assert result['members_count'] == 2 and result['members_complete']
            assert result['configuration_complete'] and result['member_statuses_complete']
            assert result['auto_enable']['ec2'] is True
            assert result['auto_enable']['ecr'] is False
            assert result['auto_enable']['codeRepository'] is None
            assert result['organization_roster_verified'] is False
            assert result['members'][MEMBER_A]['account_status'] == 'ENABLED'
            assert result['members'][MEMBER_B]['account_status'] == 'SUSPENDED'
            assert result['members'][MEMBER_B]['inactive'] is True
            assert 'SYNTHETIC_SECRETS_NEVER_LOGGED' not in str(result)
        finally:
            client.close()
    run(scenario)


def test_member_account_has_no_admin_enumeration_privileges():
    async def scenario():
        client = sdk()
        try:
            with Stubber(client) as stub:
                stub.add_response('get_delegated_admin_account',
                                  {'delegatedAdmin': {'accountId': MEMBER_A,
                                                      'relationshipStatus': 'ENABLED'}}, {})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    result = await Inspector2Facade(object(), ACCOUNT).get_organization_context(REGION)
                stub.assert_no_pending_responses()
            assert result['role'] == 'member_or_management'
            assert result['status'] == 'not_authorized_as_admin'
            assert result['members'] == {}
        finally:
            client.close()
    run(scenario)


def test_denied_and_malformed_organization_requests_fail_closed():
    async def scenario():
        client = Mock()
        client.get_delegated_admin_account.side_effect = Exception('no access')
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                result = await Inspector2Facade(object(), ACCOUNT).get_organization_context(REGION)
            assert result['status'] == 'failed'
            assert ctx.collection_issues
            client.list_members.assert_not_called()
        finally:
            await ctx.aclose()
        client = Mock()
        client.get_delegated_admin_account.return_value = {
            'delegatedAdmin': {'accountId': ACCOUNT, 'relationshipStatus': 'ENABLED'}}
        client.list_members.return_value = {'members': [
            {'accountId': MEMBER_A, 'relationshipStatus': 'ENABLED'},
            {'accountId': MEMBER_A, 'relationshipStatus': 'ENABLED'}]}
        client.describe_organization_configuration.return_value = {
            'autoEnable': {'ec2': True, 'ecr': True}}
        client.batch_get_account_status.return_value = {
            'accounts': [member_account(MEMBER_A)], 'failedAccounts': []}
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                result = await Inspector2Facade(object(), ACCOUNT).get_organization_context(REGION)
            assert result['status'] == 'partial'
            assert not result['members_complete']
            assert any(x['reason_code'] == 'InvalidOrDuplicateMember' for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
    run(scenario)


def test_member_account_rule_displays_real_account_ids_and_unknown(tmp_path):
    chosen = {'about': 'M10-E synthetic member rule', 'rules': {
        'inspector2-member-account-disabled.json': [{'enabled': True, 'level': 'warning'}]}}
    path = tmp_path / 'inspector-rule.json'
    path.write_text(json.dumps(chosen), encoding='utf-8')
    members = {
        MEMBER_A: {'account_status': 'ENABLED', 'inactive': False},
        MEMBER_B: {'account_status': 'DISABLED', 'inactive': True},
        '333333333333': {'account_status': 'UNKNOWN', 'inactive': False},
    }
    provider = SimpleNamespace(
        services={'inspector2': {'regions': {REGION: {
            'organization': {'members': members}}}}},
        service_list=['inspector2'])
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(path))).run(provider)
        finding = provider.services['inspector2']['findings']['inspector2-member-account-disabled']
        assert finding['flagged_items'] == 1
        assert finding['assessment_status'] == 'incomplete'
        assert finding['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
    finally:
        ctx.cleanup()


def test_org_template_uses_escaped_identifiers_and_no_duplicate_facade():
    html = (ROOT / 'ScoutSuite/output/data/html/partials/aws/'
            'services.inspector2.regions.id.organization.members.html').read_text(encoding='utf-8')
    assert '{{account_id}}' in html and '{{account_status}}' in html
    assert '{{{' not in html and 'onclick=' not in html and 'javascript:' not in html
    facade = (ROOT / 'ScoutSuite/providers/aws/facade/inspector2.py').read_text(encoding='utf-8')
    assert 'Inspector2OrganizationMixin' in facade
    assert 'class Inspector2Facade(' in facade
    definitions = {path.name for path in (
        ROOT / 'ScoutSuite/providers/aws/rules/findings').glob('inspector2-*.json')}
    assert definitions == {
        'inspector2-account-disabled.json',
        'inspector2-scan-type-inactive.json',
        'inspector2-coverage-inactive.json',
        'inspector2-member-account-disabled.json'}
