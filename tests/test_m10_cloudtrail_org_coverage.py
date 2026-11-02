"""M10-R CloudTrail org-wide coverage; strictly offline and fail-closed."""
import asyncio
import json
from pathlib import Path
from unittest.mock import Mock, patch

import boto3
from botocore.stub import Stubber

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.organizations import OrganizationsFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.organization_cloudtrail_coverage import (
    reconcile_cloudtrail_organization_coverage,
    _management_events_complete,
)


MASTER = '111111111111'
MEMBER = '222222222222'
REGION = 'eu-central-1'
HOME = 'us-east-1'
ARN = 'arn:aws:cloudtrail:us-east-1:111111111111:trail/org'


def fixture():
    return {
        'organizations': {
            'accounts': {
                MASTER: {'id': MASTER, 'name': 'Management', 'state': 'ACTIVE',
                         'email': 'admin@example.invalid'},
                MEMBER: {'id': MEMBER, 'name': 'Production', 'state': 'ACTIVE',
                         'email': 'prod@example.invalid'},
            },
            'organizations': {'o-1': {'id': 'o-1', 'name': 'o-1'}},
            'collection': {'accounts': 'complete', 'organization': 'complete'},
            'account_regions': {
                MASTER: {'collection_status': 'complete',
                         'regions': {HOME: 'ENABLED_BY_DEFAULT', REGION: 'ENABLED'}},
                MEMBER: {'collection_status': 'complete',
                         'regions': {HOME: 'ENABLED_BY_DEFAULT', REGION: 'ENABLED'}},
            },
        },
        'cloudtrail': {'regions': {
            HOME: {'trails_inventory_status': 'complete', 'trails': {'org': {
                'arn': ARN, 'home_region': HOME, 'IsOrganizationTrail': True,
                'is_organization_trail': True, 'IsMultiRegionTrail': True,
                'IsLogging': True, 'selector_collection_status': 'success',
                'EventSelectors': [{
                    'IncludeManagementEvents': True, 'ReadWriteType': 'All'
                }],
                'AdvancedEventSelectors': [], 'LatestDeliveryError': '',
            }}},
            REGION: {'trails_inventory_status': 'complete', 'trails': {
                'copy': {'scout_link': 'services.cloudtrail.regions.us-east-1.trails.org',
                         'arn': ARN, 'is_organization_trail': True}
            }},
        }},
    }


def test_all_accounts_configured_does_not_claim_delivered_events():
    resources = fixture()
    summary = reconcile_cloudtrail_organization_coverage(
        resources, ['organizations', 'cloudtrail'], MASTER)
    assert summary['active_accounts'] == 2
    assert summary['known_enabled_regions'] == 4
    assert summary['configured_regions'] == 4
    assert summary['gap_regions'] == 0
    assert summary['all_accounts_configured'] is True
    assert summary['per_account_delivery_verified'] is False
    assert resources['organizations']['organizations']['o-1'][
        'm10r_cloudtrail_summary']['active_accounts'] == 2
    for account in resources['organizations']['accounts'].values():
        assert account['m10r_cloudtrail_coverage']['state'] == 'configured'
        assert not account['m10r_cloudtrail_config_gap']
        assert not account['m10r_cloudtrail_coverage']['delivery_verified']
        assert account['m10r_cloudtrail_coverage']['regions'][REGION][
            'trail_arns'] == [ARN]
        assert account['email'].endswith('@example.invalid')


def test_single_region_and_opt_in_home_region_fail_closed():
    data = fixture()
    trail = data['cloudtrail']['regions'][HOME]['trails']['org']
    trail['IsMultiRegionTrail'] = False
    result = reconcile_cloudtrail_organization_coverage(
        data, ['organizations', 'cloudtrail'], MASTER)
    assert result['gap_regions'] == 2
    assert data['organizations']['accounts'][MEMBER]['m10r_cloudtrail_config_gap']
    assert data['organizations']['accounts'][MEMBER]['m10r_cloudtrail_coverage'][
        'regions'][REGION]['configuration_state'] == 'gap'

    data = fixture()
    data['organizations']['account_regions'][MEMBER]['regions'][HOME] = 'DISABLED'
    data['cloudtrail']['regions'][HOME]['trails']['org']['home_region'] = HOME
    result = reconcile_cloudtrail_organization_coverage(
        data, ['organizations', 'cloudtrail'], MASTER)
    assert result['gap_regions'] == 1
    rows = data['organizations']['accounts'][MEMBER]['m10r_cloudtrail_coverage']['regions']
    assert rows[HOME]['configuration_state'] == 'not_applicable'
    assert rows[REGION]['configuration_state'] == 'gap'


def test_read_write_selectors_must_be_unconditional():
    data = fixture()
    trail = data['cloudtrail']['regions'][HOME]['trails']['org']
    trail['EventSelectors'] = [{'IncludeManagementEvents': True,
                                'ReadWriteType': 'ReadOnly'}]
    assert _management_events_complete(trail) is False
    summary = reconcile_cloudtrail_organization_coverage(
        data, ['organizations', 'cloudtrail'], MASTER)
    assert summary['gap_regions'] == 4

    trail['EventSelectors'] = []
    trail['AdvancedEventSelectors'] = [{
        'FieldSelectors': [{'Field': 'eventCategory', 'Equals': ['Management']},
                           {'Field': 'readOnly', 'Equals': ['false']}]
    }]
    assert _management_events_complete(trail) is False
    trail['AdvancedEventSelectors'] = [{
        'FieldSelectors': [{'Field': 'eventCategory', 'Equals': ['Management']}]
    }]
    assert _management_events_complete(trail) is True


def test_denied_trails_and_region_collection_never_create_false_findings():
    data = fixture()
    data['organizations']['account_regions'][MEMBER]['collection_status'] = 'denied'
    data['organizations']['account_regions'][MEMBER]['regions'] = {}
    data['cloudtrail']['regions'][HOME]['trails']['org']['selector_collection_status'] = 'failed'
    summary = reconcile_cloudtrail_organization_coverage(
        data, ['organizations', 'cloudtrail'], MASTER)
    assert summary['accounts_unknown'] == 2
    assert summary['gap_regions'] == 0
    assert summary['all_accounts_configured'] is False
    for a in data['organizations']['accounts'].values():
        assert not a['m10r_cloudtrail_config_gap']

    data = fixture()
    data['cloudtrail']['regions'][HOME]['trails'] = {}
    data['cloudtrail']['regions'][REGION]['trails_inventory_status'] = 'denied'
    summary = reconcile_cloudtrail_organization_coverage(
        data, ['organizations', 'cloudtrail'], MASTER)
    assert summary['gap_regions'] == 0
    assert summary['unknown_regions'] == 4


def test_suspended_account_is_not_active_and_no_separate_sdk_calls():
    data = fixture()
    data['organizations']['accounts'][MEMBER]['state'] = 'SUSPENDED'
    result = reconcile_cloudtrail_organization_coverage(
        data, ['organizations', 'cloudtrail'], MASTER)
    assert result['active_accounts'] == 1
    assert data['organizations']['accounts'][MEMBER]['m10r_cloudtrail_coverage'][
        'state'] == 'not_applicable'
    sdk = Mock()
    data['cloudtrail']['client'] = sdk
    assert reconcile_cloudtrail_organization_coverage(data, ['cloudtrail'], MASTER) is None
    sdk.assert_not_called()


def test_account_management_region_inventory_uses_correct_self_scope_and_pagination():
    async def scenario():
        client = boto3.client('account', region_name='us-east-1',
                              aws_access_key_id='test', aws_secret_access_key='test')
        context = RunContext('aws').setup()
        try:
            with Stubber(client) as stub:
                stub.add_response('list_regions', {
                    'Regions': [], 'NextToken': 'next'},
                    {'MaxResults': 50})
                stub.add_response('list_regions', {'Regions': [
                    {'RegionName': HOME, 'RegionOptStatus': 'ENABLED_BY_DEFAULT'},
                    {'RegionName': REGION, 'RegionOptStatus': 'ENABLED'}]},
                    {'MaxResults': 50, 'NextToken': 'next'})
                facade = OrganizationsFacade(object(), 'aws', MASTER)
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    rows = await facade.get_account_region_inventory(
                        {MASTER: {'state': 'ACTIVE'}}, MASTER)
                stub.assert_no_pending_responses()
            assert rows[MASTER] == {'collection_status': 'complete', 'regions': {
                HOME: 'ENABLED_BY_DEFAULT', REGION: 'ENABLED'}}
            assert not context.collection_issues
        finally:
            await context.aclose()
            client.close()
    asyncio.run(scenario())


def test_denied_account_regions_remain_unknown_not_gap():
    async def scenario():
        client = boto3.client('account', region_name='us-east-1',
                              aws_access_key_id='test', aws_secret_access_key='test')
        ctx = RunContext('aws').setup()
        try:
            with Stubber(client) as stub:
                stub.add_client_error(
                    'list_regions', service_error_code='AccessDeniedException',
                    http_status_code=400,
                    expected_params={'MaxResults': 50, 'AccountId': MEMBER})
                facade = OrganizationsFacade(object(), 'aws', MASTER)
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    found = await facade.get_account_region_inventory(
                        {MEMBER: {'state': 'ACTIVE'}}, MASTER)
                stub.assert_no_pending_responses()
            assert found[MEMBER]['collection_status'] == 'denied'
            assert not found[MEMBER]['regions']
            assert any(row['status'] == 'denied' for row in ctx.collection_issues)
        finally:
            await ctx.aclose()
            client.close()
    asyncio.run(scenario())


def test_default_reporting_rule_and_safe_escaped_evidence_template():
    root = Path(__file__).resolve().parents[1]
    base = root / 'ScoutSuite/providers/aws/rules'
    rules = json.loads((base / 'rulesets/default.json').read_text(encoding='utf-8'))
    assert rules['rules']['m10r-org-cloudtrail-config-gap.json'][0]['enabled'] is True
    rule = json.loads((base / 'findings/m10r-org-cloudtrail-config-gap.json').read_text())
    assert rule['path'] == 'organizations.accounts.id'
    assert rule['conditions'][-1][0] == 'm10r_cloudtrail_config_gap'
    detail = (root / 'ScoutSuite/output/data/html/partials/aws/'
              'services.organizations.accounts.id.html').read_text(encoding='utf-8')
    assert '{{m10r_cloudtrail_coverage.state}}' in detail
    assert '{{{m10r_' not in detail


def test_restricted_region_scan_and_missing_owner_region_data_cannot_prove_complete():
    data = fixture()
    del data['cloudtrail']['regions'][REGION]
    summary = reconcile_cloudtrail_organization_coverage(
        data, ['organizations', 'cloudtrail'], MASTER)
    assert summary['cloudtrail_inventory_complete'] is False
    assert summary['gap_regions'] == 0
    assert summary['unknown_regions'] == 4
    assert summary['all_accounts_configured'] is False
    data = fixture()
    data['organizations']['account_regions'][MASTER] = {
        'collection_status': 'denied', 'regions': {}}
    summary = reconcile_cloudtrail_organization_coverage(
        data, ['organizations', 'cloudtrail'], MASTER)
    assert summary['cloudtrail_inventory_complete'] is False
    assert summary['all_accounts_configured'] is False


def test_account_regions_page_loop_reports_partial_without_inventing_clean_state():
    async def scenario():
        client = Mock()
        client.list_regions.side_effect = [
            {'Regions': [], 'NextToken': 'same'},
            {'Regions': [], 'NextToken': 'same'},
        ]
        ctx = RunContext('aws').setup()
        try:
            facade = OrganizationsFacade(object(), 'aws', MASTER)
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                records = await facade.get_account_region_inventory(
                    {MASTER: {'state': 'ACTIVE'}}, MASTER)
            assert records[MASTER]['collection_status'] == 'partial'
            assert records[MASTER]['regions'] == {}
            assert client.list_regions.call_count == 2
            assert any(x['reason_code'].startswith('AccountListRegionsInvalidToken')
                       for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
    asyncio.run(scenario())
