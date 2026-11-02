"""M10-C: strict offline Organizations API, governance evidence and report tests."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import (
    classify_organizations_features, classify_organizations_scp)
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.organizations import (
    OrganizationsFacade, HOME_REGIONS, MAX_ACCOUNT_PAGES, PAGE_SIZE)
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.provider import AWSProvider
from ScoutSuite.providers.aws.resources.organizations.base import Organizations


ROOT = Path(__file__).resolve().parents[1]
ORG_ID = 'o-exampleorgid'
ACCOUNT_ID = '111111111111'
ROOT_ID = 'r-exampleid'


def sdk(region='us-east-1'):
    return boto3.client('organizations', region_name=region,
                        aws_access_key_id='test', aws_secret_access_key='test')


def org(feature='ALL'):
    return {'Organization': {
        'Id': ORG_ID,
        'Arn': 'arn:aws:organizations::' + ACCOUNT_ID + ':organization/' + ORG_ID,
        'FeatureSet': feature, 'MasterAccountId': ACCOUNT_ID,
        'MasterAccountEmail': 'secret-management@example.invalid',
    }}


def root(status='ENABLED'):
    return {'Id': ROOT_ID, 'Arn': 'arn:aws:organizations::' + ACCOUNT_ID
            + ':root/' + ORG_ID + '/' + ROOT_ID, 'Name': '<root>',
            'PolicyTypes': [{'Type': 'SERVICE_CONTROL_POLICY', 'Status': status}]}


def account(identifier='222222222222', state='ACTIVE'):
    return {'Id': identifier, 'Name': '<img src=x onerror=alert(1)>',
            'Arn': 'arn:aws:organizations::' + ACCOUNT_ID + ':account/'
            + ORG_ID + '/' + identifier, 'State': state,
            'Status': 'SUSPENDED', 'Email': 'private-account@example.invalid'}


def test_sdk_contract_state_and_endpoints():
    model = get_session().get_service_model('organizations')
    assert 'Organization' in model.operation_model('DescribeOrganization').output_shape.members
    for name, field in [('ListAccounts', 'Accounts'), ('ListRoots', 'Roots')]:
        method = model.operation_model(name)
        assert {'NextToken', 'MaxResults'} <= set(method.input_shape.members)
        assert {field, 'NextToken'} <= set(method.output_shape.members)
    assert 'State' in model.operation_model('ListAccounts').output_shape.members[
        'Accounts'].member.members
    assert HOME_REGIONS == {'aws': 'us-east-1', 'aws-us-gov': 'us-gov-west-1',
                            'aws-cn': 'cn-northwest-1'}


def test_full_stubber_inventory_with_empty_intermediate_page_and_no_pii():
    async def scenario():
        client = sdk()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(client) as stub:
                stub.add_response('describe_organization', org(), {})
                stub.add_response('list_roots', {'Roots': [root()]}, {'MaxResults': PAGE_SIZE})
                # AWS Organizations can return an empty result WITH a next token.
                stub.add_response('list_accounts', {'Accounts': [], 'NextToken': 'continue'},
                                  {'MaxResults': PAGE_SIZE})
                stub.add_response('list_accounts', {'Accounts': [account()]},
                                  {'MaxResults': PAGE_SIZE, 'NextToken': 'continue'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client) as get_client:
                    facade = OrganizationsFacade(object(), 'aws')
                    inventory = await facade.get_organization_inventory()
                    get_client.assert_called_once_with('organizations', facade.session, 'us-east-1')
                stub.assert_no_pending_responses()
            assert inventory['collection'] == {
                'organization': 'complete', 'roots': 'complete', 'accounts': 'complete'}
            resources = Organizations(SimpleNamespace(
                organizations=SimpleNamespace(
                    get_organization_inventory=AsyncMock(return_value=inventory))))
            await resources.fetch_all()
            assert resources['organizations_count'] == 1
            assert resources['roots_count'] == 1
            assert resources['accounts_count'] == 1
            assert resources['organizations'][ORG_ID]['feature_set'] == 'ALL'
            assert resources['roots'][ROOT_ID]['scp_enabled'] is True
            acc = resources['accounts']['222222222222']
            assert acc['state'] == 'ACTIVE'  # Never use retired Status.
            serialized = json.dumps(dict(resources))
            assert 'private-account@example.invalid' not in serialized
            assert 'secret-management@example.invalid' not in serialized
            assert '"Status"' not in serialized
            assert not ctx.collection_issues
        finally:
            await ctx.aclose()
            client.close()
    asyncio.run(scenario())


def test_member_account_retains_summary_but_marks_privileged_lists_denied():
    async def scenario():
        client = sdk()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(client) as stub:
                stub.add_response('describe_organization', org(), {})
                stub.add_client_error('list_roots', service_error_code='AccessDeniedException',
                                      http_status_code=400, expected_params={'MaxResults': PAGE_SIZE})
                stub.add_client_error('list_accounts', service_error_code='AccessDeniedException',
                                      http_status_code=400, expected_params={'MaxResults': PAGE_SIZE})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    collected = await OrganizationsFacade(object(), 'aws').get_organization_inventory()
                stub.assert_no_pending_responses()
            assert collected['organization']['Id'] == ORG_ID
            assert collected['collection'] == {'organization': 'complete',
                                               'roots': 'denied', 'accounts': 'denied'}
            assert [item['status'] for item in ctx.collection_issues] == ['denied', 'denied']
        finally:
            await ctx.aclose()
            client.close()
    asyncio.run(scenario())


def test_nonmember_and_denied_describe_never_infer_clean_organization():
    async def scenario():
        for error_code, expected in [
            ('AWSOrganizationsNotInUseException', 'unsupported'),
            ('AccessDeniedException', 'denied'),
        ]:
            client = sdk()
            ctx = RunContext('aws').setup()
            try:
                with Stubber(client) as stub:
                    stub.add_client_error('describe_organization', service_error_code=error_code,
                                          http_status_code=400, expected_params={})
                    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                        data = await OrganizationsFacade(object(), 'aws').get_organization_inventory()
                    stub.assert_no_pending_responses()
                assert data['organization'] is None
                assert data['roots'] == [] and data['accounts'] == []
                assert data['collection'] == {'organization': expected,
                                              'roots': 'not_collected', 'accounts': 'not_collected'}
                assert ctx.collection_issues[0]['status'] == expected
            finally:
                await ctx.aclose()
                client.close()
    asyncio.run(scenario())


def test_partial_page_failure_preserves_verified_rows():
    async def scenario():
        client = sdk()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(client) as stub:
                stub.add_response('describe_organization', org(), {})
                stub.add_response('list_roots', {'Roots': [root()]}, {'MaxResults': PAGE_SIZE})
                stub.add_response('list_accounts', {'Accounts': [account()], 'NextToken': 'more'},
                                  {'MaxResults': PAGE_SIZE})
                stub.add_client_error('list_accounts', service_error_code='AccessDeniedException',
                                      http_status_code=400,
                                      expected_params={'MaxResults': PAGE_SIZE, 'NextToken': 'more'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    data = await OrganizationsFacade(object(), 'aws').get_organization_inventory()
                stub.assert_no_pending_responses()
            assert len(data['accounts']) == 1
            assert data['collection']['accounts'] == 'partial'
            assert any(x['status'] == 'partial' for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
            client.close()
    asyncio.run(scenario())


def test_bounded_pagination_and_invalid_pages_fail_closed():
    async def scenario():
        cases = [
            ([{}], 'list_accountsMalformedPage'),
            ([{'Accounts': [], 'NextToken': 'a'},
              {'Accounts': [], 'NextToken': 'a'}], 'list_accountsInvalidToken'),
            ([{'Accounts': [account()], 'NextToken': 'next'},
              {'Accounts': [account()], 'NextToken': 'later'}],
             'list_accountsDuplicateIdentifier'),
            ([{'Accounts': [], 'NextToken': str(i)} for i in range(MAX_ACCOUNT_PAGES)],
             'list_accountsPageLimit'),
            ([{'Accounts': [account(str(100000000000+i)) for i in range(5001)]}],
             'list_accountsItemLimit'),
        ]
        for responses, reason in cases:
            context = RunContext('aws').setup()
            try:
                client = Mock()
                client.list_accounts.side_effect = responses
                records, status = await OrganizationsFacade(object(), 'aws')._list(
                    client, 'list_accounts', 'Accounts', MAX_ACCOUNT_PAGES, 5000)
                assert len(records) <= 5000
                assert status != 'complete'
                assert any(x['reason_code'] == reason for x in context.collection_issues)
                assert client.list_accounts.call_count <= MAX_ACCOUNT_PAGES
            finally:
                await context.aclose()
    asyncio.run(scenario())


def test_global_partition_selection_and_unknown_partition_fail_closed():
    async def scenario():
        for partition, home in HOME_REGIONS.items():
            fake = Mock()
            fake.describe_organization.side_effect = RuntimeError('synthetic endpoint stop')
            context = RunContext('aws').setup()
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=fake) as construct:
                    await OrganizationsFacade(object(), partition).get_organization_inventory()
                    assert construct.call_args.args[2] == home
                assert context.collection_issues[0]['status'] == 'failed'
            finally:
                await context.aclose()
        context = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client') as construct:
                result = await OrganizationsFacade(object(), 'invalid-partition').get_organization_inventory()
            construct.assert_not_called()
            assert result['collection']['organization'] == 'unavailable'
            assert context.collection_issues[0]['status'] == 'unsupported'
        finally:
            await context.aclose()
    asyncio.run(scenario())


def test_scp_classifier_and_normalization_are_explicit():
    assert classify_organizations_features({'feature_set': 'ALL'}) == 'secure'
    assert classify_organizations_features({'feature_set': 'CONSOLIDATED_BILLING'}) == 'insecure'
    assert classify_organizations_features({}) == 'unknown'
    assert classify_organizations_scp({'scp_status': 'ENABLED'}) == 'secure'
    assert classify_organizations_scp({'scp_status': 'DISABLED'}) == 'insecure'
    assert classify_organizations_scp({'scp_status': 'NOT_ENABLED'}) == 'insecure'
    assert classify_organizations_scp({'scp_status': 'NOT_APPLICABLE'}) == 'not_applicable'
    assert classify_organizations_scp({'scp_status': 'UNKNOWN'}) == 'unknown'
    root_record = Organizations._root(root(), 'ALL')
    assert root_record['scp_enabled'] is True
    missing = dict(root())
    missing['PolicyTypes'] = []
    assert Organizations._root(missing, 'ALL')['scp_status'] == 'NOT_ENABLED'
    assert Organizations._root(missing, 'CONSOLIDATED_BILLING')['scp_enabled'] is None
    assert Organizations._root({'Id': ROOT_ID}, 'ALL')['scp_enabled'] is None


def test_rule_engine_feature_and_scp_secure_insecure_unknown(tmp_path):
    names = ('organizations-features-not-enabled.json',
             'organizations-root-scp-not-enabled.json')
    path = tmp_path / 'rules.json'
    path.write_text(json.dumps({
        'about': 'Synthetic isolated Organizations policy signals',
        'rules': {name: [{'enabled': True, 'level': 'warning'}] for name in names}
    }), encoding='utf8')
    data = {
        'organizations': {
            'all': {'feature_set': 'ALL'},
            'billing': {'feature_set': 'CONSOLIDATED_BILLING'},
            'unknown': {'feature_set': 'UNKNOWN'},
        },
        'roots': {
            'enabled': {'scp_status': 'ENABLED', 'scp_enabled': True},
            'disabled': {'scp_status': 'NOT_ENABLED', 'scp_enabled': False},
            'unknown': {'scp_status': 'UNKNOWN', 'scp_enabled': None},
            'billing': {'scp_status': 'NOT_APPLICABLE', 'scp_enabled': None},
        },
    }
    provider = SimpleNamespace(services={'organizations': data}, service_list=['organizations'])
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(path))).run(provider)
        findings = data['findings']
        feature = findings['organizations-features-not-enabled']
        scp = findings['organizations-root-scp-not-enabled']
        assert feature['items'] == ['organizations.organizations.billing.BillingOnly']
        assert scp['items'] == ['organizations.roots.disabled.SCPNotEnabled']
        assert feature['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
        assert scp['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 1}
        assert feature['assessment_status'] == scp['assessment_status'] == 'incomplete'
    finally:
        ctx.cleanup()


def test_opt_in_metadata_templates_and_packaging_contract():
    fake_config = lambda credentials: SimpleNamespace(
        credentials=credentials, iam={}, organizations={}, guardduty={},
        accessanalyzer={}, s3={})
    credentials = SimpleNamespace(session=object())
    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig', fake_config), \
         patch('ScoutSuite.providers.aws.provider.get_partition_name', return_value='aws'), \
         patch('ScoutSuite.providers.aws.provider.get_aws_account_id',
               return_value=ACCOUNT_ID):
        default = AWSProvider(credentials=credentials)
        chosen = AWSProvider(credentials=credentials, services=['organizations'])
    assert 'organizations' not in default.service_list
    assert 'accessanalyzer' not in default.service_list
    assert 'guardduty' not in default.service_list
    assert chosen.service_list == ['organizations']
    meta = json.loads((ROOT / 'ScoutSuite/providers/aws/metadata.json').read_text(encoding='utf8'))
    for resource in ('organizations', 'roots', 'accounts'):
        assert meta['management']['organizations']['resources'][resource]['path'] == (
            'services.organizations.' + resource)
        html = (ROOT / 'ScoutSuite/output/data/html/partials/aws'
                / ('services.organizations.' + resource + '.id.html')).read_text(encoding='utf8')
        assert '{{name}}' in html and '{{{' not in html
        assert 'onclick=' not in html and 'javascript:' not in html
        assert 'single_organizations_' + resource[:-1] + '_template' in html
        assert 'Email' not in html
