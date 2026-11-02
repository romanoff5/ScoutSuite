"""M10-D Inspector2 own-account public API and non-overclaiming rule evidence."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_inspector2_state
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.inspector2 import Inspector2PublicFacade, SCAN_TYPES
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.provider import AWSProvider
from ScoutSuite.providers.aws.resources.inspector2.base import Inspector2Public


ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = '000000000000'
REGION = 'us-east-1'


def client():
    return boto3.client('inspector2', region_name=REGION,
                        aws_access_key_id='synthetic', aws_secret_access_key='synthetic')


def state(status):
    return {'status': status, 'errorCode': 'ALREADY_ENABLED', 'errorMessage': 'synthetic'}


def response(status='ENABLED', scan=None):
    values = scan or {}
    resource = {'ec2': state(values.get('ec2', 'ENABLED')),
                'ecr': state(values.get('ecr', 'ENABLED'))}
    for name in SCAN_TYPES[2:]:
        if name in values:
            resource[name] = state(values[name])
    return {'accounts': [{'accountId': ACCOUNT, 'state': state(status),
                          'resourceState': resource}], 'failedAccounts': []}


def test_sdk_contract_single_account_non_paginated():
    model = get_session().get_service_model('inspector2')
    operation = model.operation_model('BatchGetAccountStatus')
    assert 'accountIds' in operation.input_shape.members
    assert 'accounts' in operation.output_shape.members
    assert 'failedAccounts' in operation.output_shape.members
    assert 'ListCoverage' in model.operation_names  # explicitly NOT called by M10-D


def test_stubber_account_scope_and_normalized_scantypes():
    async def scenario():
        sdk = client()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('batch_get_account_status',
                                  response('ENABLED', {'ec2': 'SUSPENDED', 'lambda': 'ENABLING'}),
                                  {'accountIds': [ACCOUNT]})
                facade = Inspector2PublicFacade(object(), ACCOUNT)
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk) as get_client:
                    raw = await facade.get_account_status(REGION)
                get_client.assert_called_once_with('inspector2', facade.session, REGION)
                stub.assert_no_pending_responses()
            assert raw['account_id'] == ACCOUNT
            assert raw['status'] == 'ENABLED'
            assert raw['scan_types']['ec2'] == 'SUSPENDED'
            assert raw['scan_types']['lambda'] == 'ENABLING'
            assert raw['scan_types']['lambdaCode'] is None
            assert 'errorMessage' not in str(raw) and 'findings' not in str(raw)
            upstream = SimpleNamespace(
                build_region_list=AsyncMock(return_value=[REGION]),
                inspector2=SimpleNamespace(get_account_status=AsyncMock(return_value=raw)))
            resources = Inspector2Public(upstream)
            await resources.fetch_all(regions=[REGION])
            assert resources['regions_count'] == 1
            assert resources['accounts_count'] == 1
            account = next(iter(resources['regions'][REGION]['accounts'].values()))
            assert account['id'].startswith('scoutid-')
            assert account['inactive'] is False
            assert account['scan_types']['ec2']['inactive'] is True
            assert account['scan_types']['lambda']['inactive'] is False
            assert account['scan_types']['lambdaCode']['status'] is None
        finally:
            sdk.close()
    asyncio.run(scenario())


def test_access_denied_and_invalid_owner_do_not_produce_false_clean_state():
    async def scenario():
        sdk = client()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_client_error('batch_get_account_status',
                                      service_error_code='AccessDeniedException',
                                      http_status_code=403,
                                      expected_params={'accountIds': [ACCOUNT]})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    assert await Inspector2PublicFacade(object(), ACCOUNT).get_account_status(REGION) is None
                stub.assert_no_pending_responses()
            assert any(x['status'] == 'denied' and x['scope'] == 'inspector2'
                       for x in ctx.collection_issues)
            invalid = Inspector2PublicFacade(object(), '000-not-account')
            with patch.object(AWSFacadeUtils, 'get_client') as get_client:
                assert await invalid.get_account_status(REGION) is None
                get_client.assert_not_called()
            assert any(x['reason_code'] == 'InvalidAccountId' for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(scenario())


def test_failed_accounts_unexpected_scope_and_malformed_types():
    async def scenario():
        cases = [
            ({'accounts': [], 'failedAccounts': []}, 'UnexpectedAccountScope'),
            ({'accounts': [], 'failedAccounts': [{'accountId': ACCOUNT}]}, 'FailedAccountStatus'),
            ({'accounts': [{'accountId': '111111111111', 'state': state('ENABLED'),
                            'resourceState': {}}], 'failedAccounts': []}, 'UnexpectedAccountScope'),
            ({'accounts': [{'accountId': ACCOUNT, 'state': {}, 'resourceState': {}}],
              'failedAccounts': []}, 'MalformedAccountState'),
            ({'accounts': [{'accountId': ACCOUNT, 'state': state('ENABLED'),
                            'resourceState': None}], 'failedAccounts': []}, 'MalformedAccountState'),
            ({'accounts': None, 'failedAccounts': []}, 'MalformedAccountStatus'),
        ]
        for payload, reason in cases:
            sdk = Mock()
            sdk.batch_get_account_status.return_value = payload
            ctx = RunContext('aws').setup()
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    assert await Inspector2PublicFacade(object(), ACCOUNT).get_account_status(REGION) is None
                sdk.batch_get_account_status.assert_called_once_with(accountIds=[ACCOUNT])
                assert any(x['reason_code'] == reason for x in ctx.collection_issues)
            finally:
                await ctx.aclose()
        sdk = Mock()
        payload = response()
        payload['accounts'][0]['resourceState']['ec2'] = {}
        sdk.batch_get_account_status.return_value = payload
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                raw = await Inspector2PublicFacade(object(), ACCOUNT).get_account_status(REGION)
            assert raw['scan_types']['ec2'] is None
            assert any(x['reason_code'] == 'MalformedScanType' for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
    asyncio.run(scenario())


def test_evidence_and_rule_engine_four_state_behavior(tmp_path):
    for status, expected in [('ENABLED', 'secure'), ('DISABLED', 'insecure'),
                             ('SUSPENDED', 'insecure'), ('ENABLING', 'unknown'),
                             ('DISABLING', 'unknown'), (None, 'unknown')]:
        assert classify_inspector2_state({'status': status}) == expected
    assert classify_inspector2_state(None) == 'unknown'
    chosen = {'about': 'Synthetic M10-D', 'rules': {
        'inspector2-account-inactive.json': [{'enabled': True, 'level': 'warning'}],
        'inspector2-scan-type-inactive.json': [{'enabled': True, 'level': 'warning'}]}}
    rule_file = tmp_path / 'inspector2-rules.json'
    rule_file.write_text(json.dumps(chosen), encoding='utf-8')
    data = {REGION: {'accounts': {
        'id': {'status': 'ENABLED', 'inactive': False, 'scan_types': {
            'ec2': {'status': 'SUSPENDED', 'inactive': True},
            'ecr': {'status': 'ENABLED', 'inactive': False},
            'lambda': {'status': None, 'inactive': False}}}}}}
    provider = SimpleNamespace(services={'inspector2': {'regions': data}},
                               service_list=['inspector2'])
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(rule_file))).run(provider)
        rows = provider.services['inspector2']['findings']
        assert rows['inspector2-account-inactive']['flagged_items'] == 0
        assert rows['inspector2-scan-type-inactive']['flagged_items'] == 1
        assert rows['inspector2-scan-type-inactive']['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
        assert rows['inspector2-scan-type-inactive']['assessment_status'] == 'incomplete'
    finally:
        ctx.cleanup()


def test_optin_catalog_and_safe_renderer():
    config = lambda credentials: SimpleNamespace(credentials=credentials, iam={}, s3={},
                                                   guardduty={}, accessanalyzer={},
                                                   securityhub={}, inspector2={})
    credentials = SimpleNamespace(session=object())
    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig', config), \
         patch('ScoutSuite.providers.aws.provider.get_partition_name', return_value='aws'), \
         patch('ScoutSuite.providers.aws.provider.get_aws_account_id', return_value=ACCOUNT):
        default = AWSProvider(credentials=credentials)
        chosen = AWSProvider(credentials=credentials, services=['inspector2'])
    assert 'inspector2' not in default.service_list
    assert chosen.service_list == ['inspector2']
    meta = json.loads((ROOT / 'ScoutSuite/providers/aws/metadata.json').read_text(encoding='utf-8'))
    assert meta['security']['inspector2']['resources']['accounts']['path'] == (
        'services.inspector2.regions.id.accounts')
    template = (ROOT / 'ScoutSuite/output/data/html/partials/aws/'
                'services.inspector2.regions.id.accounts.html').read_text(encoding='utf-8')
    assert 'single_inspector2_account_template' in template
    assert '{{account_id}}' in template and '{{status}}' in template
    assert '{{{' not in template and 'onclick=' not in template
    assert 'javascript:' not in template


def test_sdk_may_omit_empty_failed_accounts():
    """An absent optional failedAccounts field must not falsely fail success."""
    async def scenario():
        sdk = client()
        output = response()
        output.pop('failedAccounts')
        try:
            with Stubber(sdk) as stub:
                stub.add_response('batch_get_account_status', output,
                                  {'accountIds': [ACCOUNT]})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    result = await Inspector2PublicFacade(object(), ACCOUNT).get_account_status(REGION)
                stub.assert_no_pending_responses()
            assert result['account_id'] == ACCOUNT
            assert result['status'] == 'ENABLED'
        finally:
            sdk.close()
    asyncio.run(scenario())
