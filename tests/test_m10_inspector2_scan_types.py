"""M10-D consolidation: full account + scan-type + coverage evidence with one collector."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import (
    classify_inspector2_account, classify_inspector2_coverage, CLASSIFIERS,
)
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.output.result_encoder import ScoutResultEncoder
from ScoutSuite.providers.aws.facade.inspector2 import (
    Inspector2Facade, SCAN_TYPES, REQUIRED_SCAN_TYPES,
)
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.inspector2.accounts import InspectorAccounts
from ScoutSuite.providers.aws.resources.inspector2.base import Inspector2


ACCOUNT = '000000000000'
REGION = 'us-east-1'
ROOT = Path(__file__).resolve().parents[1]


def sdk():
    return boto3.client('inspector2', region_name=REGION,
                        aws_access_key_id='synthetic', aws_secret_access_key='synthetic')


def state(status):
    return {'status': status, 'errorCode': 'ALREADY_ENABLED',
            'errorMessage': 'SYNTHETIC_INTERNAL_MESSAGE_MUST_NOT_LEAK'}


def account_response(scan=None, include_optionals=False):
    scan = {} if scan is None else scan
    states = {'ec2': state(scan.get('ec2', 'SUSPENDED')),
              'ecr': state(scan.get('ecr', 'ENABLED'))}
    if include_optionals:
        states['lambda'] = state(scan.get('lambda', 'ENABLING'))
        states['lambdaCode'] = state(scan.get('lambdaCode', 'DISABLED'))
        states['codeRepository'] = state(scan.get('codeRepository', 'ENABLED'))
    return {'accounts': [{'accountId': ACCOUNT, 'state': state('ENABLED'),
                          'resourceState': states}], 'failedAccounts': []}


def test_required_ec2_ecr_optional_others_and_schema_preserved():
    assert REQUIRED_SCAN_TYPES == {'ec2', 'ecr'}
    assert SCAN_TYPES == ('ec2', 'ecr', 'lambda', 'lambdaCode', 'codeRepository')
    async def scenario():
        client = sdk()
        try:
            with Stubber(client) as stub:
                stub.add_response('batch_get_account_status', account_response(),
                                  {'accountIds': [ACCOUNT]})
                context = RunContext('aws').setup()
                try:
                    with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                        raw = await Inspector2Facade(object(), ACCOUNT).get_accounts(REGION)
                    assert not context.collection_issues
                finally:
                    await context.aclose()
                stub.assert_no_pending_responses()
            assert len(raw) == 1
            assert raw[0]['status'] == 'ENABLED'
            assert raw[0]['resource_states']['ec2'] == 'SUSPENDED'
            assert raw[0]['resource_states']['ecr'] == 'ENABLED'
            assert all(raw[0]['resource_states'][name] is None
                       for name in SCAN_TYPES[2:])
            assert 'SYNTHETIC_INTERNAL_MESSAGE_MUST_NOT_LEAK' not in str(raw)
            source = SimpleNamespace(
                build_region_list=AsyncMock(return_value=[REGION]),
                inspector2=SimpleNamespace(get_accounts=AsyncMock(return_value=raw),
                                           get_coverage=AsyncMock(return_value=[])))
            normalized = Inspector2(source)
            await normalized.fetch_all(regions=[REGION])
            assert normalized['accounts_count'] == 1
            assert normalized['coverage_count'] == 0
            record = next(iter(normalized['regions'][REGION]['accounts'].values()))
            assert record['resource_states']['ec2'] == 'SUSPENDED'  # legacy field
            assert record['scan_types_count'] == 5
            assert record['scan_types']['ec2']['inactive'] is True
            assert record['scan_types']['ecr']['inactive'] is False
            assert record['scan_types']['lambda']['status'] == 'UNKNOWN'
            assert record['scan_types']['lambda']['inactive'] is False
            assert all('errorMessage' not in str(value)
                       for value in record['scan_types'].values())
            assert ScoutResultEncoder.to_dict({'services': {'inspector2': dict(normalized)}})[
                'services']['inspector2']['regions'][REGION]['accounts']
        finally:
            client.close()
    asyncio.run(scenario())


def test_full_five_scan_states_and_transitional_behavior():
    async def scenario():
        client = sdk()
        try:
            with Stubber(client) as stub:
                stub.add_response('batch_get_account_status',
                                  account_response(include_optionals=True),
                                  {'accountIds': [ACCOUNT]})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    raw = await Inspector2Facade(object(), ACCOUNT).get_accounts(REGION)
                stub.assert_no_pending_responses()
            parser = InspectorAccounts.__new__(InspectorAccounts)
            parser.region = REGION
            key, normalized = parser._parse_account(raw[0])
            assert key.startswith('scoutid-')
            assert normalized['status'] == 'ENABLED'
            assert normalized['scan_types']['ec2']['status'] == 'SUSPENDED'
            assert normalized['scan_types']['lambda']['status'] == 'ENABLING'
            assert normalized['scan_types']['lambdaCode']['status'] == 'DISABLED'
            assert normalized['scan_types']['codeRepository']['status'] == 'ENABLED'
            assert CLASSIFIERS['inspector2-scan-type-state-v1'] is classify_inspector2_account
            assert classify_inspector2_account(normalized) == 'secure'
            assert classify_inspector2_account(normalized['scan_types']['ec2']) == 'insecure'
            assert classify_inspector2_account(normalized['scan_types']['lambda']) == 'unknown'
            assert classify_inspector2_account(normalized['scan_types']['lambdaCode']) == 'insecure'
            assert classify_inspector2_coverage({'scan_status': 'INACTIVE'}) == 'insecure'
        finally:
            client.close()
    asyncio.run(scenario())


def test_missing_required_ec2_and_malformed_status_never_silent():
    async def scenario():
        client = Mock()
        response = account_response()
        response['accounts'][0]['resourceState'].pop('ec2')
        response['accounts'][0]['resourceState']['ecr'] = {'status': 'BAD-UNKNOWN'}
        client.batch_get_account_status.return_value = response
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                rows = await Inspector2Facade(object(), ACCOUNT).get_accounts(REGION)
            assert rows[0]['resource_states']['ec2'] is None
            assert rows[0]['resource_states']['ecr'] is None
            assert {x['reason_code'] for x in ctx.collection_issues} >= {
                'MissingRequiredScanType', 'InvalidScanTypeStatus'}
        finally:
            await ctx.aclose()
    asyncio.run(scenario())


def test_failed_accounts_even_with_valid_account_produces_no_clean_row():
    async def scenario():
        client = Mock()
        data = account_response()
        data['failedAccounts'] = [{'accountId': ACCOUNT, 'errorCode': 'ACCESS_DENIED',
                                   'errorMessage': 'SYNTHETIC_INTERNAL_MESSAGE_MUST_NOT_LEAK',
                                   'status': 'DISABLED'}]
        client.batch_get_account_status.return_value = data
        ctx = RunContext('aws').setup()
        try:
            with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                assert await Inspector2Facade(object(), ACCOUNT).get_accounts(REGION) == []
            assert any(x['reason_code'] == 'FailedAccountStatus'
                       for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
    asyncio.run(scenario())


def test_scan_type_rule_evidence_no_duplicate_account_or_coverage_rule(tmp_path):
    selected = {'about': 'Inspector2 consolidation integration', 'rules': {
        'inspector2-account-disabled.json': [{'enabled': True, 'level': 'warning'}],
        'inspector2-coverage-inactive.json': [{'enabled': True, 'level': 'warning'}],
        'inspector2-scan-type-inactive.json': [{'enabled': True, 'level': 'warning'}],
    }}
    rule_path = tmp_path / 'selected.json'
    rule_path.write_text(json.dumps(selected), encoding='utf-8')
    samples = {
        'ec2': {'status': 'SUSPENDED', 'inactive': True},
        'ecr': {'status': 'ENABLED', 'inactive': False},
        'lambda': {'status': 'UNKNOWN', 'inactive': False},
    }
    provider = SimpleNamespace(
        services={'inspector2': {'regions': {REGION: {
            'accounts': {'only': {'status': 'ENABLED', 'disabled': False,
                                  'scan_types': samples}},
            'coverage': {'one': {'scan_status': 'INACTIVE', 'inactive': True}},
        }}}},
        service_list=['inspector2'])
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(rule_path))).run(provider)
        rows = provider.services['inspector2']['findings']
        assert set(rows) == {
            'inspector2-account-disabled', 'inspector2-coverage-inactive',
            'inspector2-scan-type-inactive'}
        assert rows['inspector2-account-disabled']['flagged_items'] == 0
        assert rows['inspector2-coverage-inactive']['flagged_items'] == 1
        scan = rows['inspector2-scan-type-inactive']
        assert scan['flagged_items'] == 1
        assert scan['assessment_status'] == 'incomplete'
        assert scan['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
    finally:
        ctx.cleanup()


def test_no_duplicate_colliding_inspector_names_and_safe_partial():
    root = ROOT / 'ScoutSuite/providers/aws/rules/findings'
    names = {file.name for file in root.glob('inspector2-*.json')}
    assert names == {
        'inspector2-account-disabled.json',
        'inspector2-coverage-inactive.json',
        'inspector2-scan-type-inactive.json'}
    html = (ROOT / 'ScoutSuite/output/data/html/partials/aws/'
            'services.inspector2.regions.id.accounts.html').read_text(encoding='utf-8')
    assert '{{scan_types.ec2.status}}' in html
    assert '{{scan_types.codeRepository.status}}' in html
    assert '{{{' not in html and 'onclick=' not in html and 'javascript:' not in html
    assert 'Inspector2PublicFacade' not in (
        ROOT / 'ScoutSuite/providers/aws/facade/inspector2.py').read_text(encoding='utf-8')
