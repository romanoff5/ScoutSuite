"""M10-J: WAFv2 regional/global read-only enumeration, boundedness and evidence."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_wafv2_empty_allow
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.wafv2 import (
    WAFv2PublicFacade, MAX_PAGES, PAGE_SIZE)
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.provider import AWSProvider
from ScoutSuite.providers.aws.resources.wafv2.base import WAFv2Public
from ScoutSuite.providers.aws.resources.wafv2.web_acls import WebACLs


ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = '000000000000'
REGION = 'us-east-1'


def client(region=REGION):
    return boto3.client('wafv2', region_name=region,
                        aws_access_key_id='synthetic',
                        aws_secret_access_key='synthetic')


def arn(name='web', scope='REGIONAL', region=REGION, account=ACCOUNT):
    kind = 'global' if scope == 'CLOUDFRONT' else 'regional'
    return ('arn:aws:wafv2:' + region + ':' + account +
            ':' + kind + '/webacl/' + name + '/synthetic-id')


def summary(name='web', scope='REGIONAL', region=REGION):
    return {'Name': name, 'Id': 'synthetic-id', 'ARN': arn(name, scope, region)}


def detail(name='web', scope='REGIONAL', region=REGION, rules=None,
           allow=True, managed=False):
    if rules is None:
        rules = []
    return {
        'Name': name, 'Id': 'synthetic-id', 'ARN': arn(name, scope, region),
        'DefaultAction': {'Allow': {}} if allow else {'Block': {}},
        'VisibilityConfig': {
            'SampledRequestsEnabled': False,
            'CloudWatchMetricsEnabled': True,
            'MetricName': 'synthetic'},
        'Rules': rules, 'ManagedByFirewallManager': managed,
    }


def test_botocore_operations_and_shapes():
    model = get_session().get_service_model('wafv2')
    listing = model.operation_model('ListWebACLs')
    getter = model.operation_model('GetWebACL')
    logging = model.operation_model('GetLoggingConfiguration')
    assert 'Scope' in listing.input_shape.required_members
    assert {'Scope', 'Limit', 'NextMarker'} <= set(listing.input_shape.members)
    assert {'Name', 'Id', 'Scope'} <= set(getter.input_shape.members)
    assert 'WebACL' in getter.output_shape.members
    assert 'ResourceArn' in logging.input_shape.required_members
    assert 'LoggingConfiguration' in logging.output_shape.members


def test_both_scopes_and_normalized_resources_with_stubbed_sdk():
    async def scenario():
        sdk = client()
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_web_acls',
                                  {'WebACLs': [summary()]},
                                  {'Scope': 'REGIONAL', 'Limit': PAGE_SIZE})
                stub.add_response('get_web_acl',
                                  {'WebACL': detail()},
                                  {'Name': 'web', 'Id': 'synthetic-id',
                                   'Scope': 'REGIONAL'})
                stub.add_response('get_logging_configuration',
                                  {'LoggingConfiguration': {
                                      'ResourceArn': arn(),
                                      'LogDestinationConfigs': [
                                          'arn:aws:logs:us-east-1:' + ACCOUNT +
                                          ':log-group:aws-waf-logs-web']}},
                                  {'ResourceArn': arn()})
                stub.add_response('list_web_acls',
                                  {'WebACLs': [summary('cdn', 'CLOUDFRONT')]},
                                  {'Scope': 'CLOUDFRONT', 'Limit': PAGE_SIZE})
                stub.add_response('get_web_acl',
                                  {'WebACL': detail('cdn', 'CLOUDFRONT', allow=False)},
                                  {'Name': 'cdn', 'Id': 'synthetic-id',
                                   'Scope': 'CLOUDFRONT'})
                stub.add_client_error('get_logging_configuration',
                                      service_error_code='WAFNonexistentItemException',
                                      http_status_code=400,
                                      expected_params={
                                          'ResourceArn': arn('cdn', 'CLOUDFRONT')})
                ctx = RunContext('aws').setup()
                try:
                    with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk) as get, \
                         patch('ScoutSuite.providers.aws.facade.wafv2.discover_associations',
                               new_callable=AsyncMock) as associations:
                        associations.return_value = {
                            'association_status': 'unknown',
                            'association_scope_complete': False,
                            'associated_resources': [],
                            'associated_resource_count': 0,
                            'checked_resource_types': [],
                            'unknown_resource_types': [],
                        }
                        facade = WAFv2PublicFacade(object(), ACCOUNT)
                        records = await facade.get_web_acls(REGION)
                        get.assert_called_once_with('wafv2', facade.session, REGION)
                        assert associations.await_count == 2
                    stub.assert_no_pending_responses()
                    assert any(x['reason_code'] == 'LoggingConfigurationNotFound'
                               for x in ctx.collection_issues)
                finally:
                    await ctx.aclose()
            assert len(records) == 2
            assert records[0]['scope'] == 'REGIONAL'
            assert records[1]['scope'] == 'CLOUDFRONT'
            assert records[0]['logging_status'] == 'configured'
            assert records[1]['logging_status'] == 'unknown'
            facade_stub = SimpleNamespace(
                build_region_list=AsyncMock(return_value=[REGION]),
                wafv2=SimpleNamespace(get_web_acls=AsyncMock(return_value=records)))
            resources = WAFv2Public(facade_stub)
            await resources.fetch_all(regions=[REGION])
            assert resources['regions_count'] == 1
            assert resources['web_acls_count'] == 2
            normalized = list(resources['regions'][REGION]['web_acls'].values())
            bad = next(x for x in normalized if x['scope'] == 'REGIONAL')
            good = next(x for x in normalized if x['scope'] == 'CLOUDFRONT')
            assert bad['web_acl_arn'] == arn()
            assert bad['unprotected_allow_all'] is True
            assert good['default_action'] == 'BLOCK'
            assert good['unprotected_allow_all'] is False
            assert bad['log_destinations'][0].endswith('aws-waf-logs-web')
            assert all(x['id'].startswith('scoutid-') for x in normalized)
        finally:
            sdk.close()
    asyncio.run(scenario())


def test_non_us_east_region_never_queries_cloudfront_scope():
    async def scenario():
        region = 'eu-central-1'
        sdk = client(region)
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_web_acls', {'WebACLs': []},
                                  {'Scope': 'REGIONAL', 'Limit': PAGE_SIZE})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    rows = await WAFv2PublicFacade(object(), ACCOUNT).get_web_acls(region)
                stub.assert_no_pending_responses()
            assert rows == []
        finally:
            sdk.close()
    asyncio.run(scenario())


def test_denied_list_and_invalid_identity_do_not_imply_clean():
    async def scenario():
        sdk = client()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(sdk) as stub:
                stub.add_client_error('list_web_acls',
                                      service_error_code='WAFInvalidPermissionException',
                                      http_status_code=403,
                                      expected_params={'Scope': 'REGIONAL',
                                                       'Limit': PAGE_SIZE})
                stub.add_response('list_web_acls', {'WebACLs': []},
                                  {'Scope': 'CLOUDFRONT', 'Limit': PAGE_SIZE})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    assert await WAFv2PublicFacade(object(), ACCOUNT).get_web_acls(REGION) == []
                stub.assert_no_pending_responses()
            assert any(x['status'] == 'denied' and x['scope'] == 'wafv2'
                       for x in ctx.collection_issues)
            with patch.object(AWSFacadeUtils, 'get_client') as get:
                assert await WAFv2PublicFacade(object(), 'bad').get_web_acls(REGION) == []
                get.assert_not_called()
            assert any(x['reason_code'] == 'InvalidAccountId'
                       for x in ctx.collection_issues)
        finally:
            await ctx.aclose()
            sdk.close()
    asyncio.run(scenario())


def test_pages_with_duplicates_cross_account_and_token_cycles():
    async def scenario():
        eu = 'eu-central-1'
        local = summary(region=eu)
        cases = [
            ([{}], 'MalformedWebACLPage'),
            ([{'WebACLs': [None]}], 'MalformedWebACLSummary'),
            ([{'WebACLs': [dict(local, ARN=arn(region=eu, account='111111111111'))]}],
             'InvalidWebACLIdentity'),
            ([{'WebACLs': [local, local]}], 'DuplicateWebACL'),
            ([{'WebACLs': [], 'NextMarker': 'loop'},
              {'WebACLs': [], 'NextMarker': 'loop'}], 'InvalidPaginationToken'),
            ([{'WebACLs': [], 'NextMarker': str(i)} for i in range(MAX_PAGES)],
             'WebACLPageLimit'),
            ([{'WebACLs': [summary(str(i)) for i in range(PAGE_SIZE + 1)]}],
             'MalformedWebACLPage'),
        ]
        for pages, reason in cases:
            sdk = Mock()
            sdk.list_web_acls.side_effect = pages + [{'WebACLs': []}]
            sdk.get_web_acl.return_value = {'WebACL': detail()}
            sdk.get_logging_configuration.return_value = {
                'LoggingConfiguration': {
                    'ResourceArn': arn(), 'LogDestinationConfigs': []}}
            ctx = RunContext('aws').setup()
            try:
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    await WAFv2PublicFacade(object(), ACCOUNT).get_web_acls(eu)
                assert sdk.list_web_acls.call_count <= MAX_PAGES
                assert any(x['reason_code'] == reason for x in ctx.collection_issues)
            finally:
                await ctx.aclose()
    asyncio.run(scenario())


def test_safe_rule_summary_and_waf_action_evidence(tmp_path):
    parser = WebACLs.__new__(WebACLs)
    parser.region = REGION
    synthetic = {
        'name': '<script>test</script>', 'id': 'synthetic-id', 'arn': arn(),
        'scope': 'REGIONAL', 'region': REGION,
        'default_action': {'Allow': {}},
        'rules': [{'Name': 'rate-limit', 'Priority': 1,
                   'Statement': {'RateBasedStatement': {'Limit': 100}},
                   'Action': {'Block': {}}}],
        'managed_by_firewall_manager': False,
        'pre_process_rule_groups': [], 'post_process_rule_groups': [],
        'logging_status': 'configured', 'log_destinations': [],
    }
    key, normalized = parser._normalize(synthetic)
    assert key.startswith('scoutid-')
    assert normalized['name'] == '<script>test</script>'
    assert normalized['rules'][0]['name'] == 'rate-limit'
    assert normalized['rules'][0]['statement_types'] == ['RateBasedStatement']
    assert '100' not in json.dumps(normalized['rules'])
    examples = [
        ({'default_action': 'ALLOW', 'rule_count': 0,
          'managed_by_firewall_manager': False}, 'insecure'),
        ({'default_action': 'BLOCK', 'rule_count': 0,
          'managed_by_firewall_manager': False}, 'secure'),
        ({'default_action': 'ALLOW', 'rule_count': 1,
          'managed_by_firewall_manager': False}, 'secure'),
        ({'default_action': 'ALLOW', 'rule_count': 0,
          'managed_by_firewall_manager': True}, 'unknown'),
        ({'default_action': 'ALLOW', 'rule_count': None,
          'managed_by_firewall_manager': False}, 'unknown'),
        ({'default_action': None, 'rule_count': 0,
          'managed_by_firewall_manager': False}, 'unknown'),
    ]
    for value, expected in examples:
        assert classify_wafv2_empty_allow(value) == expected
    assert classify_wafv2_empty_allow(None) == 'unknown'
    rules = {'about': 'M10-J synthetic', 'rules': {
        'wafv2-web-acl-empty-allow.json': [
            {'enabled': True, 'level': 'warning'}]}}
    file = tmp_path / 'rules.json'
    file.write_text(json.dumps(rules), encoding='utf-8')
    normal = dict(normalized, default_action='ALLOW', rule_count=0,
                  unprotected_allow_all=True)
    blocked = dict(normalized, default_action='BLOCK', rule_count=0,
                   unprotected_allow_all=False)
    unknown = dict(normalized, managed_by_firewall_manager=None,
                   default_action='ALLOW', rule_count=0, unprotected_allow_all=False)
    provider = SimpleNamespace(
        services={'wafv2': {'regions': {REGION: {
            'web_acls': {'bad': normal, 'good': blocked, 'unknown': unknown}}}}},
        service_list=['wafv2'])
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(file))).run(provider)
        finding = provider.services['wafv2']['findings']['wafv2-web-acl-empty-allow']
        assert finding['flagged_items'] == 1
        assert finding['assessment_status'] == 'incomplete'
        assert finding['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
    finally:
        ctx.cleanup()


def test_wafv2_is_selected_by_default_and_html_is_escaped():
    config = lambda credentials: SimpleNamespace(credentials=credentials, iam={}, s3={},
                                                   wafv2={}, ecr={}, ecs={}, eks={})
    credentials = SimpleNamespace(session=object())
    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig', config), \
         patch('ScoutSuite.providers.aws.provider.get_partition_name', return_value='aws'), \
         patch('ScoutSuite.providers.aws.provider.get_aws_account_id', return_value=ACCOUNT):
        default = AWSProvider(credentials=credentials)
        chosen = AWSProvider(credentials=credentials, services=['wafv2'])
        skipped = AWSProvider(credentials=credentials, skipped_services=['wafv2'])
    assert 'wafv2' in default.service_list
    assert chosen.service_list == ['wafv2']
    assert 'wafv2' not in skipped.service_list
    metadata = json.loads((ROOT / 'ScoutSuite/providers/aws/metadata.json').read_text())
    assert metadata['security']['wafv2']['resources']['web_acls']['path'] == (
        'services.wafv2.regions.id.web_acls')
    template = (ROOT / 'ScoutSuite/output/data/html/partials/aws/'
                'services.wafv2.regions.id.web_acls.html').read_text()
    assert '{{web_acl_arn}}' in template and '{{name}}' in template
    assert '{{{' not in template and 'onclick=' not in template and 'javascript:' not in template
