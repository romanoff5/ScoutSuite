"""M10-K: WAFv2 resource associations, CloudFront and scoped completeness."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch, call

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_wafv2_association
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.wafv2_associations import (
    discover_associations, REGIONAL_TYPES)
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.wafv2.web_acls import WebACLs


ACCOUNT = '000000000000'
REGION = 'us-east-1'
WAF_REGIONAL = ('arn:aws:wafv2:eu-central-1:' + ACCOUNT +
                ':regional/webacl/example/synthetic-id')
WAF_GLOBAL = ('arn:aws:wafv2:us-east-1:' + ACCOUNT +
              ':global/webacl/global/synthetic-id')
ALB = ('arn:aws:elasticloadbalancing:eu-central-1:' + ACCOUNT +
       ':loadbalancer/app/synthetic/abcdefgh')
API_STAGE = 'arn:aws:apigateway:eu-central-1::/restapis/abcd1234/stages/prod'
CF_ARN = 'arn:aws:cloudfront::' + ACCOUNT + ':distribution/D123EXAMPLE'
ROOT = Path(__file__).resolve().parents[1]


def facade():
    return SimpleNamespace(
        session=object(), owner_id=ACCOUNT,
        issue=Mock())


def make_client(service, region=REGION):
    return boto3.client(service, region_name=region,
                        aws_access_key_id='synthetic',
                        aws_secret_access_key='synthetic')


def test_sdk_operation_contract_and_regional_types():
    waf = get_session().get_service_model('wafv2')
    op = waf.operation_model('ListResourcesForWebACL')
    assert {'WebACLArn', 'ResourceType'} <= set(op.input_shape.members)
    assert 'ResourceArns' in op.output_shape.members
    assert set(REGIONAL_TYPES) <= set(op.input_shape.members['ResourceType'].enum)
    cf = get_session().get_service_model('cloudfront')
    op = cf.operation_model('ListDistributionsByWebACLId')
    assert {'WebACLId', 'Marker', 'MaxItems'} <= set(op.input_shape.members)
    assert 'DistributionList' in op.output_shape.members


def test_regional_api_stubber_confirms_alb_and_api_gateway():
    async def scenario():
        sdk = make_client('wafv2', 'eu-central-1')
        try:
            with Stubber(sdk) as stub:
                for kind in REGIONAL_TYPES:
                    arns = {'APPLICATION_LOAD_BALANCER': [ALB],
                            'API_GATEWAY': [API_STAGE]}.get(kind, [])
                    stub.add_response('list_resources_for_web_acl', {
                        'ResourceArns': arns}, {
                        'WebACLArn': WAF_REGIONAL, 'ResourceType': kind})
                f = facade()
                result = await discover_associations(
                    f, sdk, 'eu-central-1', 'REGIONAL', WAF_REGIONAL)
                stub.assert_no_pending_responses()
            assert result['association_status'] == 'associated'
            assert result['association_scope_complete'] is True
            assert result['associated_resource_count'] == 2
            assert result['unknown_resource_types'] == []
            assert result['associated_resources'] == [
                {'resource_type': 'APPLICATION_LOAD_BALANCER',
                 'resource_arn': ALB},
                {'resource_type': 'API_GATEWAY',
                 'resource_arn': API_STAGE}]
            f.issue.assert_not_called()
        finally:
            sdk.close()
    asyncio.run(scenario())


def test_regional_no_associations_requires_all_supported_types_checked():
    async def scenario():
        sdk = make_client('wafv2', 'eu-central-1')
        try:
            with Stubber(sdk) as stub:
                for kind in REGIONAL_TYPES:
                    stub.add_response('list_resources_for_web_acl',
                                      {'ResourceArns': []},
                                      {'WebACLArn': WAF_REGIONAL, 'ResourceType': kind})
                f = facade()
                result = await discover_associations(
                    f, sdk, 'eu-central-1', 'REGIONAL', WAF_REGIONAL)
                stub.assert_no_pending_responses()
            assert result['association_status'] == 'unused_candidate'
            assert result['association_scope_complete'] is True
            assert not result['associated_resources']
            f.issue.assert_not_called()
        finally:
            sdk.close()
    asyncio.run(scenario())


def test_denied_api_gateway_is_unknown_but_known_alb_is_preserved():
    async def scenario():
        for positive in (False, True):
            sdk = make_client('wafv2', 'eu-central-1')
            try:
                with Stubber(sdk) as stub:
                    for kind in REGIONAL_TYPES:
                        args = {'WebACLArn': WAF_REGIONAL, 'ResourceType': kind}
                        if kind == 'API_GATEWAY':
                            stub.add_client_error(
                                'list_resources_for_web_acl',
                                service_error_code='WAFInvalidPermissionException',
                                http_status_code=403, expected_params=args)
                        else:
                            arns = [ALB] if positive and kind == REGIONAL_TYPES[0] else []
                            stub.add_response('list_resources_for_web_acl',
                                              {'ResourceArns': arns}, args)
                    f = facade()
                    result = await discover_associations(
                        f, sdk, 'eu-central-1', 'REGIONAL', WAF_REGIONAL)
                    stub.assert_no_pending_responses()
                assert result['association_status'] == (
                    'associated' if positive else 'unknown')
                assert result['association_scope_complete'] is False
                assert result['unknown_resource_types'] == ['API_GATEWAY']
                assert result['associated_resource_count'] == int(positive)
                assert any(x.args[0] == 'partial' for x in f.issue.call_args_list)
            finally:
                sdk.close()
    asyncio.run(scenario())


def cf_page(items=None, truncated=False, marker=None):
    listing = {'Marker': marker or '', 'MaxItems': 100,
               'IsTruncated': truncated, 'Quantity': len(items or []),
               'Items': items or []}
    if truncated:
        listing['NextMarker'] = 'next'
    return {'DistributionList': listing}


def test_cloudfront_empty_api_stubber_and_exact_web_acl_arn():
    async def scenario():
        sdk = make_client('cloudfront')
        try:
            with Stubber(sdk) as stub:
                stub.add_response('list_distributions_by_web_acl_id',
                                  cf_page(), {'WebACLId': WAF_GLOBAL,
                                              'MaxItems': '100'})
                f = facade()
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk) as get:
                    result = await discover_associations(
                        f, object(), REGION, 'CLOUDFRONT', WAF_GLOBAL)
                    get.assert_called_once_with('cloudfront', f.session, REGION)
                stub.assert_no_pending_responses()
            assert result['association_status'] == 'unused_candidate'
            assert result['checked_resource_types'] == ['CLOUDFRONT']
        finally:
            sdk.close()
    asyncio.run(scenario())


def test_cloudfront_paginated_positive_results_preserve_identity_only():
    async def scenario():
        first = {'Id': 'D123EXAMPLE', 'ARN': CF_ARN,
                 'WebACLId': WAF_GLOBAL,
                 'DomainName': 'dexample.cloudfront.net', 'Status': 'Deployed',
                 'Origins': {'Items': [{'DomainName': 'secret.origin.invalid'}]}}
        second = {'Id': 'D456EXAMPLE',
                  'ARN': CF_ARN.replace('D123EXAMPLE', 'D456EXAMPLE'),
                  'WebACLId': WAF_GLOBAL,
                  'DomainName': 'danother.cloudfront.net', 'Status': 'InProgress'}
        sdk = Mock()
        sdk.list_distributions_by_web_acl_id.side_effect = [
            cf_page([first], truncated=True),
            cf_page([second], truncated=False, marker='next')]
        f = facade()
        with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
            result = await discover_associations(
                f, object(), REGION, 'CLOUDFRONT', WAF_GLOBAL)
        assert sdk.list_distributions_by_web_acl_id.call_args_list == [
            call(WebACLId=WAF_GLOBAL, MaxItems='100'),
            call(WebACLId=WAF_GLOBAL, MaxItems='100', Marker='next')]
        assert result['association_status'] == 'associated'
        assert result['association_scope_complete'] is True
        assert result['associated_resource_count'] == 2
        data = json.dumps(result)
        assert CF_ARN in data and 'danother.cloudfront.net' in data
        assert 'secret.origin.invalid' not in data
        f.issue.assert_not_called()
    asyncio.run(scenario())


def test_cloudfront_missing_token_and_denied_never_yield_unused_candidate():
    async def scenario():
        for response in [
            {'DistributionList': {'Marker': '', 'MaxItems': 100,
                                  'IsTruncated': True, 'Quantity': 0, 'Items': []}},
            {'DistributionList': {'Marker': '', 'MaxItems': 100,
                                  'IsTruncated': False, 'Quantity': 1, 'Items': []}},
        ]:
            sdk = Mock()
            sdk.list_distributions_by_web_acl_id.return_value = response
            f = facade()
            with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                result = await discover_associations(
                    f, object(), REGION, 'CLOUDFRONT', WAF_GLOBAL)
            assert result['association_status'] == 'unknown'
            assert result['unknown_resource_types'] == ['CLOUDFRONT']
            assert f.issue.call_count == 1
        sdk = make_client('cloudfront')
        try:
            with Stubber(sdk) as stub:
                stub.add_client_error(
                    'list_distributions_by_web_acl_id',
                    service_error_code='AccessDenied',
                    http_status_code=403,
                    expected_params={'WebACLId': WAF_GLOBAL, 'MaxItems': '100'})
                f = facade()
                with patch.object(AWSFacadeUtils, 'get_client', return_value=sdk):
                    result = await discover_associations(
                        f, object(), REGION, 'CLOUDFRONT', WAF_GLOBAL)
                stub.assert_no_pending_responses()
            assert result['association_status'] == 'unknown'
            assert f.issue.call_args.args[0] == 'partial'
        finally:
            sdk.close()
    asyncio.run(scenario())


def test_unpaginated_regional_response_is_bounded_and_partial():
    async def scenario():
        sdk = Mock()
        sdk.list_resources_for_web_acl.side_effect = [
            {'ResourceArns': [ALB, API_STAGE, CF_ARN]}
        ] + [{'ResourceArns': []}] * (len(REGIONAL_TYPES) - 1)
        f = facade()
        with patch('ScoutSuite.providers.aws.facade.wafv2_associations.MAX_ASSOCIATIONS_PER_TYPE', 2):
            result = await discover_associations(
                f, sdk, 'eu-central-1', 'REGIONAL', WAF_REGIONAL)
        assert result['association_status'] == 'associated'
        assert result['association_scope_complete'] is False
        assert result['associated_resource_count'] == 2
        assert result['unknown_resource_types'] == ['APPLICATION_LOAD_BALANCER']
        assert any('AssociationLimit' in c.args[1] for c in f.issue.call_args_list)
    asyncio.run(scenario())


def test_evidence_rule_and_normalized_resource_are_scope_aware(tmp_path):
    p = WebACLs.__new__(WebACLs)
    p.region = 'eu-central-1'
    row = {
        'name': 'source-acl', 'id': 'synthetic-id', 'arn': WAF_REGIONAL,
        'scope': 'REGIONAL', 'region': 'eu-central-1',
        'rules': [], 'default_action': {'Allow': {}},
        'managed_by_firewall_manager': False,
        'association_status': 'unused_candidate',
        'association_scope_complete': True, 'associated_resources': [],
        'checked_resource_types': list(REGIONAL_TYPES),
        'unknown_resource_types': [],
    }
    _, unused = p._normalize(row)
    assert unused['unused_candidate'] is True
    _, attached = p._normalize(dict(row, association_status='associated',
                                   associated_resources=[
                                       {'resource_type': 'APPLICATION_LOAD_BALANCER',
                                        'resource_arn': ALB}]))
    assert attached['associated_resources'][0]['resource_arn'] == ALB
    _, unknown = p._normalize(dict(row, association_status='unknown',
                                   association_scope_complete=False,
                                   unknown_resource_types=['API_GATEWAY']))
    assert unknown['unused_candidate'] is False
    for example, expected in [(unused, 'insecure'), (attached, 'secure'),
                              (unknown, 'unknown'), ({}, 'unknown')]:
        assert classify_wafv2_association(example) == expected
    rules = {'about': 'M10-K synthetic', 'rules': {
        'wafv2-web-acl-unassociated.json': [{'enabled': True, 'level': 'warning'}]}}
    file = tmp_path / 'm10k.json'
    file.write_text(json.dumps(rules), encoding='utf-8')
    provider = SimpleNamespace(
        services={'wafv2': {'regions': {'eu-central-1': {'web_acls': {
            'unused': unused, 'attached': attached, 'unknown': unknown}}}}},
        service_list=['wafv2'])
    ctx = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(file))).run(provider)
        finding = provider.services['wafv2']['findings']['wafv2-web-acl-unassociated']
        assert finding['flagged_items'] == 1
        assert finding['assessment_status'] == 'incomplete'
        assert finding['evaluation_summary']['counts'] == {
            'secure': 1, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
    finally:
        ctx.cleanup()


def test_template_escapes_identifiers_and_does_not_render_raw_config():
    template = (ROOT / 'ScoutSuite/output/data/html/partials/aws/'
                'services.wafv2.regions.id.web_acls.html').read_text()
    assert '{{resource_arn}}' in template and '{{domain_name}}' in template
    assert 'associated_resources' in template
    assert '{{{' not in template and 'onclick=' not in template
    assert 'javascript:' not in template
