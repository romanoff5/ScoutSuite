"""RC9: rule paths must address real service keys; empty means "not in use" only when collected.

Synthetic identifiers only; strict Stubber for the SDK boundary.
"""
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import boto3
from botocore.stub import Stubber

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.codebuild import CodeBuild
from ScoutSuite.providers.aws.facade.directconnect import DirectConnectFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.provider import AWSProvider
from ScoutSuite.providers.base.provider import BaseProvider

ROOT = Path(__file__).resolve().parents[1]
AWS = ROOT / 'ScoutSuite/providers/aws'
REGION = 'eu-central-1'


def sdk(service):
    return boto3.client(service, region_name=REGION, aws_access_key_id='synthetic',
                        aws_secret_access_key='synthetic')


def in_context(scenario):
    async def wrapper():
        ctx = RunContext('aws').setup()
        try:
            return await scenario(), list(ctx.collection_issues)
        finally:
            await ctx.aclose()
    return asyncio.run(wrapper())


def aws_service_keys():
    metadata = json.loads((AWS / 'metadata.json').read_text(encoding='utf-8'))
    return {service for group in metadata.values() for service in group}


def test_every_aws_rule_path_starts_with_a_report_service_key():
    """The Lambda runtime rule addressed 'lambda.' while the report key is 'awslambda'."""
    services = aws_service_keys()
    assert 'awslambda' in services and 'lambda' not in services
    checked = 0
    for path in (AWS / 'rules/findings').glob('*.json'):
        rule = json.loads(path.read_text(encoding='utf-8'))
        for key in ('path', 'display_path'):
            if key in rule:
                assert rule[key].split('.')[0] in services, (path.name, key, rule[key])
                checked += 1
    assert checked > 200


def test_lambda_runtime_rule_flags_function_under_real_service_key(tmp_path):
    from ScoutSuite.core.processingengine import ProcessingEngine
    from ScoutSuite.core.ruleset import Ruleset
    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps({'about': 'Synthetic RC9', 'rules': {
        'awslambda-function-deprecated-runtime.json': [{'enabled': True, 'level': 'warning'}]}}), encoding='utf-8')
    functions = {
        'old': {'runtime_lifecycle_status': 'deprecated', 'runtime': 'python3.8', 'package_type': 'Zip'},
        'new': {'runtime_lifecycle_status': 'supported', 'runtime': 'python3.13', 'package_type': 'Zip'}}
    provider = SimpleNamespace(services={'awslambda': {'regions': {REGION: {'functions': functions}}}},
                               service_list=['awslambda'])
    context = RunContext('aws').setup()
    try:
        ProcessingEngine(Ruleset('aws', filename=str(rules))).run(provider)
    finally:
        context.cleanup()
    finding = provider.services['awslambda']['findings']['awslambda-function-deprecated-runtime']
    assert finding['items'] == ['awslambda.regions.%s.functions.old.runtime_lifecycle_status' % REGION]
    assert finding['checked_items'] == 2 and finding['flagged_items'] == 1


def summary_for(services, issues, provider_class=BaseProvider):
    provider = SimpleNamespace(services=services, collection_status={'issues': issues},
                               COLLECTION_SCOPE_ALIASES=provider_class.COLLECTION_SCOPE_ALIASES)
    BaseProvider._update_last_run(provider, datetime(2026, 11, 3, tzinfo=timezone.utc),
                                  SimpleNamespace(name='synthetic', about='synthetic'), {})
    return provider.last_run['summary']


def test_zero_rule_empty_services_are_not_in_use_unless_collection_failed():
    services = {'codebuild': {'regions': {}, 'projects_count': 0},
                'emr': {'regions': {}, 'clusters_count': 0},
                'secretsmanager': {'regions': {}, 'secrets_count': 11},
                'legacy': None}
    issues = [{'status': 'denied', 'scope': 'emr', 'reason_code': 'AccessDenied'}]
    summary = summary_for(services, issues)
    assert summary['codebuild']['status'] == 'not_in_use'
    assert summary['emr']['status'] == 'incomplete'
    assert summary['secretsmanager']['status'] == 'not_assessed'  # Resources but nothing checks them.
    assert summary['legacy']['status'] == 'not_assessed' and summary['legacy']['collected'] is False


def test_sdk_client_scopes_are_attributed_to_aws_report_keys():
    services = {'awslambda': {'regions': {}, 'functions_count': 0},
                'networkfirewall': {'regions': {}, 'firewalls_count': 0}}
    issues = [{'status': 'denied', 'scope': 'lambda', 'reason_code': 'AccessDenied'},
              {'status': 'failed', 'scope': 'network-firewall', 'reason_code': 'Timeout'}]
    assert summary_for(services, issues)['awslambda']['status'] == 'not_in_use'  # Base: no AWS aliases.
    summary = summary_for(services, issues, AWSProvider)
    assert summary['awslambda']['collection_issues'] == 1 and summary['awslambda']['status'] == 'incomplete'
    assert summary['networkfirewall']['status'] == 'incomplete'
    assert set(AWSProvider.COLLECTION_SCOPE_ALIASES.values()) <= aws_service_keys()


def test_codebuild_listing_paginates_and_records_failures():
    def run(add, names_only=True):
        async def scenario():
            client = sdk('codebuild')
            facade = CodeBuild(object())
            try:
                with Stubber(client) as stub:
                    add(stub)
                    with patch.object(AWSFacadeUtils, 'get_client', return_value=client), \
                            patch.object(CodeBuild, '_get_project_details',
                                         side_effect=lambda name, region: {'projects': [{'name': name}]}):
                        result = await facade.get_projects(REGION)
                    stub.assert_no_pending_responses()
            finally:
                client.close()
            return result
        return in_context(scenario)

    def two_pages(stub):
        stub.add_response('list_projects', {'projects': ['p-%03d' % i for i in range(100)], 'nextToken': 't1'}, {})
        stub.add_response('list_projects', {'projects': ['p-100']}, {'nextToken': 't1'})
    result, issues = run(two_pages)
    assert len(result) == 101 and issues == []  # The former single call stopped at 100.

    result, issues = run(lambda s: s.add_client_error('list_projects', service_error_code='AccessDeniedException',
                                                      http_status_code=403))
    assert result == [] and issues == [{'status': 'denied', 'scope': 'codebuild', 'reason_code': 'AccessDenied'}]

    result, issues = run(lambda s: s.add_client_error('list_projects', service_error_code='ThrottlingException',
                                                      http_status_code=400))
    assert result == [] and issues == [{'status': 'failed', 'scope': 'codebuild', 'reason_code': 'ListProjectsThrottlingException'}]


def stubbed(service, facade_call, add):
    async def scenario():
        client = sdk(service)
        try:
            with Stubber(client) as stub:
                add(stub)
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    result = await facade_call()
                stub.assert_no_pending_responses()
        finally:
            client.close()
        return result
    return in_context(scenario)


def test_expected_vpc_only_answers_are_not_collection_failures():
    """RC9 field regression: VPC-only accounts answer InvalidParameterValue by design."""
    from ScoutSuite.providers.aws.facade.elasticache import ElastiCacheFacade
    from ScoutSuite.providers.aws.facade.redshift import RedshiftFacade
    result, issues = stubbed('elasticache', lambda: ElastiCacheFacade(object()).get_security_groups(REGION),
                             lambda s: s.add_client_error('describe_cache_security_groups',
                                                          service_error_code='InvalidParameterValue',
                                                          http_status_code=400))
    assert result == [] and issues == []
    result, issues = stubbed('redshift', lambda: RedshiftFacade(object()).get_cluster_security_groups(REGION),
                             lambda s: s.add_client_error('describe_cluster_security_groups',
                                                          service_error_code='InvalidParameterValue',
                                                          http_status_code=400))
    assert result == [] and issues == []


def test_unexpected_paginated_error_is_recorded_once_by_the_caller():
    from ScoutSuite.providers.aws.facade.dynamodb import DynamoDBFacade
    result, issues = stubbed('dynamodb', lambda: DynamoDBFacade(object()).get_tables(REGION),
                             lambda s: s.add_client_error('list_tables', service_error_code='ThrottlingException',
                                                          http_status_code=400))
    assert result == [] and issues == [
        {'status': 'failed', 'scope': 'dynamodb', 'reason_code': 'ListTablesThrottlingException'}]


def test_direct_connect_listing_failure_is_recorded_without_message():
    async def scenario():
        client = sdk('directconnect')
        try:
            with Stubber(client) as stub:
                stub.add_client_error('describe_connections', service_error_code='AccessDeniedException',
                                      service_message='secret-looking arn:aws:iam::000000000000:role/x',
                                      http_status_code=403)
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    return await DirectConnectFacade(object()).get_connections(REGION)
        finally:
            client.close()
    result, issues = in_context(scenario)
    assert result == []
    assert issues == [{'status': 'denied', 'scope': 'directconnect',
                       'reason_code': 'DescribeConnectionsAccessDeniedException'}]
    assert 'arn:' not in json.dumps(issues)
