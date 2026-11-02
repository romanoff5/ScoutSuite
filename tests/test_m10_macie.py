"""M10-P Macie: SDK contracts, pagination, completeness and no sensitive APIs."""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.macie import (
    MacieFacade, PAGE_SIZE, PageRows, STALE_DAYS, bucket_coverage)
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.macie.base import MaciePublic

REGION = 'us-east-1'
ACCOUNT = '000000000000'
BUCKET = 'company-data'
ARN = 'arn:aws:s3:::' + BUCKET
JOB = 'classification-job-1'
NOW = datetime(2026, 11, 2, tzinfo=timezone.utc)


def sdk():
    return boto3.client('macie2', region_name=REGION,
                        aws_access_key_id='synthetic', aws_secret_access_key='synthetic')


def test_sdk_models_only_read_config_and_bucket_metadata():
    model = get_session().get_service_model('macie2')
    operations = {
        'GetMacieSession', 'GetAutomatedDiscoveryConfiguration', 'GetClassificationScope',
        'ListClassificationJobs', 'DescribeClassificationJob', 'DescribeBuckets'}
    assert operations <= set(model.operation_names)
    for operation in ('ListClassificationJobs', 'DescribeBuckets'):
        members = model.operation_model(operation).input_shape.members
        assert {'maxResults', 'nextToken'} <= set(members)
    assert 'jobId' in model.operation_model('DescribeClassificationJob').input_shape.required_members
    assert 'id' in model.operation_model('GetClassificationScope').input_shape.required_members


def test_stubber_full_read_only_flow_and_pagination():
    async def scenario():
        client = sdk()
        try:
            with Stubber(client) as stub:
                stub.add_response('get_macie_session', {'status': 'ENABLED'}, {})
                stub.add_response('get_automated_discovery_configuration', {
                    'status': 'ENABLED', 'classificationScopeId': 'scope-1'}, {})
                stub.add_response('get_classification_scope', {
                    'id': 'scope-1', 's3': {'excludes': {'bucketNames': ['audit-logs']}}},
                    {'id': 'scope-1'})
                stub.add_response('list_classification_jobs', {
                    'items': [{'jobId': JOB, 'name': 'daily', 'jobStatus': 'IDLE',
                               'jobType': 'SCHEDULED'}],
                    'nextToken': 'second-page'}, {'maxResults': PAGE_SIZE})
                stub.add_response('list_classification_jobs', {
                    'items': []}, {'maxResults': PAGE_SIZE, 'nextToken': 'second-page'})
                stub.add_response('describe_classification_job', {
                    'jobId': JOB, 'name': 'daily', 'jobType': 'SCHEDULED',
                    'jobStatus': 'IDLE', 'lastRunTime': NOW - timedelta(days=7),
                    'statistics': {'numberOfRuns': 10},
                    's3JobDefinition': {'bucketDefinitions': [
                        {'accountId': ACCOUNT, 'buckets': [BUCKET]}]}},
                    {'jobId': JOB})
                stub.add_response('describe_buckets', {
                    'buckets': [{'bucketName': BUCKET, 'accountId': ACCOUNT,
                                 'bucketArn': ARN,
                                 'automatedDiscoveryMonitoringStatus': 'MONITORED',
                                 'jobDetails': {'isDefinedInJob': 'TRUE',
                                                'isMonitoredByJob': 'TRUE',
                                                'lastJobId': JOB,
                                                'lastJobRunTime': NOW - timedelta(days=7)},
                                 'classifiableObjectCount': 10}],
                    'nextToken': 'b2'}, {'maxResults': PAGE_SIZE})
                stub.add_response('describe_buckets', {
                    'buckets': []}, {'maxResults': PAGE_SIZE, 'nextToken': 'b2'})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    result = await MacieFacade(object()).get_region(REGION)
                stub.assert_no_pending_responses()
        finally:
            client.close()
        assert result['session_status'] == 'ENABLED'
        assert result['automated_discovery_status'] == 'ENABLED'
        assert result['excluded_bucket_names'] == ['audit-logs']
        assert result['jobs_complete'] and result['buckets_complete']
        assert result['jobs'][0]['job_id'] == JOB
        assert result['jobs'][0]['number_of_runs'] == 10
        assert result['buckets'][0]['bucket_arn'] == ARN
        assert result['buckets'][0]['last_job_id'] == JOB
        assert 'GetFindings' not in json.dumps(result)
        assert 'sensitiveData' not in json.dumps(result)
    asyncio.run(scenario())


def test_not_enabled_is_distinct_from_denied():
    async def scenario():
        client = sdk()
        ctx = RunContext('aws').setup()
        try:
            with Stubber(client) as stub:
                stub.add_client_error('get_macie_session',
                                      service_error_code='ResourceNotFoundException',
                                      http_status_code=404, expected_params={})
                stub.add_client_error('get_macie_session',
                                      service_error_code='AccessDeniedException',
                                      http_status_code=403, expected_params={})
                with patch.object(AWSFacadeUtils, 'get_client', return_value=client):
                    facade = MacieFacade(object())
                    missing = await facade.get_region(REGION)
                    denied = await facade.get_region(REGION)
                stub.assert_no_pending_responses()
            assert missing['session_verified'] is True
            assert missing['session_status'] == 'NOT_ENABLED'
            assert denied['session_verified'] is False
            assert denied['session_status'] == 'UNKNOWN'
            assert any(issue['scope'] == 'macie' and issue['status'] == 'denied'
                       for issue in ctx.collection_issues)
        finally:
            await ctx.aclose()
            client.close()
    asyncio.run(scenario())


def test_pages_repeated_token_and_denied_bucket_inventory():
    async def scenario():
        now = {'count': 0}
        def broken(**params):
            now['count'] += 1
            return {'items': [], 'nextToken': 'same'}
        ctx = RunContext('aws').setup()
        try:
            facade = MacieFacade(object())
            results = await facade._pages(broken, 'items', 'ListClassificationJobs')
            assert now['count'] == 2
            assert results.complete is False
            assert any(issue['reason_code'] == 'ListClassificationJobsInvalidPaginationToken'
                       for issue in ctx.collection_issues)
            bad = await facade._pages(lambda **params: {'buckets': 'bad'},
                                      'buckets', 'DescribeBuckets')
            assert bad.complete is False
        finally:
            await ctx.aclose()
    asyncio.run(scenario())


def test_bucket_coverage_is_activity_not_classification_success():
    recent = NOW - timedelta(days=5)
    stale = NOW - timedelta(days=STALE_DAYS + 2)
    base = {'jobDetails': {'isMonitoredByJob': 'TRUE'},
            'automatedDiscoveryMonitoringStatus': 'MONITORED'}
    assert bucket_coverage({**base, 'lastAutomatedDiscoveryTime': recent},
                           'ENABLED', 'ENABLED', now=NOW) == 'RECENT_ACTIVITY'
    assert bucket_coverage({**base, 'jobDetails': {'lastJobRunTime': stale}},
                           'ENABLED', 'DISABLED', now=NOW) == 'STALE_ACTIVITY'
    assert bucket_coverage(base, 'ENABLED', 'ENABLED', now=NOW) == 'NO_RECENT_ACTIVITY_EVIDENCE'
    assert bucket_coverage({**base, 'errorCode': 'ACCESS_DENIED'},
                           'ENABLED', 'ENABLED', now=NOW) == 'ERROR'
    assert bucket_coverage(base, 'UNKNOWN', 'UNKNOWN', now=NOW) == 'UNKNOWN'
    assert bucket_coverage({'jobDetails': {'isMonitoredByJob': 'FALSE',
                                          'isDefinedInJob': 'FALSE'}},
                           'ENABLED', 'DISABLED', now=NOW) == 'NO_MONITORING_CONFIGURED'


def test_resource_normalization_scheduled_vs_one_time_and_incomplete():
    async def scenario():
        raw = {
            'session_status': 'ENABLED', 'session_verified': True,
            'automated_discovery_status': 'DISABLED',
            'automated_discovery_verified': True,
            'jobs_complete': False, 'buckets_complete': True,
            'jobs': [
                {'job_id': 'old-recurring', 'name': 'recurring', 'type': 'SCHEDULED',
                 'last_run_at': '2025-01-01T00:00:00+00:00'},
                {'job_id': 'one-time', 'name': 'one time', 'type': 'ONE_TIME',
                 'last_run_at': '2025-01-01T00:00:00+00:00'}],
            'buckets': [
                {'bucket_name': BUCKET, 'account_id': ACCOUNT, 'coverage_status': 'ERROR',
                 'error_code': 'ACCESS_DENIED', 'review_required': True}],
        }
        facade = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]),
            macie=SimpleNamespace(get_region=AsyncMock(return_value=raw)))
        service = MaciePublic(facade)
        await service.fetch_all(regions=[REGION])
        region = service['regions'][REGION]
        assert service['regions_count'] == 1 and service['jobs_count'] == 2
        assert service['buckets_count'] == 1
        assert region['coverage_assessment_status'] == 'incomplete'
        assert region['jobs'][next(k for k, v in region['jobs'].items()
                                   if v['job_id'] == 'old-recurring')]['stale'] is True
        assert region['jobs'][next(k for k, v in region['jobs'].items()
                                   if v['job_id'] == 'one-time')]['stale'] is False
        bucket = next(iter(region['buckets'].values()))
        assert bucket['bucket_name'] == BUCKET and bucket['id'].startswith('scoutid-')
    asyncio.run(scenario())


def test_metadata_templates_and_privacy_guards():
    root = Path(__file__).resolve().parents[1]
    metadata = json.loads((root / 'ScoutSuite/providers/aws/metadata.json').read_text())
    assert {'regions', 'jobs', 'buckets'} <= set(metadata['security']['macie']['resources'])
    for name in ('services.macie.regions.html', 'services.macie.regions.id.jobs.html',
                 'services.macie.regions.id.buckets.html'):
        text = (root / 'ScoutSuite/output/data/html/partials/aws' / name).read_text()
        assert '{{{' not in text and 'javascript:' not in text and 'onclick=' not in text
        assert 'Handlebars.registerPartial' in text
    source = (root / 'ScoutSuite/providers/aws/facade/macie.py').read_text()
    for forbidden in ('get_findings(', 'get_sensitive_data_occurrences(', 'get_object(',
                      'get_resource_profile('):
        assert forbidden not in source


def test_explicit_no_monitoring_and_failed_job_are_reviewable():
    assert bucket_coverage({'jobDetails': {'isMonitoredByJob': 'FALSE',
                                          'isDefinedInJob': 'FALSE'}},
                           'ENABLED', 'DISABLED', now=NOW) == 'NO_MONITORING_CONFIGURED'


def test_no_classification_configured_requires_verified_complete_inventory():
    async def check(auto, complete):
        raw = {'session_status': 'ENABLED', 'session_verified': True,
               'automated_discovery_status': auto, 'automated_discovery_verified': True,
               'jobs_complete': complete, 'buckets_complete': True,
               'jobs': [], 'buckets': []}
        facade = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]),
            macie=SimpleNamespace(get_region=AsyncMock(return_value=raw)))
        inventory = MaciePublic(facade)
        await inventory.fetch_all(regions=[REGION])
        return inventory['regions'][REGION]['no_classification_configured']
    assert asyncio.run(check('DISABLED', True)) is True
    assert asyncio.run(check('ENABLED', True)) is False
    assert asyncio.run(check('DISABLED', False)) is False
