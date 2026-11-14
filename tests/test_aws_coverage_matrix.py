"""AWS evidence coverage matrix: no false PASS on missing or denied data."""
import asyncio
import json
from types import SimpleNamespace

from botocore.hooks import HierarchicalEmitter

from ScoutSuite.core.run_context import RunContext
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.providers.aws.coverage_matrix import build_aws_coverage_matrix
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.base.services import BaseServicesConfig


def _row(matrix, service, region):
    return next(x for x in matrix['rows']
                if x['service'] == service and x['region'] == region)


def test_api_event_capture_is_scoped_bounded_and_payload_free():
    fake_client = SimpleNamespace(meta=SimpleNamespace(
        events=HierarchicalEmitter(), region_name='eu-central-1'))
    session = SimpleNamespace(client=lambda service, **kwargs: fake_client)
    ctx = RunContext(provider='aws')
    with ctx.lifecycle():
        one = AWSFacadeUtils.get_client('s3', session, 'eu-central-1')
        two = AWSFacadeUtils.get_client('s3', session, 'eu-central-1')
        assert one is two
        response = SimpleNamespace(status_code=200)
        fake_client.meta.events.emit('after-call.s3.ListBuckets',
                                     http_response=response, parsed={'Secret':'DO_NOT_STORE'})
        response.status_code = 404
        fake_client.meta.events.emit(
            'after-call.s3.GetBucketEncryption', http_response=response,
            parsed={'Error': {'Code': 'ServerSideEncryptionConfigurationNotFoundError'}})
        response.status_code = 403
        fake_client.meta.events.emit('after-call.s3.GetBucketPolicy',
                                     http_response=response,
                                     parsed={'Error': {'Code': 'AccessDenied',
                                                       'Message': 'DO_NOT_STORE'}})
        snapshot = ctx.aws_telemetry_snapshot()
    outcomes = snapshot['api'][('s3', 'eu-central-1')]
    assert outcomes['success'] == 1
    assert outcomes['absent'] == 1
    assert outcomes['denied'] == 1
    assert outcomes['operations']['ListBuckets']['success'] == 1
    assert 'DO_NOT_STORE' not in json.dumps(outcomes)


def test_region_specific_denial_does_not_spread_to_other_regions():
    ctx = RunContext(provider='aws')
    ctx.record_aws_api('ec2', 'eu-central-1', 'DescribeInstances', 'success')
    ctx.record_aws_api('ec2', 'eu-west-1', 'DescribeInstances', 'success')
    ctx.record_evidence_observation('ec2', 'eu-central-1',
        'ec2.regions.eu-central-1.instances.i1', 'secure')
    ctx.record_evidence_observation('ec2', 'eu-west-1',
        'ec2.regions.eu-west-1.instances.i1', 'secure')
    ctx.record_collection_issue('denied', 'ec2', 'DescribeSecurityGroups',
                                region='eu-west-1')
    data = {'ec2': {'regions': {
        'eu-central-1': {'instances_count': 1},
        'eu-west-1': {'instances_count': 1}
    }, 'findings': {}}}
    matrix = build_aws_coverage_matrix(['ec2'], data, ctx)
    safe = _row(matrix, 'ec2', 'eu-central-1')
    denied = _row(matrix, 'ec2', 'eu-west-1')
    assert safe['status'] == 'OBSERVED_COMPLETE'
    assert safe['collection_issues'] == []
    assert safe['checked_resources'] == 1
    assert safe['inventory_records_observed'] == 1
    assert denied['status'] == 'PARTIAL'
    assert denied['collection_issues'][0]['region'] == 'eu-west-1'
    assert denied['zero_findings_interpretation'] == 'NOT_VERIFIED_CLEAN'
    assert not matrix['clean_result_verified']


def test_legacy_unscoped_error_conservatively_affects_all_regions():
    ctx = RunContext(provider='aws')
    ctx.record_aws_api('logs', 'eu-central-1', 'DescribeLogGroups', 'success')
    ctx.record_evidence_observation('cloudwatch', 'eu-central-1',
        'cloudwatch.regions.eu-central-1.log_groups.l1', 'secure')
    ctx.record_collection_issue('partial', 'cloudwatch', 'LegacyUnscopedError')
    data = {'cloudwatch': {'regions': {
        'eu-central-1': {'log_groups_count': 1},
        'eu-west-1': {'log_groups_count': 0}}}}
    matrix = build_aws_coverage_matrix(['cloudwatch'], data, ctx)
    assert all(row['status'] in ('PARTIAL', 'UNKNOWN')
               for row in matrix['rows'])
    assert all(row['issues_without_region'] for row in matrix['rows'])
    assert _row(matrix, 'cloudwatch', 'eu-central-1')['api']['success'] == 1


def test_explicit_skips_and_incomplete_zero_finding_are_distinct():
    ctx = RunContext(provider='aws')
    ctx.record_aws_api('rds', 'eu-central-1', 'DescribeDBInstances', 'denied')
    data = {'rds': {'regions': {'eu-central-1': {'instances_count': 0}}},
            'ec2': {'regions': {}}}
    matrix = build_aws_coverage_matrix(
        ['rds', 'ec2'], data, ctx, requested_regions=['eu-central-1'],
        skipped_services=['s3'], enabled_rule_counts={'s3': 13})
    assert _row(matrix, 'rds', 'eu-central-1')['status'] == 'DENIED'
    assert _row(matrix, 'ec2', 'eu-central-1')['status'] == 'UNKNOWN'
    skip = _row(matrix, 's3', 'not_scanned')
    assert skip['status'] == 'SKIPPED'
    assert skip['skipped_checks'] == 13
    assert skip['api']['success'] == 0
    assert skip['inventory_records_observed'] is None
    assert all(row['zero_findings_interpretation'] == 'NOT_VERIFIED_CLEAN'
               for row in matrix['rows'])


def test_empty_api_or_no_policy_checks_cannot_mean_complete():
    ctx = RunContext(provider='aws')
    ctx.record_aws_api('iam', 'global', 'ListRoles', 'success')
    data = {'iam': {'users_count': 0, 'findings': {}}}
    matrix = build_aws_coverage_matrix(['iam'], data, ctx)
    row = _row(matrix, 'iam', 'global')
    assert row['status'] == 'NOT_ASSESSED'
    assert row['checked_resources'] == 0
    assert row['zero_findings_interpretation'] == 'NOT_VERIFIED_CLEAN'
    assert not matrix['complete']


def test_duplicate_policy_evaluation_paths_not_counted_as_new_resources():
    ctx = RunContext(provider='aws')
    path = 'rds.regions.eu-central-1.proxies.p1'
    ctx.record_aws_api('rds', 'eu-central-1', 'DescribeDBProxyTargets', 'success')
    ctx.record_evidence_observation('rds', 'eu-central-1', path, 'secure')
    ctx.record_evidence_observation('rds', 'eu-central-1', path, 'secure')
    ctx.record_evidence_observation('rds', 'eu-central-1', path, 'unknown')
    data = {'rds': {'regions': {'eu-central-1': {'proxies_count': 1}}}}
    row = _row(build_aws_coverage_matrix(['rds'], data, ctx), 'rds', 'eu-central-1')
    assert row['checked_resources'] == 1
    assert row['unknown_resources'] == 1
    assert row['status'] == 'PARTIAL'


def test_rule_evidence_unknown_is_assigned_to_actual_region():
    ctx = RunContext(provider='aws')
    services = {'rds': {'regions': {
        'eu-central-1': {'proxies': {'one': {'target_health_status': 'healthy'}}},
        'eu-west-1': {'proxies': {'two': {'target_health_status': 'unknown'}}}
    }}}
    rule = SimpleNamespace(
        evidence_policy='rds-proxy-targets-empty-v1',
        filename='rds-proxy-no-registered-targets.json',
        path='rds.regions.id.proxies.id')
    with ctx.lifecycle():
        summary = evaluate_rule_evidence(rule, services)
        assert summary['counts']['secure'] == 1
        assert summary['counts']['unknown'] == 1
        assert ctx.collection_issues == [{
            'status': 'partial', 'scope': 'rds',
            'reason_code': 'RuleEvidenceUnknown', 'region': 'eu-west-1'
        }]
        ctx.record_aws_api('rds', 'eu-central-1', 'DescribeDBProxies', 'success')
        ctx.record_aws_api('rds', 'eu-west-1', 'DescribeDBProxies', 'success')
        matrix = build_aws_coverage_matrix(['rds'], services, ctx)
    assert _row(matrix, 'rds', 'eu-central-1')['status'] == 'OBSERVED_COMPLETE'
    assert _row(matrix, 'rds', 'eu-west-1')['status'] == 'PARTIAL'


def test_service_fetch_exception_records_gap_without_raising():
    async def broken(**kwargs):
        raise RuntimeError('simulated service fault')
    collector = BaseServicesConfig(None)
    collector.demo = SimpleNamespace(fetch_all=broken)
    ctx = RunContext(provider='aws')
    async def go():
        ctx.setup()
        try:
            await collector._fetch('demo')
            return list(ctx.collection_issues)
        finally:
            await ctx.aclose()
    issues = asyncio.run(go())
    assert issues == [{
        'status': 'failed', 'scope': 'demo',
        'reason_code': 'ServiceFetchFailed'
    }]


def test_context_isolation_across_assessments():
    first = RunContext(provider='aws')
    second = RunContext(provider='aws')
    first.record_aws_api('ec2', 'eu-central-1', 'DescribeInstances', 'denied')
    assert not second.aws_telemetry_snapshot()['api']
    assert not second.collection_issues
