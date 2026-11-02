"""M10-Q operational read-only evidence; SDK boundaries are mocked, no AWS/network."""
import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from ScoutSuite.providers.aws.facade.operational_evidence import (
    collect_ecr_images, collect_backup_rpo, collect_waf_traffic
)


class Facade:
    owner_id = '123456789012'
    session = object()

    def __init__(self):
        self.issues = []

    def issue(self, *args):
        self.issues.append(args)

    def failure(self, *args, **kwargs):
        self.issues.append(args)


async def immediate(function):
    return function()


class ECRClient:
    def __init__(self, status='COMPLETE', scanned=True, denied=False):
        self.status, self.scanned, self.denied = status, scanned, denied
        self.calls = []

    def describe_images(self, **kwargs):
        self.calls.append(('describe_images', kwargs))
        return {'imageDetails': [{
            'imageDigest': 'sha256:' + 'a' * 64, 'imageTags': ['latest'],
            'imageStatus': 'ACTIVE', 'imagePushedAt': datetime.now(timezone.utc) - timedelta(days=1)}]}

    def describe_image_scan_findings(self, **kwargs):
        self.calls.append(('scan', kwargs))
        if self.denied:
            raise RuntimeError('AccessDenied')
        return {'registryId': '123456789012', 'repositoryName': 'app',
                'imageId': kwargs['imageId'], 'imageScanStatus': {'status': self.status},
                'imageScanFindings': {
                    'imageScanCompletedAt': datetime.now(timezone.utc) if self.scanned else None,
                    'findingSeverityCounts': {'CRITICAL': 1},
                    'findings': [{'private_object': 'should never be copied'}]}}


def test_each_ecr_digest_has_individual_successful_scan_evidence():
    facade, client = Facade(), ECRClient()
    with patch('ScoutSuite.providers.aws.facade.operational_evidence.AWSFacadeUtils.get_client',
               return_value=client), patch(
               'ScoutSuite.providers.aws.facade.operational_evidence.run_concurrently', immediate):
        evidence = asyncio.run(collect_ecr_images(facade, 'eu-west-1', 'app'))
    assert evidence['status'] == 'verified'
    assert evidence['image_level_scan_execution_verified']
    assert evidence['total_images'] == evidence['verified_images'] == 1
    assert len([c for c in client.calls if c[0] == 'scan']) == 1
    assert 'findings' not in str(evidence)
    assert client.calls[1][1]['imageId']['imageDigest'] == 'sha256:' + 'a' * 64


def test_failed_or_denied_scan_is_never_success():
    for client in (ECRClient(status='FAILED'), ECRClient(denied=True),
                   ECRClient(scanned=False)):
        facade = Facade()
        with patch('ScoutSuite.providers.aws.facade.operational_evidence.AWSFacadeUtils.get_client',
                   return_value=client), patch(
                   'ScoutSuite.providers.aws.facade.operational_evidence.run_concurrently', immediate):
            evidence = asyncio.run(collect_ecr_images(facade, 'eu-west-1', 'app'))
        assert not evidence['image_level_scan_execution_verified']
        assert evidence['status'] in ('gap_observed', 'unknown')


def test_ecr_pagination_cycle_never_reports_complete_census():
    class Cyclic(ECRClient):
        def describe_images(self, **kwargs):
            return {'imageDetails': [], 'nextToken': 'cycle'}
    facade = Facade()
    with patch('ScoutSuite.providers.aws.facade.operational_evidence.AWSFacadeUtils.get_client',
               return_value=Cyclic()), patch(
               'ScoutSuite.providers.aws.facade.operational_evidence.run_concurrently', immediate):
        evidence = asyncio.run(collect_ecr_images(facade, 'eu-west-1', 'app'))
    assert not evidence['census_complete']
    assert evidence['status'] == 'unknown'


class CloudWatchClient:
    def __init__(self, traffic):
        self.traffic = traffic
        self.queries = None

    def get_metric_data(self, **kwargs):
        self.queries = kwargs
        return {'MetricDataResults': [
            {'Id': 'm' + str(i), 'StatusCode': 'Complete',
             'Values': [self.traffic if i == 0 else 0.0]}
            for i in range(5)]}


def test_waf_metrics_verify_observed_requests_not_full_routing():
    for count in (0, 12):
        client, facade = CloudWatchClient(count), Facade()
        with patch('ScoutSuite.providers.aws.facade.operational_evidence.AWSFacadeUtils.get_client',
                   return_value=client), patch(
                   'ScoutSuite.providers.aws.facade.operational_evidence.run_concurrently', immediate):
            evidence = asyncio.run(collect_waf_traffic(facade, 'eu-central-1', {
                'scope': 'REGIONAL', 'visibility_config': {
                    'CloudWatchMetricsEnabled': True, 'MetricName': 'web-acl'}}))
        assert evidence['requests_observed'] is (count > 0)
        assert evidence['status'] == ('observed' if count else 'unknown')
        assert client.queries['MetricDataQueries'][0]['MetricStat']['Metric']['Dimensions'][2] == {
            'Name': 'Region', 'Value': 'eu-central-1'}
        assert 'request_ips' not in str(evidence)


class BackupClient:
    def __init__(self, status='AVAILABLE'):
        self.status = status

    def list_recovery_points_by_resource(self, **kwargs):
        return {'RecoveryPoints': [{
            'RecoveryPointArn': 'arn:aws:backup:eu-west-1:123456789012:recovery-point:a',
            'BackupVaultName': 'vault-1', 'Status': self.status,
            'CreationDate': datetime.now(timezone.utc) - timedelta(minutes=5)}]}


def test_backup_rpo_requires_configured_objective_and_never_claims_continuous(monkeypatch):
    arn = 'arn:aws:s3:::my-bucket'
    facade = Facade()
    monkeypatch.delenv('SCOUTSUITE_BACKUP_RPO_MINUTES', raising=False)
    with patch('ScoutSuite.providers.aws.facade.operational_evidence.AWSFacadeUtils.get_client',
               return_value=BackupClient()), patch(
               'ScoutSuite.providers.aws.facade.operational_evidence.run_concurrently', immediate):
        no_target = asyncio.run(collect_backup_rpo(facade, 'eu-west-1', [arn], []))
        monkeypatch.setenv('SCOUTSUITE_BACKUP_RPO_MINUTES', '30')
        observed = asyncio.run(collect_backup_rpo(facade, 'eu-west-1', [arn], []))
    assert no_target['resources'][arn]['state'] == 'unknown'
    assert observed['resources'][arn]['state'] == 'fresh_point_observed'
    assert not observed['continuous_compliance_verified']


def test_stopped_backup_and_denied_recovery_history():
    arn = 'arn:aws:s3:::my-bucket'
    facade = Facade()
    with patch('ScoutSuite.providers.aws.facade.operational_evidence.AWSFacadeUtils.get_client',
               return_value=BackupClient(status='STOPPED')), patch(
               'ScoutSuite.providers.aws.facade.operational_evidence.run_concurrently', immediate):
        output = asyncio.run(collect_backup_rpo(facade, 'eu-west-1', [arn], []))
    assert output['resources'][arn]['state'] == 'gap_observed'
    class Denied:
        def list_recovery_points_by_resource(self, **kwargs):
            raise RuntimeError('AccessDenied')
    with patch('ScoutSuite.providers.aws.facade.operational_evidence.AWSFacadeUtils.get_client',
               return_value=Denied()), patch(
               'ScoutSuite.providers.aws.facade.operational_evidence.run_concurrently', immediate):
        failed = asyncio.run(collect_backup_rpo(facade, 'eu-west-1', [arn], []))
    assert failed['resources'][arn]['state'] == 'unknown'
    assert not failed['resources'][arn]['census_complete']
