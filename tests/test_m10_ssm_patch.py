"""M10-O: strict SDK, freshness, denial and report security regression tests."""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import boto3
from botocore.exceptions import ClientError
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import (
    classify_ssm_agent, classify_ssm_critical, classify_ssm_ec2,
    classify_ssm_scan, classify_ssm_security)
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.providers.aws.facade.ssm_patch import (
    SSMPatchFacade, PATCH_STALE_DAYS, PAGE_SIZE, iso)
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.ssm_patch.base import SSMPatchPublic

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)
REGION = 'eu-central-1'
MANAGED = 'i-0123456789abcdef0'
UNMANAGED = 'i-0123456789abcdef1'
BASELINE = 'pb-0123456789abcdef0'
COMMAND_ID = '11111111-1111-4111-8111-111111111111'


def client(service):
    return boto3.client(service, region_name=REGION,
                        aws_access_key_id='synthetic', aws_secret_access_key='synthetic')


def state(critical=0, security=0, age_hours=1):
    return {
        'InstanceId': MANAGED, 'BaselineId': BASELINE, 'PatchGroup': 'servers',
        'Operation': 'Scan', 'OperationStartTime': NOW-timedelta(hours=age_hours, minutes=1),
        'OperationEndTime': NOW-timedelta(hours=age_hours),
        'CriticalNonCompliantCount': critical, 'SecurityNonCompliantCount': security,
        'MissingCount': security, 'FailedCount': 0,
        'InstalledPendingRebootCount': 0, 'InstalledRejectedCount': 0,
        'InstalledCount': 99, 'AvailableSecurityUpdateCount': 0,
    }


def managed_inventory(critical=0, security=0, snapshot_age=1, scan_age=1,
                      scan_known=True, online=True):
    return {
        'instance_id': MANAGED, 'name': 'host-1', 'resource_type': 'EC2Instance',
        'patch_baseline_id': BASELINE, 'patch_group': 'servers',
        'patch_health': ('observed_current' if snapshot_age < 168 and scan_known
                         and scan_age < 168 and online and not (critical or security)
                         else 'stale_or_unverified_scan'),
        'agent_status': 'Online' if online else 'ConnectionLost',
        'agent_online_recent': online, 'agent_connection_lost': not online,
        'agent_version': '3.3.0.0', 'last_agent_ping_at': iso(NOW-timedelta(minutes=5)),
        'patch_state_collection': 'complete', 'patch_details_collection': 'complete',
        'scan_evidence_collection': 'complete', 'patch_observation_complete': True,
        'successful_scan_fresh': scan_known and scan_age < 168,
        'patch_snapshot_fresh': snapshot_age < 168,
        'last_successful_scan_at': iso(NOW-timedelta(hours=scan_age)) if scan_known else None,
        'critical_noncompliant_count': critical, 'missing_security_patch_count': security,
        'patch_counts': {'MissingCount': security, 'FailedCount': 0,
                         'CriticalNonCompliantCount': critical,
                         'SecurityNonCompliantCount': security},
        'missing_patch_details': [], 'scan_evidence': 'confirmed' if scan_known else 'unverified',
    }


def example_inventory(node=None, managed_status='complete'):
    return {
        'baselines': [{'baseline_id': BASELINE, 'name': 'Linux', 'operating_system': 'AMAZON_LINUX',
                       'detail_collection': 'complete', 'details': {}}],
        'patch_groups': [{'PatchGroup': 'servers', 'BaselineIdentity': {'BaselineId': BASELINE}}],
        'managed_nodes': [node] if node is not None else [],
        'ec2_instances': [{'instance_id': MANAGED, 'name': 'managed', 'instance_state': 'running'},
                          {'instance_id': UNMANAGED, 'name': 'unmanaged', 'instance_state': 'running'}],
        'collection': {'managed_nodes': managed_status, 'ec2_instances': 'complete',
                       'baselines': 'complete', 'patch_groups': 'complete'},
    }


def run_resource(value):
    async def scenario():
        facade = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]),
            ssm_patch=SimpleNamespace(inventory=AsyncMock(return_value=value)))
        resources = SSMPatchPublic(facade)
        await resources.fetch_all()
        return resources
    return asyncio.run(scenario())


def test_sdk_has_only_required_read_operations_and_shapes():
    ssm = get_session().get_service_model('ssm')
    for name, output in (
        ('DescribePatchBaselines', 'BaselineIdentities'),
        ('DescribePatchGroups', 'Mappings'),
        ('DescribeInstanceInformation', 'InstanceInformationList'),
        ('DescribeInstancePatchStates', 'InstancePatchStates'),
        ('DescribeInstancePatches', 'Patches'),
        ('ListCommandInvocations', 'CommandInvocations'),
        ('ListCommands', 'Commands'),
    ):
        op = ssm.operation_model(name)
        assert output in op.output_shape.members
        if name not in ('DescribeInstancePatchStates',):
            assert 'NextToken' in op.output_shape.members
    assert 'Parameters' in ssm.operation_model('ListCommands').output_shape.members['Commands'].member.members
    assert 'Operation' in ssm.operation_model('GetPatchBaseline').output_shape.members or (
        'ApprovalRules' in ssm.operation_model('GetPatchBaseline').output_shape.members)
    ec2 = get_session().get_service_model('ec2').operation_model('DescribeInstances')
    assert {'MaxResults', 'NextToken'} <= set(ec2.input_shape.members)


def test_sdk_stubber_confirms_successful_scan_with_explicit_operation_and_ec2_reconciliation():
    async def scenario():
        ssm, ec2 = client('ssm'), client('ec2')
        try:
            with Stubber(ssm) as a, Stubber(ec2) as b:
                a.add_response('describe_patch_baselines', {'BaselineIdentities': [{
                    'BaselineId': BASELINE, 'BaselineName': 'Linux'}]},
                    {'MaxResults': PAGE_SIZE})
                a.add_response('get_patch_baseline', {
                    'BaselineId': BASELINE, 'Name': 'Linux',
                    'ApprovalRules': {'PatchRules': []}}, {'BaselineId': BASELINE})
                a.add_response('describe_patch_groups', {'Mappings': [{
                    'PatchGroup': 'servers', 'BaselineIdentity': {
                        'BaselineId': BASELINE, 'BaselineName': 'Linux'}}]},
                    {'MaxResults': PAGE_SIZE})
                a.add_response('describe_instance_information', {'InstanceInformationList': [{
                    'InstanceId': MANAGED, 'PingStatus': 'Online',
                    'AgentVersion': '3.3.0.0', 'LastPingDateTime': NOW-timedelta(minutes=3),
                    'ResourceType': 'EC2Instance', 'PlatformType': 'Linux',
                    'Name': 'host'}]}, {'MaxResults': PAGE_SIZE})
                a.add_response('describe_instance_patch_states', {
                    'InstancePatchStates': [state()]}, {'InstanceIds': [MANAGED]})
                a.add_response('describe_instance_patches', {'Patches': []}, {
                    'InstanceId': MANAGED, 'MaxResults': PAGE_SIZE,
                    'Filters': [{'Key': 'State', 'Values': [
                        'Missing', 'Failed', 'InstalledPendingReboot', 'InstalledRejected'],
                        'Type': 'Equal'}]})
                a.add_response('list_command_invocations', {'CommandInvocations': [{
                    'CommandId': COMMAND_ID, 'InstanceId': MANAGED,
                    'Status': 'Success', 'DocumentName': 'AWS-RunPatchBaseline',
                    'RequestedDateTime': NOW-timedelta(hours=2),
                    'CommandPlugins': [{
                        'Name': 'runPatchBaseline', 'Status': 'Success',
                        'ResponseFinishDateTime': NOW-timedelta(hours=1, minutes=50)}]
                }]}, {'InstanceId': MANAGED, 'Details': True, 'MaxResults': PAGE_SIZE})
                a.add_response('list_commands', {'Commands': [{
                    'CommandId': COMMAND_ID, 'DocumentName': 'AWS-RunPatchBaseline',
                    'Parameters': {'Operation': ['Scan']}}]}, {'CommandId': COMMAND_ID})
                b.add_response('describe_instances', {'Reservations': [{
                    'Instances': [{'InstanceId': MANAGED, 'State': {'Name': 'running'}}]},
                    {'Instances': [{'InstanceId': UNMANAGED, 'State': {'Name': 'running'}}]}]},
                    {'MaxResults': 1000})
                with patch.object(AWSFacadeUtils, 'get_client',
                                  side_effect=lambda service, *_: ssm if service == 'ssm' else ec2):
                    inventory = await SSMPatchFacade(object()).inventory(REGION, now=NOW)
                a.assert_no_pending_responses()
                b.assert_no_pending_responses()
        finally:
            ssm.close()
            ec2.close()
        node = inventory['managed_nodes'][0]
        assert node['scan_evidence'] == 'confirmed'
        assert node['scan_timestamp_source'] == 'plugin_completion'
        assert node['last_successful_scan_at'] == iso(NOW-timedelta(hours=1, minutes=50))
        assert node['patch_health'] == 'observed_current'
        assert inventory['collection']['managed_nodes'] == 'complete'
        assert len(inventory['ec2_instances']) == 2
        report = run_resource(inventory)
        region = report['regions'][REGION]
        managed = next(iter(region['managed_nodes'].values()))
        assert managed['patch_health'] == 'observed_current'
        assert managed['patch_inventory_complete'] is True
        assert region['unmanaged_running_count'] == 1
        unmanaged = next(item for item in region['ec2_instances'].values()
                         if item['instance_id'] == UNMANAGED)
        assert unmanaged['ssm_coverage_status'] == 'unmanaged_unverified_agent'
        assert unmanaged['running_unmanaged'] is True
    asyncio.run(scenario())


def test_stale_no_success_critical_and_agent_offline_never_misreported_as_patched():
    current = run_resource(example_inventory(managed_inventory(critical=2, security=3)))
    node = next(iter(current['regions'][REGION]['managed_nodes'].values()))
    assert node['critical_noncompliant_count'] == 2
    assert node['missing_security_patch_count'] == 3
    assert classify_ssm_critical(node) == 'insecure'
    assert classify_ssm_security(node) == 'insecure'
    no_scan = run_resource(example_inventory(managed_inventory(scan_known=False)))
    node = next(iter(no_scan['regions'][REGION]['managed_nodes'].values()))
    assert classify_ssm_critical(node) == 'unknown'
    assert classify_ssm_scan(node) == 'insecure'
    stale = run_resource(example_inventory(managed_inventory(scan_age=PATCH_STALE_DAYS*24+1)))
    node = next(iter(stale['regions'][REGION]['managed_nodes'].values()))
    assert classify_ssm_scan(node) == 'insecure'
    offline = run_resource(example_inventory(managed_inventory(online=False)))
    node = next(iter(offline['regions'][REGION]['managed_nodes'].values()))
    assert classify_ssm_agent(node) == 'insecure'
    assert classify_ssm_critical(node) == 'unknown'
    assert classify_ssm_scan({'patch_state_collection': 'partial'}) == 'unknown'


def test_ssm_denied_means_unknown_not_unmanaged_or_clean():
    data = example_inventory(None, managed_status='partial')
    resource = run_resource(data)
    node = next(item for item in resource['regions'][REGION]['ec2_instances'].values()
                if item['instance_id'] == UNMANAGED)
    assert node['ssm_managed'] is None
    assert node['ssm_coverage_status'] == 'unknown'
    assert classify_ssm_ec2(node) == 'unknown'
    assert resource['collection_status'] == 'partial'
    assert classify_ssm_ec2({'ssm_coverage_status': 'managed'}) == 'secure'
    assert classify_ssm_ec2({'ssm_coverage_status': 'not_applicable'}) == 'not_applicable'


def test_pagination_preserves_partial_and_rejects_token_cycles_and_denied():
    async def scenario():
        ssm = Mock()
        ssm.describe_patch_baselines.side_effect = [
            {'BaselineIdentities': [], 'NextToken': 'again'},
            {'BaselineIdentities': [{'BaselineId': BASELINE}], 'NextToken': 'again'}]
        context = RunContext('aws').setup()
        try:
            facade = SSMPatchFacade(object())
            rows, status = await facade.pages(
                ssm, 'describe_patch_baselines', 'BaselineIdentities',
                {'MaxResults': PAGE_SIZE})
            assert status == 'partial'
            assert rows == [{'BaselineId': BASELINE}]
            assert any('InvalidToken' in x['reason_code'] for x in context.collection_issues)
            ssm.describe_patch_baselines.side_effect = [
                {'BaselineIdentities': [{'BaselineId': BASELINE}], 'NextToken': 'next'},
                ClientError({'Error': {'Code': 'AccessDeniedException',
                                       'Message': 'synthetic'}}, 'DescribePatchBaselines')]
            rows, status = await facade.pages(
                ssm, 'describe_patch_baselines', 'BaselineIdentities',
                {'MaxResults': PAGE_SIZE})
            assert status == 'partial'
            assert rows == [{'BaselineId': BASELINE}]
            assert any(x['status'] == 'denied' for x in context.collection_issues)
        finally:
            await context.aclose()
    asyncio.run(scenario())


def test_install_is_not_successful_scan_even_with_successful_invocation():
    async def scenario():
        ssm = Mock()
        ssm.list_command_invocations.return_value = {'CommandInvocations': [{
            'CommandId': COMMAND_ID, 'InstanceId': MANAGED,
            'Status': 'Success', 'DocumentName': 'AWS-RunPatchBaseline',
            'RequestedDateTime': NOW-timedelta(hours=1)}]}
        ssm.list_commands.return_value = {'Commands': [{
            'CommandId': COMMAND_ID, 'DocumentName': 'AWS-RunPatchBaseline',
            'Parameters': {'Operation': ['Install']}}]}
        report = await SSMPatchFacade(object())._scan_evidence(ssm, MANAGED)
        assert report['last_successful_scan_at'] is None
        assert report['scan_evidence'] == 'unverified'
    asyncio.run(scenario())


def test_report_escaped_and_default_metadata_and_rules_registered():
    metadata = json.loads((ROOT / 'ScoutSuite/providers/aws/metadata.json').read_text())
    assert metadata['management']['ssm']['resources']['managed_nodes']['path'] == (
        'services.ssm.regions.id.managed_nodes')
    rules = json.loads((ROOT / 'ScoutSuite/providers/aws/rules/rulesets/default.json').read_text())
    for name in ('ssm-critical-patches.json', 'ssm-security-patches.json',
                 'ssm-stale-or-unverified-scan.json', 'ssm-agent-offline.json',
                 'ssm-running-ec2-unmanaged.json'):
        assert name in rules['rules']
    for kind in ('patch_baselines', 'patch_groups', 'managed_nodes', 'ec2_instances'):
        contents = (ROOT / 'ScoutSuite/output/data/html/partials/aws'
                    / ('services.ssm.regions.id.' + kind + '.html')).read_text(encoding='utf-8')
        assert '{{{' not in contents
        assert 'innerHTML' not in contents
        assert 'eval(' not in contents
        assert '{{name}}' in contents
    node_html = (ROOT / 'ScoutSuite/output/data/html/partials/aws'
                 / 'services.ssm.regions.id.managed_nodes.html').read_text()
    assert '{{last_successful_scan_at}}' in node_html
    assert '{{critical_noncompliant_count}}' in node_html
    assert '{{missing_security_patch_count}}' in node_html
