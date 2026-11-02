"""M10-O: synthetic, offline SSM patch visibility and SDK contracts."""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, AsyncMock, patch

import boto3
from botocore.exceptions import ClientError
from botocore.session import get_session
from botocore.stub import Stubber

from ScoutSuite.providers.aws.facade.ssm_public import (
    SSMPublicFacade, assessment, json_safe, SCAN_MAX_AGE_DAYS)
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.ssm.base import SSMPublic

ROOT = Path(__file__).resolve().parents[1]
REGION = 'us-east-1'
INSTANCE = 'i-1234567890abcdef0'
SECOND = 'i-00000000000000001'
NOW = datetime(2026, 11, 2, tzinfo=timezone.utc)


def state(**overrides):
    data = {
        'InstanceId': INSTANCE, 'BaselineId': 'pb-0123456789abcdef0',
        'Operation': 'Scan', 'OperationEndTime': NOW,
        'MissingCount': 0, 'FailedCount': 0,
        'InstalledPendingRebootCount': 0, 'InstalledRejectedCount': 0,
        'CriticalNonCompliantCount': 0, 'SecurityNonCompliantCount': 0,
        'OtherNonCompliantCount': 0,
    }
    data.update(overrides)
    return data


def node(**overrides):
    data = {'ssm_managed': True, 'ping_status': 'Online',
            'last_ping_at': NOW.isoformat(),
            'patch_state': state(), 'patch_state_observed': True,
            'last_successful_scan_at': NOW.isoformat(),
            'successful_scan_confirmed': True}
    data.update(overrides)
    return data


def test_sdk_read_only_apis_and_state_pagination_contract():
    model = get_session().get_service_model('ssm')
    for operation in ('DescribeInstanceInformation', 'DescribePatchBaselines',
                      'GetPatchBaseline', 'DescribePatchGroups',
                      'DescribeInstancePatchStates', 'DescribeInstancePatches'):
        assert operation in model.operation_names
    states = model.operation_model('DescribeInstancePatchStates').input_shape.members
    assert {'InstanceIds', 'NextToken', 'MaxResults'} <= set(states)
    assert {'Filters', 'InstanceId', 'NextToken'} <= set(
        model.operation_model('DescribeInstancePatches').input_shape.members)


def test_clean_requires_online_agent_current_scan_and_known_counts():
    item = assessment(node(), NOW)
    assert item['patch_compliant_evidence'] is True
    assert item['patch_assessment'] == 'recent_scan_no_reported_noncompliance'
    assert item['fully_patched_verified'] is False
    for sample in (
        node(ping_status='ConnectionLost'),
        node(patch_state=state(Operation='Install')),
        node(patch_state=state(OperationEndTime=NOW-timedelta(days=8))),
        node(patch_state=state(OperationEndTime=None)),
        node(patch_state={}),
        node(patch_state_observed=False),
        node(patch_state=state(MissingCount=None)),
    ):
        result = assessment(sample, NOW)
        assert not result['patch_compliant_evidence'], result
    assert assessment(node(patch_state=state(
        OperationEndTime=NOW-timedelta(days=8))), NOW)['scan_stale']


def test_critical_security_and_pending_reboot_never_clear():
    critical = assessment(node(patch_state=state(
        CriticalNonCompliantCount=3, SecurityNonCompliantCount=2)), NOW)
    assert critical['security_noncompliant'] is True
    assert critical['patch_assessment'] == 'security_noncompliant'
    assert not critical['patch_compliant_evidence']
    reboot = assessment(node(patch_state=state(
        InstalledPendingRebootCount=1)), NOW)
    assert reboot['missing_or_failed_patches'] is True
    assert not reboot['patch_compliant_evidence']
    missing = assessment(node(patch_state=state(MissingCount=5)), NOW)
    assert missing['missing_or_failed_patches'] is True



def test_successful_scan_requires_matching_operation_node_and_command_success():
    async def scenario():
        facade = SSMPublicFacade(object())
        client = Mock()
        cid = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        client.list_commands.return_value = {'Commands': [
            {'CommandId': cid, 'DocumentName': 'AWS-RunPatchBaseline',
             'Parameters': {'Operation': ['Scan']}, 'Status': 'Success'},
            {'CommandId': 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
             'DocumentName': 'AWS-RunPatchBaseline',
             'Parameters': {'Operation': ['Install']}, 'Status': 'Success'}]}
        client.list_command_invocations.return_value = {'CommandInvocations': [
            {'CommandId': cid, 'InstanceId': INSTANCE,
             'DocumentName': 'AWS-RunPatchBaseline',
             'Status': 'Success', 'StatusDetails': 'Success',
             'CommandPlugins': [{
                 'Status': 'Success', 'ResponseFinishDateTime': NOW}]},
            {'CommandId': cid, 'InstanceId': SECOND,
             'DocumentName': 'AWS-RunPatchBaseline',
             'Status': 'Failed', 'StatusDetails': 'Failed',
             'CommandPlugins': [{
                 'Status': 'Failed', 'ResponseFinishDateTime': NOW}]}]}
        scans, complete = await facade.successful_scan_commands(client, [INSTANCE, SECOND])
        assert complete
        assert scans[INSTANCE].startswith('2026-11-02')
        assert SECOND not in scans
        assert client.list_command_invocations.call_count == 1
        assert assessment(node(), NOW)['patch_compliant_evidence']
        assert not assessment(node(
            successful_scan_confirmed=False,
            last_successful_scan_at=None), NOW)['patch_compliant_evidence']

        client.list_commands.return_value = {'Commands': [
            {'CommandId': cid, 'DocumentName': 'AWS-RunPatchBaseline',
             'Parameters': {'Operation': ['Scan']}}]}
        client.list_command_invocations.return_value = {'CommandInvocations': [
            {'CommandId': cid, 'InstanceId': INSTANCE,
             'DocumentName': 'AWS-RunPatchBaseline',
             'Status': 'Success', 'StatusDetails': 'Success',
             'CommandPlugins': []}]}
        scans, complete = await facade.successful_scan_commands(client, [INSTANCE])
        assert complete and scans == {}
    asyncio.run(scenario())


def test_running_ec2_without_ssm_not_presented_as_patched():
    result = assessment({'ssm_managed': False, 'ec2_state': 'running',
                         'patch_state': None}, NOW)
    assert result['unmanaged_running_ec2']
    assert result['patch_assessment'] == 'unmanaged_running_ec2'
    assert not result['patch_compliant_evidence']
    stopped = assessment({'ssm_managed': False, 'ec2_state': 'stopped'}, NOW)
    assert not stopped['unmanaged_running_ec2']


def test_timestamp_and_all_aws_diagnostics_not_truncated():
    raw = {'timestamp': NOW, 'CVEIds': 'CVE-2026-123,CVE-2026-456',
           'extra': [{'long': 'x' * 20000}]}
    safe = json_safe(raw)
    assert safe['timestamp'].startswith('2026-11-02')
    assert len(safe['extra'][0]['long']) == 20000
    json.dumps(safe)


def test_real_sdk_stubber_for_patch_states_pagination_and_scalar_fields():
    client = boto3.client('ssm', region_name=REGION,
                          aws_access_key_id='test', aws_secret_access_key='test')
    try:
        with Stubber(client) as stub:
            stub.add_response('describe_instance_patch_states', {
                'InstancePatchStates': [{
                    'InstanceId': INSTANCE, 'BaselineId': 'pb-0123456789abcdef0',
                    'PatchGroup': 'production',
                    'Operation': 'Scan', 'OperationStartTime': NOW - timedelta(minutes=5),
                    'OperationEndTime': NOW,
                    'MissingCount': 1, 'CriticalNonCompliantCount': 1,
                    'SecurityNonCompliantCount': 1,
                }], 'NextToken': 'next'}, {
                'InstanceIds': [INSTANCE], 'MaxResults': 50})
            stub.add_response('describe_instance_patch_states', {
                'InstancePatchStates': []}, {
                'InstanceIds': [INSTANCE], 'MaxResults': 50, 'NextToken': 'next'})
            states, complete = asyncio.run(
                SSMPublicFacade(object()).patch_states(client, [INSTANCE]))
            assert complete
            assert states[INSTANCE]['MissingCount'] == 1
            stub.assert_no_pending_responses()
    finally:
        client.close()


def test_missing_agent_only_when_both_inventories_complete():
    async def scenario(incomplete=False):
        ssm, ec2 = Mock(), Mock()
        ssm.describe_instance_information.return_value = {'InstanceInformationList': []}
        ssm.describe_patch_baselines.return_value = {'BaselineIdentities': []}
        ssm.describe_patch_groups.return_value = {'Mappings': []}
        ec2.describe_instances.return_value = {'Reservations': [{
            'Instances': [{'InstanceId': INSTANCE,
                           'State': {'Name': 'running'},
                           'Tags': [{'Key': 'Name', 'Value': 'payments'}]},
                          {'InstanceId': SECOND,
                           'State': {'Name': 'stopped'}}]}]}
        if incomplete:
            ssm.describe_instance_information.side_effect = ClientError(
                {'Error': {'Code': 'AccessDeniedException', 'Message': 'denied'}},
                'DescribeInstanceInformation')
        with patch.object(AWSFacadeUtils, 'get_client',
                          side_effect=lambda service, session, region: {
                              'ssm': ssm, 'ec2': ec2}[service]):
            result = await SSMPublicFacade(object()).inventory(REGION)
        rows = {x['instance_id']: x for x in result['managed_nodes']}
        if incomplete:
            assert result['collection']['managed_nodes'] is False
            assert not result['ec2_comparison_complete']
            assert rows == {}
        else:
            assert result['ec2_comparison_complete']
            assert rows[INSTANCE]['unmanaged_running_ec2'] is True
            assert rows[INSTANCE]['name'] == 'payments'
            assert rows[SECOND]['unmanaged_running_ec2'] is False
            assert not rows[INSTANCE]['patch_compliant_evidence']
    asyncio.run(scenario(False))
    asyncio.run(scenario(True))


def test_unreported_states_remain_unknown_and_details_are_preserved():
    async def scenario():
        ssm, ec2 = Mock(), Mock()
        ssm.describe_instance_information.return_value = {
            'InstanceInformationList': [{
                'InstanceId': INSTANCE, 'PingStatus': 'Online',
                'ComputerName': 'prod-host',
                'LastPingDateTime': NOW}]}
        ssm.describe_patch_baselines.return_value = {
            'BaselineIdentities': [{
                'BaselineId': 'pb-0123456789abcdef0', 'BaselineName': 'prod-baseline'}]}
        ssm.get_patch_baseline.return_value = {
            'BaselineId': 'pb-0123456789abcdef0', 'Name': 'prod-baseline',
            'ApprovedPatches': ['KB123456']}
        ssm.describe_patch_groups.return_value = {'Mappings': []}
        ssm.describe_instance_patch_states.return_value = {
            'InstancePatchStates': [state(MissingCount=1, SecurityNonCompliantCount=1)]}
        ssm.describe_instance_patches.return_value = {
            'Patches': [{'Title': 'Security patch', 'KBId': 'KB123456',
                         'Classification': 'SecurityUpdates',
                         'Severity': 'Important', 'State': 'MISSING',
                         'CVEIds': 'CVE-2026-11111'}]}
        ec2.describe_instances.return_value = {'Reservations': []}
        with patch.object(AWSFacadeUtils, 'get_client',
                          side_effect=lambda service, session, region: {
                              'ssm': ssm, 'ec2': ec2}[service]):
            result = await SSMPublicFacade(object()).inventory(REGION)
        assert result['collection']['patch_states']
        assert result['patch_baselines'][0]['detail']['ApprovedPatches'] == ['KB123456']
        item = result['managed_nodes'][0]
        assert item['security_noncompliant']
        assert item['security_related_missing_patches'][0]['CVEIds'] == 'CVE-2026-11111'
        assert item['last_reported_scan_at'].startswith('2026-11-02')
        assert item['missing_patches_collection_complete'] is True

        facade = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]),
            ssm=SimpleNamespace(inventory=AsyncMock(return_value=result)))
        resources = SSMPublic(facade)
        await resources.fetch_all(regions=[REGION])
        assert resources['managed_nodes_count'] == 1
        assert resources['patch_baselines_count'] == 1
        assert 'CVE-2026-11111' in json.dumps(resources)
    asyncio.run(scenario())


def test_partial_page_or_repeated_token_cannot_pass():
    async def scenario():
        facade = SSMPublicFacade(object())
        api = Mock()
        api.describe_instance_information.side_effect = [
            {'InstanceInformationList': [], 'NextToken': 'again'},
            {'InstanceInformationList': [], 'NextToken': 'again'}]
        rows, complete = await facade.pages(
            api, 'describe_instance_information', 'InstanceInformationList')
        assert rows == [] and not complete
        api.describe_instance_information.side_effect = None
        api.describe_instance_information.return_value = {'InstanceInformationList': 'wrong'}
        rows, complete = await facade.pages(
            api, 'describe_instance_information', 'InstanceInformationList')
        assert rows == [] and not complete
    asyncio.run(scenario())


def test_rule_definitions_and_offline_safe_html():
    rule_ids = ('ssm-running-ec2-unmanaged.json',
                'ssm-managed-node-offline.json',
                'ssm-managed-node-scan-unverified.json',
                'ssm-managed-node-security-noncompliant.json',
                'ssm-managed-node-missing-patches.json')
    rules = json.loads((ROOT / 'ScoutSuite/providers/aws/rules/rulesets/default.json')
                       .read_text(encoding='utf-8'))['rules']
    for filename in rule_ids:
        assert rules[filename][0]['enabled']
        rule = json.loads((ROOT / 'ScoutSuite/providers/aws/rules/findings'
                           / filename).read_text(encoding='utf-8'))
        assert rule['path'] == 'ssm.regions.id.managed_nodes.id'
        assert rule['conditions'][1][1] == 'true'
    for filename in ('managed_nodes', 'patch_baselines', 'patch_groups'):
        html = (ROOT / 'ScoutSuite/output/data/html/partials/aws' /
                ('services.ssm.regions.id.' + filename + '.html')).read_text(encoding='utf-8')
        assert 'registerPartial' in html
        assert '{{{' not in html and 'eval(' not in html
        assert 'http://' not in html and 'https://' not in html


def test_baseline_and_group_identity_integrity():
    async def scenario():
        facade = SimpleNamespace(
            build_region_list=AsyncMock(return_value=[REGION]),
            ssm=SimpleNamespace(inventory=AsyncMock(return_value={
                'managed_nodes': [], 'patch_baselines': [
                    {'BaselineId': 'pb-1', 'BaselineName': 'first'},
                    {'BaselineId': 'pb-2', 'BaselineName': 'second'}],
                'patch_groups': [{'PatchGroup': 'production',
                                  'BaselineIdentity': {'BaselineId': 'pb-1'}}],
                'collection': {'patch_baselines': True, 'patch_groups': True},
                'ec2_comparison_complete': False})))
        resources = SSMPublic(facade)
        await resources.fetch_all()
        assert resources['patch_baselines_count'] == 2
        assert resources['patch_groups_count'] == 1
    asyncio.run(scenario())
