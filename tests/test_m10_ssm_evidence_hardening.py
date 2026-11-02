"""M10-O evidence hardening: last agent ping, baseline completeness and pagination."""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

from ScoutSuite.core.rule_evidence import (
    CLASSIFIERS, classify_ssm_offline, classify_ssm_scan_unverified,
    classify_ssm_unmanaged, classify_ssm_security_noncompliant,
    classify_ssm_missing_patches)
from ScoutSuite.providers.aws.facade.ssm_public import (
    assessment, SSMPublicFacade, PATCH_DETAIL_MAX_ITEMS,
    PATCH_DETAIL_MAX_PAGES)
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils


REGION = 'eu-central-1'
NODE = 'i-0123456789abcdef0'
BASELINE = 'pb-0123456789abcdef0'
NOW = datetime.now(timezone.utc)
ROOT = Path(__file__).resolve().parents[1]


def patch_data():
    return {
        'InstanceId': NODE, 'PatchGroup': 'prod', 'BaselineId': BASELINE,
        'Operation': 'Scan', 'OperationStartTime': NOW-timedelta(hours=1, minutes=2),
        'OperationEndTime': NOW-timedelta(hours=1),
        'MissingCount': 0, 'FailedCount': 0, 'InstalledPendingRebootCount': 0,
        'InstalledRejectedCount': 0, 'CriticalNonCompliantCount': 0,
        'SecurityNonCompliantCount': 0, 'OtherNonCompliantCount': 0,
    }


def test_stale_online_agent_is_not_evidence_of_healthy_patch_state():
    base = {'ssm_managed': True, 'ping_status': 'Online',
            'last_ping_at': (NOW-timedelta(days=2)).isoformat(),
            'patch_state': patch_data(), 'patch_state_observed': True,
            'last_successful_scan_at': NOW.isoformat(),
            'successful_scan_confirmed': True}
    old = assessment(base.copy(), NOW)
    assert old['agent_ping_fresh'] is False
    assert old['agent_ping_unverified'] is True
    assert old['patch_compliant_evidence'] is False
    assert classify_ssm_offline(old) == 'unknown'
    fresh = assessment(dict(base, last_ping_at=NOW.isoformat()), NOW)
    assert fresh['agent_ping_fresh'] is True
    assert fresh['patch_compliant_evidence'] is True
    assert classify_ssm_offline(fresh) == 'secure'
    missing = assessment(dict(base, last_ping_at=None), NOW)
    assert missing['agent_ping_fresh'] is False
    assert missing['patch_compliant_evidence'] is False


def test_rule_classifiers_unknown_vs_confirmed_and_no_missing_agent_assumption():
    values = {k for k in CLASSIFIERS if k.startswith('ssm-')}
    assert values == {
        'ssm-unmanaged-ec2-v1', 'ssm-offline-agent-v1',
        'ssm-scan-unverified-v1', 'ssm-security-patches-v1',
        'ssm-missing-patches-v1'}
    assert classify_ssm_unmanaged({
        'unmanaged_running_ec2': True, 'ssm_managed': False}) == 'insecure'
    assert classify_ssm_unmanaged({'ssm_managed': None}) == 'unknown'
    assert classify_ssm_offline({'ssm_managed': True,
                                 'ping_status': 'ConnectionLost'}) == 'insecure'
    assert classify_ssm_scan_unverified({
        'ssm_managed': True, 'scan_unverified': True}) == 'insecure'
    assert classify_ssm_scan_unverified({
        'ssm_managed': True, 'scan_unverified': False,
        'patch_compliant_evidence': False}) == 'unknown'
    patch = {'CriticalNonCompliantCount': 3, 'SecurityNonCompliantCount': 0,
             'MissingCount': 2, 'FailedCount': 0,
             'InstalledPendingRebootCount': 0, 'InstalledRejectedCount': 0}
    assert classify_ssm_security_noncompliant({
        'ssm_managed': True, 'patch_state': patch}) == 'insecure'
    assert classify_ssm_missing_patches({
        'ssm_managed': True, 'patch_state': patch}) == 'insecure'
    patch['CriticalNonCompliantCount'] = 0
    patch['MissingCount'] = 0
    incomplete = {'ssm_managed': True, 'patch_state': patch,
                  'patch_compliant_evidence': False}
    assert classify_ssm_security_noncompliant(incomplete) == 'unknown'
    assert classify_ssm_missing_patches(incomplete) == 'unknown'
    clean = dict(incomplete, patch_compliant_evidence=True)
    assert classify_ssm_security_noncompliant(clean) == 'secure'
    assert classify_ssm_missing_patches(clean) == 'secure'


def test_patch_detail_enumeration_is_bounded_and_truncation_reported():
    async def scenario():
        client = Mock()
        count = 0
        def page(**kwargs):
            nonlocal count
            count += 1
            return {'Patches': [{'State': 'MISSING'} for _ in range(50)],
                    'NextToken': 'page-'+str(count)}
        client.describe_instance_patches.side_effect = page
        data, complete = await SSMPublicFacade(object()).pages(
            client, 'describe_instance_patches', 'Patches',
            InstanceId=NODE, max_pages=PATCH_DETAIL_MAX_PAGES,
            max_items=PATCH_DETAIL_MAX_ITEMS)
        assert len(data) == PATCH_DETAIL_MAX_ITEMS
        assert complete is False
        assert count == PATCH_DETAIL_MAX_PAGES
    asyncio.run(scenario())


def test_inventory_does_not_pass_when_baseline_detail_denied():
    async def scenario(deny_baseline):
        ssm, ec2 = Mock(), Mock()
        ssm.describe_instance_information.return_value = {
            'InstanceInformationList': [{
                'InstanceId': NODE, 'PingStatus': 'Online',
                'LastPingDateTime': NOW, 'AgentVersion': '3.3.0.0'}]}
        ssm.describe_patch_baselines.return_value = {
            'BaselineIdentities': [{'BaselineId': BASELINE, 'BaselineName': 'Prod'}]}
        if deny_baseline:
            ssm.get_patch_baseline.side_effect = ClientError({
                'Error': {'Code': 'AccessDeniedException', 'Message': 'synthetic'}},
                'GetPatchBaseline')
        else:
            ssm.get_patch_baseline.return_value = {
                'BaselineId': BASELINE, 'Name': 'Prod',
                'ApprovalRules': {'PatchRules': []}}
        ssm.describe_patch_groups.return_value = {'Mappings': []}
        ssm.describe_instance_patch_states.return_value = {
            'InstancePatchStates': [patch_data()]}
        ssm.list_commands.return_value = {'Commands': [{
            'DocumentName': 'AWS-RunPatchBaseline',
            'CommandId': '11111111-1111-4111-8111-111111111111',
            'Parameters': {'Operation': ['Scan']}, 'Status': 'Success'}]}
        ssm.list_command_invocations.return_value = {'CommandInvocations': [{
            'DocumentName': 'AWS-RunPatchBaseline',
            'CommandId': '11111111-1111-4111-8111-111111111111',
            'InstanceId': NODE, 'Status': 'Success', 'StatusDetails': 'Success',
            'CommandPlugins': [{
                'Status': 'Success',
                'ResponseFinishDateTime': NOW-timedelta(minutes=5)}]}]}
        ec2.describe_instances.return_value = {'Reservations': [{
            'Instances': [{'InstanceId': NODE, 'State': {'Name': 'running'}}]}]}
        with patch.object(AWSFacadeUtils, 'get_client',
                          side_effect=lambda name, *_: ssm if name == 'ssm' else ec2):
            return await SSMPublicFacade(object()).inventory(REGION)
    good = asyncio.run(scenario(False))
    assert good['managed_nodes'][0]['patch_compliant_evidence'] is True
    assert good['managed_nodes'][0]['baseline_resolution_status'] == 'resolved'
    assert good['managed_nodes'][0]['inventory_evidence_complete'] is True
    bad = asyncio.run(scenario(True))
    node = bad['managed_nodes'][0]
    assert node['patch_compliant_evidence'] is False
    assert node['baseline_resolution_status'] == 'unknown'
    assert node['patch_assessment'] == 'inventory_incomplete'
    assert bad['collection']['patch_baselines'] is False


def test_each_finding_evidence_policy_is_a_supported_classifier():
    names = (
        'ssm-running-ec2-unmanaged.json',
        'ssm-managed-node-offline.json',
        'ssm-managed-node-scan-unverified.json',
        'ssm-managed-node-security-noncompliant.json',
        'ssm-managed-node-missing-patches.json')
    for name in names:
        path = ROOT / 'ScoutSuite/providers/aws/rules/findings' / name
        rule = json.loads(path.read_text(encoding='utf-8'))
        assert rule['evidence_policy'] in CLASSIFIERS
        assert callable(CLASSIFIERS[rule['evidence_policy']])
