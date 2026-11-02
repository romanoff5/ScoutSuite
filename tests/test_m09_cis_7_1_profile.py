"""M09-A: vetted control IDs are candidate mappings, never certification."""
import json
from types import SimpleNamespace

import pytest

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.ruleset import PolicyProfileError, Ruleset
from tests.fixtures import ROOT


PROFILE = ROOT / 'ScoutSuite/providers/aws/rules/rulesets/cis-foundations-7.1.0-partial.json'


def test_cis_7_1_0_partial_profile_is_explicit_and_preserves_legacy_mapping():
    profile = json.loads(PROFILE.read_text(encoding='utf-8'))
    assert profile['benchmark']['version'] == '7.1.0'
    assert profile['benchmark']['coverage'] == 'partial'
    assert profile['profile_id'] == 'cis-aws-foundations-partial'
    assert len(profile['control_mappings']) == len(profile['rules']) == 32
    assert profile['control_mappings']['ec2-instance-imdsv1-enabled.json'][0]['control_id'] == '6.7'
    assert profile['control_mappings']['iam-password-policy-minimum-length.json'][0]['control_id'] == '2.8'
    assert (ROOT / 'ScoutSuite/providers/aws/rules/rulesets/cis-1.2.0.json').exists()
    ruleset = Ruleset('aws', filename=str(PROFILE))
    assert ruleset.benchmark['version'] == '7.1.0'
    assert ruleset.control_mappings['ec2-instance-imdsv1-enabled.json']


def test_partial_profile_emits_candidate_control_without_claiming_compliance():
    ruleset = Ruleset('aws', filename=str(PROFILE))
    provider = SimpleNamespace(services={'ec2': {'regions': {'us-east-1': {
        'vpcs': {'vpc-test': {'instances': {
            'i-test': {'imds_v2_status': 'optional'},
        }}}}}}}, service_list=['ec2'])
    ProcessingEngine(ruleset).run(provider)
    finding = provider.services['ec2']['findings']['ec2-instance-imdsv1-enabled']
    assert finding['flagged_items'] == 1
    assert finding['policy_profile'] == {
        'id': 'cis-aws-foundations-partial', 'version': '2026.11.1'
    }
    assert finding['standard_mappings'] == [{
        'benchmark_id': 'cis-aws-foundations',
        'benchmark_version': '7.1.0',
        'control_id': '6.7',
        'coverage': 'candidate',
        'compliance_verified': False,
    }]


@pytest.mark.parametrize('invalid', [
    {'benchmark': {'id': 'cis-aws-foundations', 'version': '7.1.0', 'coverage': 'complete'}},
    {'control_mappings': {'missing-rule.json': [{'control_id': '2.8', 'coverage': 'candidate'}]}},
    {'control_mappings': {'ec2-instance-imdsv1-enabled.json': [
        {'control_id': '6.7', 'coverage': 'verified'}]}},
])
def test_invalid_benchmark_metadata_fails_closed(tmp_path, invalid):
    original = json.loads(PROFILE.read_text(encoding='utf-8'))
    original.update(invalid)
    name = tmp_path / 'invalid-cis.json'
    name.write_text(json.dumps(original), encoding='utf-8')
    with pytest.raises(PolicyProfileError):
        Ruleset('aws', filename=str(name))


def test_rc4_profile_adds_observed_auto_controls_without_replacing_legacy():
    profile = json.loads(PROFILE.read_text(encoding='utf-8'))
    for name, control_id in {
        'iam-user-without-mfa.json': '2.10',
        'iam-unused-credentials-not-disabled.json': '2.11',
        'iam-user-no-key-rotation.json': '2.12',
        's3-bucket-allowing-cleartext.json': '3.1.1',
        'rds-instance-storage-not-encrypted.json': '3.2.1',
        'rds-instance-no-minor-upgrade.json': '3.2.2',
        'rds-instance-publicly-accessible.json': '3.2.3',
        'rds-instance-deletion-protection-disabled.json': '3.2.5',
        'efs-filesystem-not-encrypted.json': '3.3.1',
        's3-bucket-public-access-block-incomplete.json': '3.1.4',
        'securityhub-region-not-subscribed.json': '5.16',
        'ec2-ebs-default-encryption-disabled.json': '6.1.1',
        'bedrock-invocation-logging-review.json': '7.4.2',
    }.items():
        assert profile['control_mappings'][name] == [{
            'control_id': control_id, 'coverage': 'candidate'}]
        assert profile['rules'][name][0]['enabled'] is True
    assert profile['rules']['iam-unused-credentials-not-disabled.json'][0]['args'] == ['45']
    assert profile['rules']['iam-user-no-key-rotation.json'][0]['args'] == ['Active', '90']
    assert len({v[0]['control_id'] for v in profile['control_mappings'].values()}) == 30
    assert all(v[0]['coverage'] == 'candidate' for v in profile['control_mappings'].values())
    assert profile['benchmark']['coverage'] == 'partial'
    assert not profile['benchmark'].get('compliance_verified', False)
