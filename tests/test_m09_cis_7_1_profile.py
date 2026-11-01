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
    assert len(profile['control_mappings']) == len(profile['rules']) == 11
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
        'id': 'cis-aws-foundations-partial', 'version': '2026.11.0'
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
