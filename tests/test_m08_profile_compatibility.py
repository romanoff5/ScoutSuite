"""M08 strict profile validation and stable legacy finding exceptions."""
import json
from types import SimpleNamespace

import pytest

from ScoutSuite.core.exceptions import RuleExceptions
from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.ruleset import PolicyProfileError, Ruleset
from tests.fixtures import ROOT


PROFILE = ROOT / 'ScoutSuite/providers/aws/rules/rulesets/aws-security-focused-2026-11.json'


@pytest.mark.parametrize('profile_fields', [
    {'profile_id': 'aws-security-focused', 'profile_version': 'bad',
     'schema_version': 1},
    {'profile_id': 'aws-security-focused', 'profile_version': '2026.11.0',
     'schema_version': 99},
    {'profile_id': 'aws-security-focused', 'profile_version': None,
     'schema_version': 1},
])
def test_invalid_opt_in_profile_is_rejected_not_loaded_empty(tmp_path, profile_fields):
    data = {
        'about': 'Synthetic invalid profile',
        'rules': {'kms-cmk-rotation-disabled.json': [
            {'enabled': True, 'level': 'warning'}
        ]},
        **profile_fields,
    }
    path = tmp_path / 'invalid-profile.json'
    path.write_text(json.dumps(data), encoding='utf-8')
    with pytest.raises(PolicyProfileError):
        Ruleset('aws', filename=str(path))


def test_m08_evidence_additions_preserve_existing_exception_keys(tmp_path):
    provider = SimpleNamespace(services={
        'kms': {'regions': {'us-east-1': {'keys': {
            'key1': {
                'key_manager': 'CUSTOMER', 'key_enabled': True,
                'origin': 'AWS_KMS', 'key_spec': 'SYMMETRIC_DEFAULT',
                'key_usage': 'ENCRYPT_DECRYPT',
                'rotation_status': 'disabled', 'rotation_enabled': False,
            }
        }}}},
        'cloudtrail': {'regions': {}},
    }, service_list=['kms', 'cloudtrail'])
    ProcessingEngine(Ruleset('aws', filename=str(PROFILE))).run(provider)
    key = 'kms-cmk-rotation-disabled'
    finding = provider.services['kms']['findings'][key]
    original_path = 'kms.regions.us-east-1.keys.key1.rotation_enabled'
    assert finding['items'] == [original_path]
    assert finding['flagged_items'] == 1
    assert finding['evaluation_summary']['counts']['insecure'] == 1

    exception_path = tmp_path / 'exceptions.js'
    exception_path.write_text(
        'exceptions =\n' + json.dumps({'kms': {key: [original_path]}}),
        encoding='utf-8'
    )
    RuleExceptions(str(exception_path)).process(provider)
    assert finding['items'] == []
    assert finding['flagged_items'] == 0
    # The evidence result reflects evaluation before a user exception.
    assert finding['evaluation_summary']['counts']['insecure'] == 1
    assert finding['policy_profile']['version'] == '2026.11.0'
