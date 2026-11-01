"""M08 evidence semantics and opt-in versioned AWS ruleset (offline)."""
import asyncio
from types import SimpleNamespace

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import (
    classify_cloudtrail_data_coverage,
    classify_cloudtrail_data_events,
    classify_kms_automatic_rotation,
)
from ScoutSuite.core.ruleset import Ruleset
from ScoutSuite.core.run_context import RunContext
from ScoutSuite.output.result_encoder import ScoutResultEncoder
from tests.fixtures import ROOT


PROFILE = ROOT / 'ScoutSuite/providers/aws/rules/rulesets/aws-security-focused-2026-11.json'


def kms_key(**values):
    item = {
        'key_manager': 'CUSTOMER',
        'key_enabled': True,
        'origin': 'AWS_KMS',
        'key_spec': 'SYMMETRIC_DEFAULT',
        'key_usage': 'ENCRYPT_DECRYPT',
        'rotation_status': 'enabled',
        'rotation_enabled': True,
    }
    item.update(values)
    return item


def trail(**values):
    item = {
        'DataEventsEnabled': True,
        'wildcard_data_logging': True,
        'selector_collection_status': 'success',
    }
    item.update(values)
    return item


def services():
    return {
        'kms': {
            'regions': {
                'us-east-1': {
                    'keys': {
                        'secure': kms_key(),
                        'insecure': kms_key(rotation_status='disabled', rotation_enabled=False),
                        'denied': kms_key(rotation_status='unavailable', rotation_enabled=None),
                        'unknown': kms_key(rotation_status='unknown', rotation_enabled=None),
                        'imported': kms_key(origin='EXTERNAL', rotation_status='not_supported',
                                            rotation_enabled=None),
                        'aws-owned': kms_key(key_manager='AWS', rotation_status='aws_managed'),
                    }
                }
            }
        },
        'cloudtrail': {
            'regions': {
                'us-east-1': {
                    'trails': {
                        'secure': trail(),
                        'insecure': trail(DataEventsEnabled=False, wildcard_data_logging=False),
                        'denied': trail(DataEventsEnabled=None, wildcard_data_logging=None,
                                        selector_collection_status='failed'),
                    }
                }
            }
        },
    }


def test_m08_classifiers_handle_secure_insecure_unknown_and_not_applicable():
    assert classify_kms_automatic_rotation(kms_key()) == 'secure'
    assert classify_kms_automatic_rotation(kms_key(rotation_status='disabled',
                                                   rotation_enabled=False)) == 'insecure'
    assert classify_kms_automatic_rotation(kms_key(rotation_status='unavailable',
                                                   rotation_enabled=None)) == 'unknown'
    assert classify_kms_automatic_rotation(kms_key(key_spec=None)) == 'unknown'
    assert classify_kms_automatic_rotation(kms_key(origin='EXTERNAL')) == 'not_applicable'
    assert classify_kms_automatic_rotation(kms_key(key_manager='AWS')) == 'not_applicable'
    assert classify_kms_automatic_rotation(kms_key(key_enabled=False)) == 'not_applicable'
    assert classify_cloudtrail_data_events(trail()) == 'secure'
    assert classify_cloudtrail_data_events(trail(DataEventsEnabled=False)) == 'insecure'
    assert classify_cloudtrail_data_events(trail(selector_collection_status='failed')) == 'unknown'
    assert classify_cloudtrail_data_coverage(trail(wildcard_data_logging=False)) == 'insecure'
    assert classify_cloudtrail_data_coverage(trail(wildcard_data_logging=None)) == 'unknown'


def test_versioned_profile_preserves_rule_ids_and_flags_incomplete_evidence():
    async def scenario():
        context = RunContext('aws').setup()
        provider = SimpleNamespace(services=services(), service_list=['kms', 'cloudtrail'])
        try:
            ruleset = Ruleset('aws', filename=str(PROFILE))
            assert ruleset.profile_id == 'aws-security-focused'
            assert ruleset.profile_version == '2026.11.0'
            ProcessingEngine(ruleset).run(provider)
            kms = provider.services['kms']['findings']['kms-cmk-rotation-disabled']
            expected = 'kms.regions.us-east-1.keys.insecure.rotation_enabled'
            assert kms['items'] == [expected]
            assert kms['flagged_items'] == 1
            assert kms['checked_items'] == 6
            assert kms['level'] == 'warning'
            assert kms['assessment_status'] == 'incomplete'
            summary = kms['evaluation_summary']
            assert summary['counts'] == {
                'secure': 1, 'insecure': 1, 'unknown': 2, 'not_applicable': 2
            }
            assert summary['evaluated_resources'] == 2
            assert summary['unknown_resources'] == [
                'kms.regions.us-east-1.keys.denied',
                'kms.regions.us-east-1.keys.unknown',
            ]
            assert kms['policy_profile'] == {
                'id': 'aws-security-focused', 'version': '2026.11.0'
            }
            events = provider.services['cloudtrail']['findings']['cloudtrail-no-data-logging']
            coverage = provider.services['cloudtrail']['findings']['cloudtrail-partial-data-logging']
            assert events['items'] == [
                'cloudtrail.regions.us-east-1.trails.insecure.cloudtrail-data-events-disabled'
            ]
            assert coverage['items'] == [
                'cloudtrail.regions.us-east-1.trails.insecure.cloudtrail-data-events-disabled'
            ]
            assert events['flagged_items'] == 1
            assert coverage['flagged_items'] == 1
            assert events['checked_items'] == coverage['checked_items'] == 3
            assert events['evaluation_summary']['counts']['unknown'] == 1
            assert coverage['assessment_status'] == 'incomplete'
            assert sorted(issue['scope'] for issue in context.collection_issues) == [
                'cloudtrail', 'kms'
            ]
            encoded = ScoutResultEncoder.to_dict(provider)
            assert encoded['services']['kms']['findings']['kms-cmk-rotation-disabled'][
                'evaluation_summary']['counts'] == summary['counts']
        finally:
            await context.aclose()

    asyncio.run(scenario())


def test_all_inapplicable_keys_and_no_trails_do_not_imply_verified_compliance():
    async def scenario():
        context = RunContext('aws').setup()
        dataset = {
            'kms': {'regions': {'us-east-1': {'keys': {
                'imported': kms_key(origin='EXTERNAL', rotation_status='not_supported')
            }}}},
            'cloudtrail': {'regions': {}},
        }
        provider = SimpleNamespace(services=dataset, service_list=['kms', 'cloudtrail'])
        try:
            ProcessingEngine(Ruleset('aws', filename=str(PROFILE))).run(provider)
            for service in ('kms', 'cloudtrail'):
                for finding in provider.services[service]['findings'].values():
                    assert finding['items'] == []
                    assert finding['flagged_items'] == 0
                    assert finding['evaluation_summary']['assessment_status'] == 'not_applicable'
                    assert finding['evaluation_summary']['compliance_verified'] is False
            assert not context.collection_issues
        finally:
            await context.aclose()

    asyncio.run(scenario())


def test_legacy_default_profile_is_not_silently_upgraded():
    ruleset = Ruleset('aws')
    assert ruleset.filename.endswith('rulesets/default.json')
    assert ruleset.profile_id is None
    assert ruleset.profile_version is None
    assert 'kms-cmk-rotation-disabled.json' in ruleset.rules
