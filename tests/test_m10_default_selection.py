"""M10 services must participate in the standard AWS service selection."""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ScoutSuite.providers.aws.provider import AWSProvider


M10_SERVICES = frozenset((
    'accessanalyzer', 'guardduty', 'securityhub', 'organizations',
    'inspector2', 'ecr', 'ecs', 'eks',
))
ROOT = Path(__file__).resolve().parents[1]


def make_provider(*, services=None, skipped_services=None):
    """Use a harmless synthetic service catalog: no SDK or authentication."""
    names = {'iam', 's3'} | M10_SERVICES

    def fake_services(credentials):
        return SimpleNamespace(credentials=credentials, **{s: {} for s in names})

    credentials = SimpleNamespace(session=object())
    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig',
               fake_services), \
         patch('ScoutSuite.providers.aws.provider.get_partition_name',
               return_value='aws'), \
         patch('ScoutSuite.providers.aws.provider.get_aws_account_id',
               return_value='000000000000'):
        return AWSProvider(
            credentials=credentials,
            services=services,
            skipped_services=skipped_services,
        )


def test_every_m10_service_in_unfiltered_aws_scan():
    selected = set(make_provider().service_list)
    assert M10_SERVICES <= selected
    assert {'iam', 's3'} <= selected


def test_explicit_services_still_select_only_requested_ones():
    assert set(make_provider(
        services=['inspector2', 'iam']).service_list) == {'iam', 'inspector2'}


def test_skipped_services_exclude_m10_without_disabling_other_services():
    selected = set(make_provider(
        skipped_services=['organizations', 'inspector2', 'ecs']).service_list)
    assert selected == ({'iam', 's3'} | M10_SERVICES) - {
        'organizations', 'inspector2', 'ecs'
    }


def test_explicit_and_skipped_services_interact_consistently():
    selected = set(make_provider(
        services=['eks', 'ecr', 'guardduty'],
        skipped_services=['guardduty']).service_list)
    assert selected == {'eks', 'ecr'}


def test_default_ruleset_has_at_least_one_rule_for_every_m10_service():
    catalog = json.loads(
        (ROOT / 'ScoutSuite/providers/aws/rules/rulesets/default.json'
         ).read_text(encoding='utf-8'))
    rules = catalog['rules']
    for service in M10_SERVICES:
        assert any(
            key.startswith(service + '-') and any(
                entry.get('enabled') for entry in values)
            for key, values in rules.items()
        ), service
