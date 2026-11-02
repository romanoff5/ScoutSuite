"""M10 default AWS service inclusion contract without live cloud access."""
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ScoutSuite.providers.aws.provider import AWSProvider


M10_SERVICES = frozenset({
    'accessanalyzer', 'guardduty', 'securityhub', 'organizations',
    'inspector2', 'ecr', 'ecs', 'eks', 'wafv2',
})


def fake_services(credentials):
    values = {'credentials': credentials, 'iam': {}, 's3': {}}
    values.update({name: {} for name in M10_SERVICES})
    return SimpleNamespace(**values)


def build_provider(services=None, skipped_services=None):
    credentials = SimpleNamespace(session=object())
    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig', fake_services), \
         patch('ScoutSuite.providers.aws.provider.get_partition_name', return_value='aws'), \
         patch('ScoutSuite.providers.aws.provider.get_aws_account_id',
               return_value='000000000000'):
        return AWSProvider(credentials=credentials, services=services,
                           skipped_services=skipped_services)


def test_every_m10_service_is_in_the_normal_aws_scan():
    normal = build_provider()
    assert M10_SERVICES.issubset(set(normal.service_list))
    assert {'iam', 's3'}.issubset(set(normal.service_list))
    assert len(normal.service_list) == len(set(normal.service_list))


@pytest.mark.parametrize('service', sorted(M10_SERVICES))
def test_every_m10_service_can_be_selected_individually(service):
    assert build_provider(services=[service]).service_list == [service]


@pytest.mark.parametrize('service', sorted(M10_SERVICES))
def test_every_m10_service_can_be_excluded_from_default_scan(service):
    result = build_provider(skipped_services=[service])
    assert service not in result.service_list
    assert M10_SERVICES.difference({service}).issubset(set(result.service_list))


def test_multiple_explicit_skips_do_not_disable_unrelated_m10_services():
    skipped = ['securityhub', 'inspector2', 'ecs']
    actual = set(build_provider(skipped_services=skipped).service_list)
    assert not actual.intersection(skipped)
    assert M10_SERVICES.difference(skipped).issubset(actual)


def test_explicit_selection_and_skip_filter_are_composed():
    chosen = build_provider(
        services=['guardduty', 'organizations', 'eks'],
        skipped_services=['organizations'])
    assert set(chosen.service_list) == {'guardduty', 'eks'}


def test_aws_local_replay_never_instantiates_any_live_provider():
    with patch('ScoutSuite.providers.aws.provider.AWSServicesConfig') as constructor:
        provider = AWSProvider(fetch_local=True)
        constructor.assert_not_called()
        assert M10_SERVICES.isdisjoint(set(provider.service_list))
