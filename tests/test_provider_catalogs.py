import json

import pytest

from ScoutSuite import __main__ as cli_bootstrap
from ScoutSuite.providers import get_provider_object, providers_dict
from ScoutSuite.providers.base.provider import BaseProvider
from tests.fixtures import DATA, ROOT, provider_catalog


@pytest.mark.parametrize('provider', ['aws', 'azure', 'gcp'])
def test_provider_import_and_structural_contract(provider):
    assert callable(cli_bootstrap.run_from_cli)
    cls = get_provider_object(provider)
    assert cls.__name__ == providers_dict[provider]
    assert issubclass(cls, BaseProvider)
    expected = json.loads((DATA / 'provider-catalogs.json').read_text())[provider]
    assert provider_catalog(provider) == expected
    assert expected['core_services']
    assert expected['default_rule_keys']
    assert expected['templates']
    for rule in expected['default_rule_keys']:
        definition = ROOT / 'ScoutSuite/providers' / provider / 'rules/findings' / rule
        parsed = json.loads(definition.read_text(encoding='utf-8'))
        assert isinstance(parsed['conditions'], list)
        assert isinstance(parsed['path'], str)
    for template in expected['templates']:
        contents = (ROOT / 'ScoutSuite/output/data/html' / template).read_text(encoding='utf-8')
        assert '<script' in contents
        assert '</script>' in contents
