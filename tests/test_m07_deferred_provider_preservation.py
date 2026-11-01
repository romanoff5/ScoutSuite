"""M07 deferred-provider preservation: exact offline source and SDK drift gate.

Checks the committed pre-M07 Azure/GCP provider trees without importing SDKs,
discovering credentials, starting processes or accessing the network.
"""
import hashlib
import json
from pathlib import Path

import pytest

from tests.fixtures import ROOT


MANIFEST = ROOT / 'tests' / 'data' / 'm07-provider-preservation.json'
PROVIDER_ROOT = ROOT / 'ScoutSuite' / 'providers'
REQUIREMENTS = ROOT / 'requirements.txt'


def _expected():
    data = json.loads(MANIFEST.read_text(encoding='utf-8'))
    assert data['schema_version'] == 1
    assert data['path_prefix'] == 'ScoutSuite/providers'
    assert data['content_hash'] == 'git-blob-sha1-lf-normalized'
    return data


def _blob_sha(path: Path) -> str:
    """Use Git's blob hash to compare against the committed tree on both OSes."""
    content = path.read_bytes().replace(b'\r\n', b'\n')
    header = b'blob ' + str(len(content)).encode('ascii') + b'\0'
    return hashlib.sha1(header + content).hexdigest()


@pytest.mark.parametrize('provider', ('azure', 'gcp'))
def test_deferred_provider_source_rules_and_assets_are_unchanged(provider):
    snapshot = _expected()['providers'][provider]
    expected = snapshot['files']
    root = PROVIDER_ROOT / provider
    actual_paths = {
        path.relative_to(root).as_posix(): path
        for path in root.rglob('*')
        if path.is_file() and path.suffix in ('.py', '.json')
    }

    missing = sorted(set(expected) - set(actual_paths))
    unexpected = sorted(set(actual_paths) - set(expected))
    assert not missing, f'{provider} files removed: {missing[:12]}'
    assert not unexpected, f'{provider} files added: {unexpected[:12]}'

    changed = sorted(
        name for name, path in actual_paths.items()
        if _blob_sha(path) != expected[name]
    )
    assert not changed, (
        f'{provider} SDK/collector/rule content drift: {changed[:12]}. '
        'A deliberate Azure/GCP migration requires its own reviewed scope '
        'and a new preservation baseline; do not regenerate golden hashes to pass.'
    )

    assert sum(name.endswith('.py') for name in expected) == snapshot['counts']['python']
    assert sum(name.endswith('.json') for name in expected) == snapshot['counts']['json']
    assert sum(
        name.startswith('rules/findings/') for name in expected
    ) == snapshot['counts']['finding_rules']


def test_deferred_azure_gcp_dependency_constraints_are_unchanged():
    snapshot = _expected()
    lines = REQUIREMENTS.read_text(encoding='utf-8').splitlines()
    begin = lines.index('# GCP Provider')
    end = lines.index('# Aliyun / Alibaba Cloud Provider', begin + 1)
    actual = [
        line.strip() for line in lines[begin + 1:end]
        if line.strip() and not line.lstrip().startswith('#')
    ]
    assert actual == snapshot['dependency_lines'], (
        'M07 preservation: declared Azure/GCP dependencies changed. '
        'Review the migration scope and record new compatibility evidence.'
    )
