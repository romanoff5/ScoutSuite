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

# M11 is the single explicitly-authorized exception to the M07 frozen baseline.
# The manifest is deliberately not rebaselined; unrelated provider files remain hash-gated.
M11_ALLOWED = {
    'gcp': frozenset({
        'facade/kms.py', 'facade/stackdrivermonitoring.py',
        'resources/stackdrivermonitoring/monitoring_alert_policies.py',
    }),
    'azure': frozenset({
        'facade/sqldatabase.py',
        'resources/sqldatabase/database_threat_detection_policies.py',
        'resources/sqldatabase/server_security_alert_policies.py',
    }),
}
M11_DEPENDENCIES = {
    'google-cloud-kms==1.3.0': 'google-cloud-kms==3.17.0',
    'google-cloud-monitoring==1.1.0': 'google-cloud-monitoring==2.31.0',
    'azure-mgmt-sql==1.0.0': 'azure-mgmt-sql==4.0.0',
}



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
        if name not in M11_ALLOWED[provider] and _blob_sha(path) != expected[name]
    )
    assert not changed, (
        f'{provider} SDK/collector/rule content drift: {changed[:12]}. '
        'A deliberate Azure/GCP migration requires its own reviewed scope '
        'and a new preservation baseline; do not regenerate golden hashes to pass.'
    )

    assert M11_ALLOWED[provider] <= set(expected)
    assert all(_blob_sha(actual_paths[name]) != expected[name]
               for name in M11_ALLOWED[provider]), 'M11 file unexpectedly reverted'

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
    approved_lines = [M11_DEPENDENCIES.get(line, line)
                      for line in snapshot['dependency_lines']]
    assert actual == approved_lines, (
        'M07 preservation: declared Azure/GCP dependencies changed. '
        'Review the migration scope and record new compatibility evidence.'
    )
