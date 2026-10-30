"""Explicit, portable rule-fixture loading and coverage accounting."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'tests/data'
MANIFEST = DATA / 'rule-fixtures.json'


class FixtureError(ValueError):
    pass


def load_fixture(path, root=DATA):
    """Resolve native symlinks and Windows Git text aliases without invoking Git."""
    root = Path(root).resolve()
    path = Path(path)
    seen = set()
    while True:
        try:
            resolved = path.resolve()
            resolved.relative_to(root)
        except (ValueError, RuntimeError, OSError) as error:
            raise FixtureError('Fixture escapes its root or has a symlink cycle') from error
        if resolved in seen:
            raise FixtureError('Fixture alias cycle')
        seen.add(resolved)
        try:
            text = resolved.read_text(encoding='utf-8')
        except FileNotFoundError:
            raise
        try:
            return json.loads(text)
        except json.JSONDecodeError as error:
            alias = text.strip()
            if '\n' not in alias and alias.endswith('.json') and not alias.startswith(('{', '[', '"')):
                if Path(alias).is_absolute() or '..' in Path(alias).parts:
                    raise FixtureError('Unsafe fixture alias') from error
                path = resolved.parent / alias
            else:
                raise FixtureError('Invalid fixture JSON') from error


def case_key(case):
    return ':'.join((case['provider'], case['rule'], case['id']))


def read_manifest(path=MANIFEST):
    manifest = json.loads(Path(path).read_text(encoding='utf-8'))
    if manifest.get('version') != 1:
        raise FixtureError('Unknown fixture manifest version')
    keys = [case_key(case) for case in manifest['cases']]
    if len(set(keys)) != len(keys):
        raise FixtureError('Duplicate fixture case')
    return manifest


def fixture_inventory(manifest, data=DATA):
    """Presence/validity is distinct from runtime verification by pytest."""
    inventory = []
    for case in manifest['cases']:
        row = dict(case, key=case_key(case), fixture_status='valid', test_status='not_run')
        try:
            config = load_fixture(Path(data) / case['input'], root=data)
            expected = load_fixture(Path(data) / case['expected'], root=data)
            if case['kind'] == 'legacy':
                if not isinstance(config, dict) or 'services' not in config or not isinstance(expected, list):
                    raise FixtureError('Legacy fixture requires services and an expected item list')
            elif case['kind'] == 'characterization':
                selected = config['cases'][case['id']]
                if not isinstance(selected['response'], list) or not isinstance(selected['expected'], dict):
                    raise FixtureError('Invalid characterization case')
                if not isinstance(expected['cases'][case['id']]['expected'], dict):
                    raise FixtureError('Missing characterization expectation')
            else:
                raise FixtureError('Unknown fixture kind')
        except FileNotFoundError:
            row['fixture_status'] = 'missing'
        except (FixtureError, KeyError, TypeError):
            row['fixture_status'] = 'invalid'
        inventory.append(row)
    return inventory


def validate_manifest_catalog(manifest, root=ROOT):
    for provider, untested in manifest['untested'].items():
        rules_path = Path(root) / 'ScoutSuite/providers' / provider / 'rules/rulesets/default.json'
        catalog = set(json.loads(rules_path.read_text(encoding='utf-8'))['rules'])
        declared = {case['rule'] for case in manifest['cases'] if case['provider'] == provider}
        if len(untested) != len(set(untested)) or set(untested) & declared:
            raise FixtureError('Ambiguous untested-rule declaration: ' + provider)
        if catalog != declared | set(untested):
            raise FixtureError('Rule catalog drift requires manifest review: ' + provider)
    invalid = [row['key'] + '=' + row['fixture_status'] for row in fixture_inventory(manifest)
               if row['fixture_status'] != 'valid']
    if invalid:
        raise FixtureError('Incomplete declared coverage: ' + ', '.join(invalid))
