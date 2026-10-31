"""Explicit, portable rule-fixture loading and coverage accounting."""

import ast
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
                if (not isinstance(config, dict) or not isinstance(config.get('services'), dict)
                        or not isinstance(expected, list) or any(not isinstance(item, str) for item in expected)):
                    raise FixtureError('Legacy fixture requires services and an expected item list')
            elif case['kind'] == 'characterization':
                source_case = case.get('source_case', case['id'])
                selected = config['cases'][source_case]
                if not isinstance(selected['response'], list) or not isinstance(selected['expected'], dict):
                    raise FixtureError('Invalid characterization case')
                if not isinstance(expected['cases'][source_case]['expected'], dict):
                    raise FixtureError('Missing characterization expectation')
                expectation = selected['expected']
                if (not isinstance(expectation['resources'], dict) or not isinstance(expectation['items'], list)
                        or not isinstance(expectation['checked_items'], int) or not isinstance(expectation['level'], str)):
                    raise FixtureError('Invalid characterization expectation')
            else:
                raise FixtureError('Unknown fixture kind')
        except FileNotFoundError:
            row['fixture_status'] = 'missing'
        except (FixtureError, KeyError, TypeError):
            row['fixture_status'] = 'invalid'
        inventory.append(row)
    return inventory


def validate_manifest_catalog(manifest, root=ROOT):
    providers = {'aws', 'azure', 'gcp'}
    if set(manifest['untested']) != providers or any(case['provider'] not in providers for case in manifest['cases']):
        raise FixtureError('Manifest must account for AWS, Azure and GCP')
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


def provider_catalog(provider, root=ROOT):
    """Structural inventory only; optional declarations do not establish support."""
    root = Path(root)
    base = root / 'ScoutSuite/providers' / provider
    tree = ast.parse((base / 'services.py').read_text(encoding='utf-8'))
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef))
    init = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == '__init__')

    def names(nodes):
        return {node.targets[0].attr for node in nodes if isinstance(node, ast.Assign)
                and isinstance(node.targets[0], ast.Attribute)
                and isinstance(node.targets[0].value, ast.Name) and node.targets[0].value.id == 'self'}

    core = names(init.body)
    all_services = names(ast.walk(init))
    metadata = json.loads((base / 'metadata.json').read_text(encoding='utf-8'))
    rules = json.loads((base / 'rules/rulesets/default.json').read_text(encoding='utf-8'))['rules']
    templates = root / 'ScoutSuite/output/data/html'
    return {'core_services': sorted(core), 'optional_declarations': sorted(all_services - core),
            'metadata_services': sorted({name for group in metadata.values() for name in group}),
            'default_rule_keys': sorted(rules),
            'templates': sorted(path.relative_to(templates).as_posix() for kind in ('partials', 'summaries')
                                for path in (templates / kind / provider).glob('*.html'))}
