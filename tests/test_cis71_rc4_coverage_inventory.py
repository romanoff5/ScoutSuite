"""CIS v7.1.0 source inventory covers all recommendation IDs, not compliance."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWS = ROOT / 'ScoutSuite/providers/aws/rules'
CATALOG = AWS / 'catalogs/cis-foundations-v7.1.0-coverage.json'
PROFILE = AWS / 'rulesets/cis-foundations-7.1.0-partial.json'


def test_complete_94_control_inventory_and_no_false_certification():
    inventory = json.loads(CATALOG.read_text(encoding='utf-8'))
    profile = json.loads(PROFILE.read_text(encoding='utf-8'))
    assert inventory['benchmark']['version'] == '7.1.0'
    controls = inventory['controls']
    assert len(controls) == 94
    assert len({row['id'] for row in controls}) == 94
    assert set(row['status'] for row in controls) == {
        'candidate', 'manual_review', 'partial_existing_unmapped',
        'not_implemented'}
    assert all(row['evidence_verified'] is False and
               row['compliance_verified'] is False for row in controls)
    status_counts = {status: sum(row['status'] == status for row in controls)
                     for status in ('candidate', 'manual_review',
                                    'partial_existing_unmapped', 'not_implemented')}
    assert status_counts == {
        'candidate': 30, 'manual_review': 43,
        'partial_existing_unmapped': 13, 'not_implemented': 8}
    assert len(profile['rules']) == len(profile['control_mappings']) == 33
    mapped = {}
    for rule_filename, entries in profile['control_mappings'].items():
        assert rule_filename in profile['rules']
        assert (AWS / 'findings' / rule_filename).is_file()
        for entry in entries:
            assert entry['coverage'] == 'candidate'
            mapped.setdefault(entry['control_id'], []).append(rule_filename)
    assert len(mapped) == 30
    for item in controls:
        if item['status'] == 'candidate':
            assert sorted(item['candidate_rules']) == sorted(mapped[item['id']])
        else:
            assert item['id'] not in mapped
            assert 'candidate_rules' not in item
    assert profile['benchmark']['coverage'] == 'partial'
    assert all('text' not in item and 'description' not in item for item in controls)


def test_rc4_scoped_rules_registered_in_default_and_detailed():
    for name in ('default.json', 'detailed.json'):
        ruleset = json.loads((AWS / 'rulesets' / name).read_text(encoding='utf-8'))
        for rule in (
            'rds-instance-deletion-protection-disabled.json',
            'rds-cluster-deletion-protection-disabled.json',
            'efs-filesystem-not-encrypted.json',
            's3-bucket-public-access-block-incomplete.json',
            'securityhub-region-not-subscribed.json',
        ):
            assert ruleset['rules'][rule][0]['enabled'] is True
