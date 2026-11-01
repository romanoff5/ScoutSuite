"""M09-A: results schema, deterministic non-mutating serialization and v0 readers."""
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlitedict import SqliteDict

from ScoutSuite.output.result_encoder import (
    JavaScriptEncoder, ScoutResultEncoder, SqlLiteEncoder,
    UnsupportedReportVersion, prepare_results, validate_results,
)
from ScoutSuite.output.utils import get_filename
from tests.fixtures import ROOT


def synthetic_provider():
    return SimpleNamespace(
        provider_code='aws', service_list=['ec2'],
        services={'ec2': {
            'findings': {'ec2-instance-imdsv1-enabled': {
                'items': ['ec2.regions.us-east-1.vpcs.vpc-a.instances.i-a.imds_v2_status'],
                'flagged_items': 1, 'assessment_status': 'incomplete',
                'evaluation_summary': {'version': 1, 'counts': {
                    'secure': 0, 'insecure': 1, 'unknown': 1,
                    'not_applicable': 0}}}},
            'filters': {'saved-filter': {'items': []}}}},
        collection_status={'version': 1, 'status': 'partial',
                           'complete': False, 'issues': [{
                               'status': 'partial', 'scope': 'ec2',
                               'reason_code': 'RuleEvidenceUnknown'}]},
        credentials='SYNTHETIC_SECRET_NEVER_PUBLISH',
        profile='SYNTHETIC_PROFILE_PRIVATE',
        metadata_path='SYNTHETIC_PRIVATE_PATH',
        services_config={'sensitive': 'SYNTHETIC_PRIVATE_CONFIG'},
        last_run=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )


def test_to_dict_does_not_mutate_provider_and_omits_sensitive_fields():
    provider = synthetic_provider()
    original = dict(vars(provider))
    first = ScoutResultEncoder.to_dict(provider)
    second = ScoutResultEncoder.to_dict(provider)
    assert first == second
    assert vars(provider) == original
    assert all(hasattr(provider, name) for name in (
        'credentials', 'profile', 'metadata_path', 'services_config'))
    data = json.dumps(first)
    assert 'SYNTHETIC_SECRET' not in data
    assert 'SYNTHETIC_PROFILE_PRIVATE' not in data
    assert 'SYNTHETIC_PRIVATE_CONFIG' not in data
    assert first['services']['ec2']['findings']['ec2-instance-imdsv1-enabled']['flagged_items'] == 1


def test_prepare_results_versioned_copy_preserves_root_and_incomplete_evidence():
    provider = synthetic_provider()
    value = prepare_results(provider)
    assert value['report_schema_version'] == 1
    assert value['collection_status']['complete'] is False
    assert value['services']['ec2']['findings']['ec2-instance-imdsv1-enabled']['assessment_status'] == 'incomplete'
    assert not hasattr(provider, 'report_schema_version')
    assert 'credentials' in vars(provider)
    # A dict input should also have sensitive top-level fields removed, without
    # modifying the original mapping.
    original = {'services': {}, 'credentials': 'SYNTHETIC_SECRET'}
    assert 'credentials' not in prepare_results(original)
    assert original['credentials'] == 'SYNTHETIC_SECRET'


def test_javascript_results_round_trip_deterministic_and_private(tmp_path):
    provider = synthetic_provider()
    encoder = JavaScriptEncoder(report_name='synthetic', report_dir=str(tmp_path),
                                timestamp='test')
    encoder.save_to_file(provider, 'RESULTS', True, False)
    filename, first_line = get_filename('RESULTS', 'synthetic', str(tmp_path))
    text = (ROOT / 'tests' / 'data').exists() and open(filename, encoding='utf-8').read()
    assert text.startswith(first_line + '\n')
    assert 'SYNTHETIC_SECRET' not in text
    result = encoder.load_from_file('RESULTS')
    assert result['report_schema_version'] == 1
    assert result['services']['ec2']['findings']['ec2-instance-imdsv1-enabled']['flagged_items'] == 1
    encoder.save_to_file(provider, 'RESULTS', True, False)
    with open(filename, encoding='utf-8') as f:
        assert f.read() == text
    assert vars(provider)['credentials'] == 'SYNTHETIC_SECRET_NEVER_PUBLISH'


def test_sqlite_results_round_trip_and_correct_db_extension(tmp_path):
    provider = synthetic_provider()
    encoder = SqlLiteEncoder(report_name='synthetic', report_dir=str(tmp_path))
    encoder.save_to_file(provider, 'RESULTS', True, False)
    path, _ = get_filename('RESULTS', 'synthetic', str(tmp_path), file_extension='db')
    result = encoder.load_from_file('RESULTS')
    assert result['report_schema_version'] == 1
    assert result['collection_status']['status'] == 'partial'
    with SqliteDict(path) as db:
        assert 'credentials' not in db
        assert db['services']['ec2']['findings']['ec2-instance-imdsv1-enabled']['items']
    assert vars(provider)['credentials'] == 'SYNTHETIC_SECRET_NEVER_PUBLISH'


def test_legacy_unversioned_js_and_sqlite_are_readable(tmp_path):
    root = ROOT / 'tests/data/report-golden/aws-v0-results.js'
    legacy_js = JavaScriptEncoder(report_name='synthetic', report_dir=str(tmp_path))
    value = legacy_js.load_from_file('RESULTS', file_path=str(root), first_line='scoutsuite_results =')
    assert 'report_schema_version' not in value
    assert value['services']['iam']['findings']['iam-root-account-no-mfa']['flagged_items'] == 1

    path = tmp_path / 'old.db'
    with SqliteDict(str(path), autocommit=True) as db:
        for key, item in value.items():
            db[key] = item
    legacy_db = SqlLiteEncoder(report_name='synthetic', report_dir=str(tmp_path))
    assert legacy_db.load_from_file('RESULTS', config_path=str(path)) == value


@pytest.mark.parametrize('version', [2, -1, '1', 1.5, True, None])
def test_future_or_malformed_results_version_rejected(version, tmp_path):
    with pytest.raises(UnsupportedReportVersion):
        validate_results({'report_schema_version': version, 'services': {}})
    path = tmp_path / 'bad.js'
    path.write_text('scoutsuite_results =\n' +
                    json.dumps({'report_schema_version': version, 'services': {}}),
                    encoding='utf-8')
    with pytest.raises(UnsupportedReportVersion):
        JavaScriptEncoder().load_from_file('RESULTS', file_path=str(path),
                                          first_line='scoutsuite_results =')


def test_legacy_exceptions_and_errors_are_not_versioned(tmp_path):
    js = JavaScriptEncoder(report_name='synthetic', report_dir=str(tmp_path))
    for kind, value in [('EXCEPTIONS', {'ec2': {'saved-finding': []}}),
                        ('ERRORS', [{'message': 'synthetic'}])]:
        js.save_to_file(value, kind, True, False)
        assert js.load_from_file(kind) == value
        assert 'report_schema_version' not in str(js.load_from_file(kind))
