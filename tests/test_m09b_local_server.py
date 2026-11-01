"""M09-B: bounded, bearer-authorized, read-only local SQLite API."""
from pathlib import Path
import pickle

import cherrypy
import pytest
from sqlitedict import SqliteDict

from ScoutSuite.output.safe_pickle import UnsafeReportValue, decode_report_pickle
from ScoutSuite.output.result_encoder import SqlLiteEncoder
from ScoutSuite.core.server import (
    Server, pagination, validate_key, validate_viewer_request,
)


@pytest.fixture
def local_db(tmp_path):
    path = tmp_path / 'scoutsuite_results_test.db'
    with SqliteDict(str(path), autocommit=True) as db:
        db['provider_code'] = 'aws'
        db['report_schema_version'] = 1
        db['services'] = {
            'ec2': {'regions': {'us-east-1': {'instances': {'i-1': {'safe': True}}}},
                    'findings': {'x': {'flagged_items': 1}},
                    'filters': {}, 'instances_count': 1}}
    return path


def test_valid_sqlite_reads_preserve_summary_navigation_and_count(local_db):
    api = Server(str(local_db), viewer_token='A' * 32)
    assert api.summary()['data']['services']['ec2']['findings']['x']['flagged_items'] == 1
    assert api.data('services¤ec2¤regions')['data']['type'] == 'dict'
    assert api.full('services¤ec2¤regions¤us-east-1¤instances')['data']['i-1']['safe']
    assert api.page('services¤ec2¤regions¤us-east-1¤instances',
                    page='0', pagesize='25')['data']['i-1']['type'] == 'dict'
    assert api.get_item({'a': [0, 1]}, 'a¤1') == 1
    assert 'x' in api.summary()['data']['services']['ec2']['findings']


@pytest.mark.parametrize('value', [
    '../etc/passwd', # a literal dict key is not a filesystem path; remains lookup only
])
def test_path_is_treated_as_data_not_disk(local_db, value):
    api = Server(str(local_db), viewer_token='B' * 32)
    with pytest.raises(cherrypy.HTTPError) as e:
        api.full(value)
    assert e.value.status == 404


@pytest.mark.parametrize('bad', [
    'a¤', 'a¤__proto__', 'constructor', 'prototype', 'abc\x00def',
    'a¤' * 100, 'a' * 2049,
])
def test_reject_invalid_navigation_path(bad):
    with pytest.raises(ValueError):
        validate_key(bad)


@pytest.mark.parametrize(('page', 'size'), [
    ('-1', '100'), ('0', '0'), ('0', '501'),
    ('1e9', '50'), ('10000000', '500'), ('0', 'x'),
    ('0', '1.5'), ('1', None), (0, '10'),
])
def test_pagination_fails_closed(page, size):
    with pytest.raises(ValueError):
        pagination(page, size)


def test_pagination_and_real_resource_id_are_compatible():
    assert pagination('1', '500') == (500, 500)
    assert validate_key('services¤ec2¤regions¤eu-west-1¤vpcs¤vpc-12345')[-1] == 'vpc-12345'


def test_http_origin_and_token_enforcement():
    expected = 'S' * 32
    assert validate_viewer_request('null', expected, expected)
    assert validate_viewer_request(None, expected, expected)
    assert not validate_viewer_request('https://example.org', expected, expected)
    assert not validate_viewer_request('http://127.0.0.1:1234', expected, expected)
    assert not validate_viewer_request('null', 'wrong', expected)
    assert not validate_viewer_request('null', None, expected)
    assert validate_viewer_request('null', None, expected, method='OPTIONS')
    assert not validate_viewer_request('https://evil.test', None, expected, method='OPTIONS')
    assert not validate_viewer_request('null', expected, expected, method='POST')


def test_untrusted_sqlite_header_and_symlink_rejected(tmp_path, local_db):
    bad = tmp_path / 'invalid.db'
    bad.write_bytes(b'not a SQLite report')
    with pytest.raises(ValueError, match='SQLite header'):
        Server(str(bad))
    link = tmp_path / 'linked.db'
    try:
        link.symlink_to(local_db)
    except OSError:
        pytest.skip('Symlink creation is unavailable for this account')
    with pytest.raises(ValueError, match='Invalid report database'):
        Server(str(link))


def test_server_starts_only_on_fixed_loopback_with_local_token(monkeypatch, local_db):
    seen = {}
    def fake_quickstart(root, mount, config):
        seen.update(root=root, mount=mount, config=config)
    monkeypatch.setattr(cherrypy, 'quickstart', fake_quickstart)
    with pytest.raises(ValueError, match='loopback'):
        Server.init(str(local_db), '0.0.0.0', 8000)
    with pytest.raises(ValueError, match='loopback'):
        Server.init(str(local_db), '127.0.0.1', 8001)
    Server.init(str(local_db), '127.0.0.1', 8000)
    assert seen['mount'] == '/api'
    assert seen['config']['/']['tools.scout_viewer_guard.on']
    token = seen['root'].viewer_token
    assert len(token) >= 32
    file = Path(local_db).parent / 'scoutsuite_viewer_session.js'
    assert token in file.read_text(encoding='utf8')
    assert 'http' not in file.read_text(encoding='utf8')


class _Poison:
    def __reduce__(self):
        return (eval, ("__import__('os').system('echo UNSAFE-PICKLE')",))


def test_legacy_sqlite_pickle_decoder_allows_only_json_values():
    benign = {'services': {'ec2': {'findings': {'example': {
        'items': ['a', 'b'], 'flagged_items': 1}}}},
        'collection_status': {'complete': False, 'issues': []}}
    assert decode_report_pickle(pickle.dumps(benign)) == benign
    assert decode_report_pickle(pickle.dumps([None, True, 'text', 3, 1.25])) == [
        None, True, 'text', 3, 1.25]
    with pytest.raises(UnsafeReportValue):
        decode_report_pickle(pickle.dumps(_Poison()))
    with pytest.raises(UnsafeReportValue):
        decode_report_pickle(pickle.dumps({'x': 1}) + b'junk')
    with pytest.raises(UnsafeReportValue):
        decode_report_pickle(pickle.dumps({'x': {1: 'not a JSON key'}}))


def test_untrusted_sqlite_pickled_globals_rejected_by_server_and_loader(tmp_path):
    db_file = tmp_path / 'malicious.db'
    with SqliteDict(str(db_file), autocommit=True) as db:
        db['provider_code'] = 'aws'
        db['report_schema_version'] = 1
        db['services'] = {}
        db['payload'] = _Poison()
    with pytest.raises(UnsafeReportValue):
        Server(str(db_file))
    reader = SqlLiteEncoder(report_name='malicious', report_dir=str(tmp_path))
    with pytest.raises(UnsafeReportValue):
        reader.load_from_file('RESULTS', config_path=str(db_file))
