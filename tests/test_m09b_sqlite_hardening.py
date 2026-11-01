"""Offline regression checks for safe SQLite report reads and viewer routing."""
import pickle
from pathlib import Path

import cherrypy
import pytest
from sqlitedict import SqliteDict

from ScoutSuite.core.server import Server, MAX_RESPONSE_BYTES
from ScoutSuite.output.safe_sqlite import decode_sqlite_value


def test_sqlite_decoder_preserves_legacy_json_values():
    original = {'services': {'ec2': {'count': 2, 'enabled': True}},
                'items': [None, 2, 1.25, 'resource-name']}
    assert decode_sqlite_value(pickle.dumps(original)) == original


def test_sqlite_decoder_rejects_globals_without_executing(tmp_path):
    marker = tmp_path / 'executed'
    class Attack:
        def __reduce__(self):
            return (eval, (f"__import__('pathlib').Path({str(marker)!r}).write_text('bad')",))
    with pytest.raises(pickle.UnpicklingError):
        decode_sqlite_value(pickle.dumps(Attack()))
    assert not marker.exists()


@pytest.mark.parametrize('payload', [
    {'bad': (1, 2)}, {42: 'bad'}, {'bad': {1, 2}}, b'not a pickle',
])
def test_sqlite_decoder_rejects_non_json_data(payload):
    with pytest.raises((pickle.UnpicklingError, EOFError)):
        decode_sqlite_value(pickle.dumps(payload) if not isinstance(payload, bytes) else payload)


def test_standard_report_root_and_legacy_sqlite_roundtrip(tmp_path):
    report_root = tmp_path / 'report'
    data_root = report_root / 'scoutsuite-results'
    data_root.mkdir(parents=True)
    report = report_root / 'assessment.html'
    report.write_text('<html>OK</html>', encoding='utf-8')
    (report_root / 'inc-scoutsuite').mkdir()
    script = report_root / 'inc-scoutsuite' / 'scoutsuite.js'
    script.write_text('/* trusted asset */', encoding='utf-8')
    database_path = data_root / 'scoutsuite_results_assessment.db'
    with SqliteDict(str(database_path)) as database:
        database['services'] = {'ec2': {'findings': {'sample': {'level': 'warning'}},
                                         'instances_count': 1, 'instances': {'id': {}}}}
        database['account_id'] = 'synthetic'
        database.commit()
    server = Server(str(database_path))
    assert server.report_root == report_root.resolve()
    assert server.report_filename == report.name
    assert server.results['account_id'] == 'synthetic'
    assert server.results['services']['ec2']['instances_count'] == 1
    assert (server.report_root / server.report_filename).is_file()
    assert (server.report_root / 'inc-scoutsuite' / 'scoutsuite.js').is_file()
    assert server.bounded_payload({'data': 'ok'}) == {'data': 'ok'}
    assert server.bounded_payload({'data': {'key': [1, 2]}}) == {'data': {'key': [1, 2]}}
    server.results.close()


def test_large_response_fails_closed():
    with pytest.raises(cherrypy.HTTPError) as error:
        Server.bounded_payload({'data': 'X' * MAX_RESPONSE_BYTES})
    assert error.value.status == 413


def test_no_active_css_functions_in_sanitizer():
    source = (Path(__file__).resolve().parents[1] / 'ScoutSuite/output/data/inc-scoutsuite/report_sanitizer.js')
    content = source.read_text(encoding='utf-8')
    assert 'SAFE_STYLE_PROPERTIES' in content
    assert 'sanitizeInlineStyle(value)' in content
    assert '/^[a-zA-Z0-9#.% +,-]+$/' in content
