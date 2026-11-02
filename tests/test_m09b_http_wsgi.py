"""HTTP/WSGI integration smoke without sockets or subprocesses.

CherryPy handles the actual HTTP request pipeline; the offline guard remains
active, while network I/O is unnecessary for these synthetic requests.
"""
import io
import json
from wsgiref.util import setup_testing_defaults

import cherrypy
from sqlitedict import SqliteDict

from ScoutSuite.core.server import Server, MAX_RESPONSE_BYTES


def _request(app, path, query='', host='127.0.0.1:8000', origin=None):
    environ = {}
    setup_testing_defaults(environ)
    environ.update({
        'REQUEST_METHOD': 'GET',
        'SCRIPT_NAME': '/api',
        'PATH_INFO': path,
        'QUERY_STRING': query,
        'SERVER_NAME': '127.0.0.1',
        'SERVER_PORT': '8000',
        'HTTP_HOST': host,
        'wsgi.input': io.BytesIO(),
    })
    if origin:
        environ['HTTP_ORIGIN'] = origin
    result = {}

    def start_response(status, headers, exc_info=None):
        result['status'] = int(status.split()[0])
        result['headers'] = dict(headers)

    chunks = app(environ, start_response)
    try:
        result['body'] = b''.join(chunks)
    finally:
        if hasattr(chunks, 'close'):
            chunks.close()
    return result


def test_real_cherrypy_wsgi_report_and_api_routes(tmp_path):
    report_root = tmp_path / 'reports'
    data = report_root / 'scoutsuite-results'
    assets = report_root / 'inc-scoutsuite'
    data.mkdir(parents=True)
    assets.mkdir()
    (report_root / 'sample.html').write_text('<html>synthetic</html>', encoding='utf-8')
    (assets / 'scoutsuite.js').write_text('/* offline */', encoding='utf-8')
    db = data / 'scoutsuite_results_sample.db'
    with SqliteDict(str(db)) as database:
        database['account_id'] = 'synthetic'
        database['services'] = {'ec2': {'instances_count': 2, 'findings': {}}}
        database.commit()
    server = Server(str(db))
    app = cherrypy.Application(server, script_name='/api')
    cherrypy.server.socket_port = 8000
    try:
        html = _request(app, '/sample.html')
        assert html['status'] == 200, html
        assert b'synthetic' in html['body']
        js = _request(app, '/inc-scoutsuite/scoutsuite.js')
        assert js['status'] == 200, js
        summary = _request(app, '/summary')
        assert summary['status'] == 200, summary
        assert json.loads(summary['body'])['data']['account_id'] == 'synthetic'
        blocked = _request(app, '/scoutsuite-results/scoutsuite_results_sample.db')
        assert blocked['status'] == 404
        assert _request(app, '/unrelated.html')['status'] == 404
        assert _request(app, '/summary', host='evil.example')['status'] == 403
        assert _request(app, '/summary', origin='https://evil.example')['status'] == 403
        assert _request(app, '/full')['status'] == 400
        page = _request(app, '/page', query='key=services%C2%A4ec2%C2%A4findings&page=0&pagesize=2')
        assert page['status'] == 200, page
    finally:
        server.results.close()


def test_paginated_sqlite_http_preserves_scalars_and_bounds_nested_data(tmp_path):
    """Exercise genuine CherryPy HTTP/WSGI routing with a disk SQLite report."""
    from urllib.parse import urlencode

    db = tmp_path / 'scoutsuite_results_report.db'
    resources = {
        'r%04d' % i: {
            'name': 'resource-%04d' % i,
            'active': i % 2 == 0,
            'risk': None if i == 0 else i,
            'details': {'owner': 'team', 'zone': 'test'},
            'events': [{'id': j} for j in range(3)],
        }
        for i in range(1500)
    }
    huge = {'k%06d' % i: i for i in range(30000)}
    with SqliteDict(str(db)) as writer:
        writer['resources'] = resources
        writer['entries'] = [1, False, None, {'nested': 'value'}, ['nested'], 0]
        writer['large'] = {'container': huge, 'scalar': 0}
        writer['account_id'] = 'synthetic'
        writer.commit()

    server = Server(str(db))
    app = cherrypy.Application(server, script_name='/api')
    cherrypy.server.socket_port = 8000

    def get(path, key, index=0, size=10):
        query = urlencode({'key': key, 'page': index, 'pagesize': size})
        response = _request(app, path, query=query)
        assert response['status'] == 200, response
        return json.loads(response['body'])['data']

    try:
        first = get('/page', 'resources', 0, 10)
        second = get('/page', 'resources', 1, 10)
        last = get('/page', 'resources', 149, 10)
        assert len(first) == len(second) == len(last) == 10
        assert not (set(first) & set(second))
        assert first['r0000']['type'] == 'dict'
        assert first['r0000']['keys'] == ['name', 'active', 'risk', 'details', 'events']
        assert list(second) == ['r%04d' % i for i in range(10, 20)]
        assert list(last)[-1] == 'r1499'
        assert get('/page', 'resources', 150, 10) == {}

        # Fetch selected resource in full; the page must not embed it.
        full = _request(app, '/full', query=urlencode({'key': 'resources¤r0000'}))
        assert full['status'] == 200, full
        obj = json.loads(full['body'])['data']
        assert obj['name'] == 'resource-0000'
        assert obj['active'] is True and obj['risk'] is None
        assert obj['events'] == [{'id': j} for j in range(3)]

        entries = get('/page', 'entries', 0, 6)
        assert entries == [1, False, None, {'type': 'dict', 'keys': ['nested']},
                           {'type': 'list', 'length': 1}, 0]
        assert get('/page', 'large', 0, 10)['scalar'] == 0
        large_meta = get('/page', 'large', 0, 10)['container']
        assert large_meta['type'] == 'dict'
        assert large_meta['truncated'] is True
        assert large_meta['length'] == 30000
        assert len(large_meta['keys']) == 100
        assert len(json.dumps(large_meta)) < 4000

        # A genuinely oversized SQLite value must not escape through /full.\n        oversized = _request(app, '/full', query=urlencode({'key': 'oversized'}))\n        assert oversized['status'] == 413\n        oversized_page = _request(app, '/page', query=urlencode(\n            {'key': 'oversized', 'page': 0, 'pagesize': 1}))\n        assert oversized_page['status'] == 413\n        header = _request(app, '/data', query=urlencode({'key': 'oversized'}))\n        assert header['status'] == 200\n        assert json.loads(header['body'])['data']['keys'] == ['payload']\n\n        # Invalid pagination and cross-origin checks remain effective.
        bad = _request(app, '/page',
                       query=urlencode({'key': 'resources', 'page': '-1', 'pagesize': 20}))
        assert bad['status'] == 400
        assert _request(app, '/page', query=urlencode(
            {'key': 'resources', 'page': 0, 'pagesize': 1}),
            origin='https://example.invalid')['status'] == 403
    finally:
        server.results.close()
