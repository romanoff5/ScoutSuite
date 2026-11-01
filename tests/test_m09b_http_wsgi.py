"""HTTP/WSGI integration smoke without sockets or subprocesses.

CherryPy handles the actual HTTP request pipeline; the offline guard remains
active, while network I/O is unnecessary for these synthetic requests.
"""
import io
import json
from wsgiref.util import setup_testing_defaults

import cherrypy
from sqlitedict import SqliteDict

from ScoutSuite.core.server import Server


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
