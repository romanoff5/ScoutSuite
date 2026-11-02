"""Exercise SQLite report APIs over real TCP loopback, in an offline network namespace.

Executed separately from guarded pytest (which correctly rejects all sockets).
No cloud credentials, external hosts, subprocesses or customer report data.
"""
import json
from pathlib import Path
import tempfile
from threading import Thread
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener
from wsgiref.simple_server import make_server, WSGIRequestHandler

import cherrypy
from sqlitedict import SqliteDict

from ScoutSuite.core.server import MAX_RESPONSE_BYTES, Server


class QuietHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        pass


def run_http_checks():
    with tempfile.TemporaryDirectory(prefix='scoutsuite-sqlite-http-') as folder:
        root = Path(folder)
        data = root / 'scoutsuite-results'
        data.mkdir()
        (root / 'report.html').write_text('<html>offline</html>', encoding='utf-8')
        db_path = data / 'scoutsuite_results_report.db'
        resources = {
            'r%05d' % i: {
                'name': 'resource-%05d' % i, 'active': i % 2 == 0,
                'count': i, 'notes': None if i == 0 else 'synthetic',
                'details': {'owner': 'team', 'region': 'test'},
                'events': [1, False, None],
            }
            for i in range(2400)
        }
        with SqliteDict(str(db_path)) as db:
            db['account_id'] = 'synthetic'
            db['services'] = {'ec2': {'instances_count': 2400, 'findings': {},
                                      'instances': resources}}
            db['scalars'] = [0, False, None, 'hello', {'a': 1}, [1, 2]]
            db['large'] = {'container': {'k%06d' % i: i for i in range(25000)},
                           'value': 0}
            db['oversized'] = {'payload': 'X' * (MAX_RESPONSE_BYTES + 1)}
            db.commit()

        api = Server(str(db_path))
        # Mirror the production /api mount, including WSGI PATH_INFO routing.
        tree = cherrypy._cptree.Tree()
        tree.mount(api, '/api')
        opener = build_opener(ProxyHandler({}))
        with make_server('127.0.0.1', 0, tree,
                         handler_class=QuietHandler) as httpd:
            port = httpd.server_port
            cherrypy.server.socket_port = port
            base = 'http://127.0.0.1:%d/api/' % port
            thread = Thread(target=httpd.serve_forever, daemon=True)
            thread.start()

            def request(route, query=None, expected=200, headers=None):
                url = base + route
                if query:
                    url += '?' + urlencode(query)
                req = Request(url, headers=headers or {})
                try:
                    with opener.open(req, timeout=15) as response:
                        status = response.status
                        body = response.read(MAX_RESPONSE_BYTES + 4096)
                except HTTPError as error:
                    status = error.code
                    body = error.read(4096)
                assert status == expected, (route, status, expected, body[:300])
                if expected != 200:
                    return None
                assert len(body) <= MAX_RESPONSE_BYTES + 4096
                return json.loads(body)['data']

            try:
                assert request('summary')['services']['ec2']['instances_count'] == 2400
                base_key = 'services¤ec2¤instances'
                first = request('page', {'key': base_key, 'page': 0, 'pagesize': 40})
                second = request('page', {'key': base_key, 'page': 1, 'pagesize': 40})
                end = request('page', {'key': base_key, 'page': 59, 'pagesize': 40})
                assert len(first) == len(second) == len(end) == 40
                assert not set(first).intersection(second)
                assert list(first)[0] == 'r00000'
                assert list(end)[-1] == 'r02399'
                assert request('page', {'key': base_key, 'page': 60, 'pagesize': 40}) == {}
                assert first['r00000']['type'] == 'dict'
                assert 'name' in first['r00000']['keys']
                full = request('full', {'key': base_key + '¤r00000'})
                assert full['active'] is True
                assert full['count'] == 0 and full['notes'] is None
                assert full['events'] == [1, False, None]
                assert request('page', {'key': 'scalars', 'page': 0, 'pagesize': 6}) == [
                    0, False, None, 'hello', {'type': 'dict', 'keys': ['a']},
                    {'type': 'list', 'length': 2}]
                metadata = request('page', {'key': 'large', 'page': 0, 'pagesize': 2})
                assert metadata['value'] == 0
                assert metadata['container']['type'] == 'dict'
                assert metadata['container']['truncated'] is True
                assert len(metadata['container']['keys']) == 100
                assert metadata['container']['length'] == 25000
                assert len(json.dumps(metadata)) < 4000
                request('full', {'key': 'oversized'}, expected=413)
                request('page', {'key': 'oversized', 'page': 0, 'pagesize': 1},
                        expected=413)
                assert request('data', {'key': 'oversized'}) == {
                    'type': 'dict', 'keys': ['payload']}
                request('page', {'key': base_key, 'page': '-1', 'pagesize': 10},
                        expected=400)
                request('summary', expected=403,
                        headers={'Origin': 'https://example.invalid'})
                request('summary', expected=403,
                        headers={'Host': 'invalid.example'})
                request('scoutsuite-results/scoutsuite_results_report.db', expected=404)
                print('Real TCP loopback SQLite HTTP integration: PASSED (2400 resources, '
                      '25000 keys, 8 MiB rejection, same-origin checks)', flush=True)
            finally:
                httpd.shutdown()
                thread.join(timeout=10)
                api.results.close()
                assert not thread.is_alive()


if __name__ == '__main__':
    run_http_checks()
