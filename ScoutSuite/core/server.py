"""Bounded read-only local report API; never expose report data to websites."""
import json
import re
import secrets
from pathlib import Path

import cherrypy
from sqlitedict import SqliteDict

from ScoutSuite.output.result_encoder import validate_results

_SEPARATOR = '¤'
_MAX_KEY_LENGTH = 2048
_MAX_SEGMENTS = 64
_MAX_PAGE_SIZE = 500
_MAX_PAGE_OFFSET = 5_000_000
_MAX_RESPONSE_BYTES = 3 * 1024 * 1024
_FORBIDDEN_KEYS = frozenset(('__proto__', 'constructor', 'prototype'))


def validate_key(key):
    """Validate a report navigation key without assuming AWS IDs are alphanumeric."""
    if key is None:
        return []
    if not isinstance(key, str) or len(key) > _MAX_KEY_LENGTH:
        raise ValueError('Invalid report key')
    parts = key.split(_SEPARATOR)
    if (len(parts) > _MAX_SEGMENTS or any(not part or part in _FORBIDDEN_KEYS
            or any(ord(char) < 32 or ord(char) == 127 for char in part)
            for part in parts)):
        raise ValueError('Invalid report key')
    return parts


def pagination(page, pagesize):
    """Limit paging to bounded, nonnegative integers."""
    if (not isinstance(page, str) or not re.fullmatch(r'[0-9]{1,8}', page)
            or not isinstance(pagesize, str)
            or not re.fullmatch(r'[0-9]{1,4}', pagesize)):
        raise ValueError('Malformed pagination')
    index, size = int(page), int(pagesize)
    if size < 1 or size > _MAX_PAGE_SIZE or index * size > _MAX_PAGE_OFFSET:
        raise ValueError('Pagination exceeds report API limits')
    return index * size, size


def validate_viewer_request(origin, token, expected_token, method='GET'):
    """A file:// viewer sends Origin:null; a bearer token prevents null-origin exfil.

    No remote HTTP(S) origin may use this API, even with a guessed session token.
    """
    if origin not in (None, 'null') or method not in ('GET', 'OPTIONS'):
        return False
    if method == 'OPTIONS':
        return origin == 'null'
    return isinstance(token, str) and secrets.compare_digest(token, expected_token)


def _viewer_guard():
    request = cherrypy.request
    root = request.app.root
    origin = request.headers.get('Origin')
    method = request.method
    token = request.headers.get('X-Scout-Viewer-Token')
    if not validate_viewer_request(origin, token, root.viewer_token, method):
        raise cherrypy.HTTPError(403, 'Report viewer request denied')
    cherrypy.response.headers['Cache-Control'] = 'no-store'
    cherrypy.response.headers['X-Content-Type-Options'] = 'nosniff'
    cherrypy.response.headers['Vary'] = 'Origin'
    if origin == 'null':
        cherrypy.response.headers['Access-Control-Allow-Origin'] = 'null'
    if method == 'OPTIONS':
        if (request.headers.get('Access-Control-Request-Method') != 'GET'
                or request.headers.get('Access-Control-Request-Headers', '').lower()
                not in ('x-scout-viewer-token', '')):
            raise cherrypy.HTTPError(403, 'Invalid viewer preflight')
        cherrypy.response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        cherrypy.response.headers['Access-Control-Allow-Headers'] = 'X-Scout-Viewer-Token'
        cherrypy.response.status = 204
        cherrypy.request.handler = lambda: b''


def _api_call(fn):
    """Conceal report internals; do not turn malformed paths into 500s."""
    try:
        result = fn()
        if len(json.dumps(result, default=str).encode('utf-8')) > _MAX_RESPONSE_BYTES:
            raise cherrypy.HTTPError(413, 'Response exceeds local viewer limit')
        return {'data': result}
    except (ValueError, TypeError):
        raise cherrypy.HTTPError(400, 'Invalid report request')
    except (IndexError, KeyError):
        raise cherrypy.HTTPError(404, 'Report key not found')


class Server:
    """Read-only report data over loopback, with a session token from a local file."""

    def __init__(self, filename, viewer_token=None):
        filename = Path(filename)
        if (not filename.is_file() or filename.is_symlink()
                or filename.stat().st_size < 16
                or filename.stat().st_size > 2 * 1024 * 1024 * 1024):
            raise ValueError('Invalid report database file')
        with filename.open('rb') as fp:
            if fp.read(16) != b'SQLite format 3\x00':
                raise ValueError('Invalid report SQLite header')
        self.viewer_token = viewer_token or secrets.token_urlsafe(32)
        self.results = SqliteDict(str(filename), flag='r')
        validate_results(dict(self.results))

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def summary(self):
        def render():
            data = dict(self.results)
            stripped_services = {}
            for name, service in data.get('services', {}).items():
                selected = {}
                for key, value in service.items():
                    if key in ('findings', 'filters') or re.fullmatch(r'.*_count', key):
                        selected[key] = value
                stripped_services[name] = selected
            data['services'] = stripped_services
            return data
        return _api_call(render)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def data(self, key=None):
        def render():
            item = self.get_item(self.results, key)
            if isinstance(item, dict) or isinstance(item, SqliteDict):
                return {'type': 'dict', 'keys': list(item.keys())}
            if isinstance(item, list):
                return {'type': 'list', 'length': len(item)}
            return item
        return _api_call(render)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def full(self, key=None):
        def render():
            item = self.get_item(self.results, key)
            return dict(item) if isinstance(item, SqliteDict) else item
        return _api_call(render)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def page(self, key=None, page=None, pagesize=None):
        def render():
            start, size = pagination(page, pagesize)
            item = self.get_item(self.results, key)
            if isinstance(item, dict) or isinstance(item, SqliteDict):
                subset = {k: item[k] for k in sorted(item)[start:start + size]}
            elif isinstance(item, list):
                subset = item[start:start + size]
            else:
                raise ValueError('Cannot paginate scalar data')
            return self.strip_nested_data(subset)
        return _api_call(render)

    @staticmethod
    def init(database_filename, host, port):
        if host != '127.0.0.1' or port != 8000:
            raise ValueError('SQLite viewer only supports loopback 127.0.0.1:8000')
        token = secrets.token_urlsafe(32)
        server = Server(database_filename, viewer_token=token)
        # The script is loaded with file:// in the locally generated report.
        # It must never be exposed by the local HTTP API.
        session_file = Path(database_filename).parent / 'scoutsuite_viewer_session.js'
        if session_file.is_symlink():
            raise ValueError('Viewer session path must not be a symlink')
        import os
        fd = os.open(str(session_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write('window.scoutViewerSession = ' + json.dumps(token) + ';\n')
        except Exception:
            session_file.unlink(missing_ok=True)
            raise
        cherrypy.tools.scout_viewer_guard = cherrypy.Tool('before_handler', _viewer_guard)
        config = {'/': {'tools.scout_viewer_guard.on': True,
                        'tools.sessions.on': False}}
        cherrypy.config.update({'server.socket_host': host, 'server.socket_port': port})
        cherrypy.quickstart(server, '/api', config=config)

    @staticmethod
    def get_item(data, key):
        for part in validate_key(key):
            if isinstance(data, (dict, SqliteDict)):
                data = data[part]
            elif isinstance(data, list):
                if not re.fullmatch(r'[0-9]{1,10}', part):
                    raise ValueError('Invalid list index')
                data = data[int(part)]
            else:
                raise KeyError(part)
        return data

    @staticmethod
    def strip_nested_data(data):
        if not isinstance(data, dict):
            return data
        result = {}
        for key, value in data.items():
            if isinstance(value, dict):
                result[key] = {'type': 'dict', 'keys': list(value.keys())}
            elif isinstance(value, list):
                result[key] = {'type': 'list', 'length': len(value)}
            else:
                result[key] = value
        return result
