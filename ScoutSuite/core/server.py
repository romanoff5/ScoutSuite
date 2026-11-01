from sqlitedict import SqliteDict
import cherrypy

import re
import ipaddress
from pathlib import Path

count_re = re.compile(r".*_count$")
MAX_PAGE_SIZE = 100
MAX_PAGE_INDEX = 100000
MAX_PATH_LENGTH = 2048
MAX_PATH_DEPTH = 32
INTEGER_RE = re.compile(r'^(0|[1-9][0-9]*)$')


class Server:
    """
    Boots a server that serves the result of the report for the user. This is still a proof of concept,
    but will eventually be used to serve data when it exceeds 400mb.
    """
    def __init__(self, filename):
        """
        Constructor of the server object. Should not be called directly outside the class.

        :param filename:                Name of the file to write data to.
        :return:                        The server object.
        """
        self.results = SqliteDict(filename, flag='r')
        self.report_root = Path(filename).resolve().parent

    def check_same_origin(self):
        host = cherrypy.request.headers.get('Host', '').split(':', 1)[0].lower()
        if host not in ('127.0.0.1', 'localhost', '[::1]'):
            raise cherrypy.HTTPError(403, 'Invalid local report host')
        origin = cherrypy.request.headers.get('Origin')
        if origin:
            valid = {'http://127.0.0.1:' + str(cherrypy.server.socket_port),
                     'http://localhost:' + str(cherrypy.server.socket_port)}
            if origin not in valid:
                raise cherrypy.HTTPError(403, 'Cross-origin access denied')

    @cherrypy.expose
    def default(self, *parts):
        """Read-only same-origin HTML and packaged static assets. Never serve databases."""
        self.check_same_origin()
        if not parts or any(p in ('', '.', '..') for p in parts):
            raise cherrypy.HTTPError(404)
        relative = Path(*parts)
        top = parts[0]
        file = (self.report_root / relative).resolve()
        if not file.is_relative_to(self.report_root) or not file.is_file():
            raise cherrypy.HTTPError(404)
        if (len(parts) == 1 and top.endswith('.html')):
            pass
        elif (top.startswith('inc-') and
              file.suffix.lower() in ('.css', '.js', '.ico', '.png', '.jpg',
                                      '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf')):
            pass
        elif (top == 'scoutsuite-results' and len(parts) == 2 and
              (parts[1].endswith('-exceptions.js') or parts[1].endswith('-errors.js'))):
            pass
        else:
            raise cherrypy.HTTPError(404)
        cherrypy.response.headers['Cache-Control'] = 'no-store'
        cherrypy.response.headers['X-Content-Type-Options'] = 'nosniff'
        return cherrypy.lib.static.serve_file(str(file))

    @cherrypy.expose()
    @cherrypy.tools.json_out()
    def summary(self):
        """
        Returns the stripped down data of the results that doesn't scale up when using a lot of resources,
        used to render the summary.
        Should be the first call from the server.
        Can be found at GET /api/summary

        :return:                        The summary data of the report.
        """
        self.check_same_origin()
        data = dict(self.results)
        services = data.get('services') or {}
        stripped_services = {}
        for k1, v1 in services.items():
            service = {}
            for k2, v2 in v1.items():
                if k2 == 'findings' or k2 == 'filters' or count_re.match(k2):
                    service[k2] = v2
            stripped_services[k1] = service
        data['services'] = stripped_services
        return {'data': data}

    @cherrypy.expose()
    @cherrypy.tools.json_out()
    def data(self, key=None):
        """
        Return the data at the requested key. Doesn't returns nested dictionaries and lists.
        If one of the value is a dictionary, it will return {'type': 'dict', 'keys': <Array of all the keys>}
        If one of the value is a list, it will return {'type': 'list', 'count': <number of elements in the list>}

        Can be found at GET /api/data?key=<KEY>
        :param key:                     Key of the requested information, separated by the character '¤'.
        :return:                        The data at the requested location stripped of its nested data.
        """
        self.check_same_origin()
        result = self.get_item(self.results, key)
        # Returns only indexes or length if it's a complex type
        if isinstance(result, dict) or isinstance(result, SqliteDict):
            result = {'type': 'dict', 'keys': list(result.keys())}
        elif isinstance(result, list):
            result = {'type': 'list', 'length': len(result)}
        return {'data': result}

    @cherrypy.expose()
    @cherrypy.tools.json_out()
    def full(self, key=None):
        """
        Return the data at the requested key. Returns all the nested data.
        Be sure not to use it on a key that may contains a lot of data, as the request won't be answered
        if it's too large(generally 3mb).

        Can be found at GET /api/full?key=<KEY>
        :param key:                     Key of the requested information, separated by the character '¤'.
        :return:                        The data at the requested location.
        """
        self.check_same_origin()
        result = self.get_item(self.results, key)
        if isinstance(result, (dict, SqliteDict)):
            result = dict(result)
        return {'data': result}

    @cherrypy.expose()
    @cherrypy.tools.json_out()
    def page(self, key=None, page=None, pagesize=None):
        """
        Return a page of the data at the requested key. Doesn't returns nested dictionaries and lists.
        For example, if you set pagesize=10 and page=2, it should return element 10-19
        If one of the value is a dictionary, it will return {'type': 'dict', 'keys': <Array of all the keys>}
        If one of the value is a list, it will return {'type': 'list', 'count': <number of elements in the list>}

        Can be found at GET /api/page?key=<KEY>&page=<PAGE>&pagesize=<PAGESIZE>
        :param key:                     Key of the requested information, separated by the character '¤'.
        :param page:                    The number of the page you request.
        :param pagesize:                The size of the page you request.
        :return:                        A subset of the data at the requested location.
        """
        self.check_same_origin()
        result = self.get_item(self.results, key)

        page = self.parse_bounded_integer(page, MAX_PAGE_INDEX, minimum=0)
        pagesize = self.parse_bounded_integer(pagesize, MAX_PAGE_SIZE, minimum=1)
        if not isinstance(result, (list, dict, SqliteDict)):
            raise cherrypy.HTTPError(400, 'Pagination requires a collection')
        start = page * pagesize
        end = min((page + 1) * pagesize, len(result))

        if isinstance(result, dict) or isinstance(result, SqliteDict):
            page = {k: result.get(k) for k in sorted(list(result))[start:end]}
        if isinstance(result, list):
            page = result[start:end]

        return {'data': self.strip_nested_data(page)}

    @staticmethod
    def init(database_filename, host, port):
        """
        Configure and starts the server.

        :param database_filename:       Location of the database file.
        :param host:                    Address on which to listen.
        :param port:                    Port on which to listen.
        """
        ip = ipaddress.ip_address(host)
        if not ip.is_loopback:
            raise ValueError('Report API is restricted to loopback interfaces')
        config = {
            '/': {
                'tools.sessions.on': False,
                'tools.response_headers.on': True,
                'tools.response_headers.headers': [
                    ('Cache-Control', 'no-store'),
                    ('X-Content-Type-Options', 'nosniff'),
                ],
            },
        }
        cherrypy.config.update({
                'server.socket_host': host,
                'server.socket_port': port,
                'server.thread_pool': 5,
        })
        cherrypy.quickstart(Server(database_filename), "/api", config=config)

    @staticmethod
    def parse_bounded_integer(raw, maximum, minimum=0):
        if raw is None or not INTEGER_RE.fullmatch(str(raw)) or len(str(raw)) > 8:
            raise cherrypy.HTTPError(400, 'Invalid pagination parameter')
        value = int(raw)
        if value < minimum or value > maximum:
            raise cherrypy.HTTPError(400, 'Pagination parameter outside allowed range')
        return value

    @staticmethod
    def get_item(data, key):
        """Resolve a bounded data path without coercing or traversing arbitrary values."""
        if key is None or key == '':
            return data
        if (not isinstance(key, str) or len(key) > MAX_PATH_LENGTH
                or '\\x00' in key or '/' in key or '\\\\' in key):
            raise cherrypy.HTTPError(400, 'Invalid result path')
        parts = key.split('¤')
        if (len(parts) > MAX_PATH_DEPTH or
                any(not part or part.startswith('_') or part in (
                    '__proto__', 'prototype', 'constructor') for part in parts)):
            raise cherrypy.HTTPError(400, 'Invalid result path')
        for part in parts:
            if isinstance(data, (dict, SqliteDict)):
                if part not in data:
                    raise cherrypy.HTTPError(404, 'Result path does not exist')
                data = data[part]
            elif isinstance(data, list):
                if not INTEGER_RE.fullmatch(part) or len(part) > 8:
                    raise cherrypy.HTTPError(400, 'Invalid array index')
                index = int(part)
                if index >= len(data):
                    raise cherrypy.HTTPError(404, 'Result index does not exist')
                data = data[index]
            else:
                raise cherrypy.HTTPError(400, 'Cannot traverse scalar report data')
        return data

    @staticmethod
    def strip_nested_data(data):
        """
        Strip nested lists and dictionaries from the provided object to reduce its size.

        :param data:                    The object to strip.
        :return:                        The input data stripped of its nested lists and dictionaries.
        """
        if not isinstance(data, dict):
            return data

        result = {}
        for k, v in data.items():
            if isinstance(v, dict):
                result[k] = {'type': 'dict', 'keys': list(v.keys())}
            elif isinstance(v, list):
                result[k] = {'type': 'list', 'length': len(v)}
        return result

