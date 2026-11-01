import datetime
import json
import os

import dateutil
from sqlitedict import SqliteDict

from ScoutSuite.output.safe_pickle import decode_report_pickle

from ScoutSuite import DEFAULT_REPORT_DIRECTORY
from ScoutSuite.core.console import print_exception, print_info
from ScoutSuite.output.utils import get_filename, prompt_for_overwrite


# Only RESULTS payloads carry a schema version. Exceptions and error files retain
# their historical shapes to preserve existing reader/UI compatibility.
RESULTS_SCHEMA_VERSION = 1
_PRIVATE_ATTRIBUTES = frozenset({
    'credentials', 'profile', 'metadata_path', 'services_config',
    'session', '_session',
})


class UnsupportedReportVersion(ValueError):
    """The report cannot be interpreted by this reader without migration."""


def prepare_results(config):
    """Produce a versioned, sanitized copy; never edit provider state."""
    result = ScoutResultEncoder.to_dict(config)
    if not isinstance(result, dict):
        raise TypeError('RESULTS payload must be a mapping')
    result = {key: value for key, value in result.items()
              if key not in _PRIVATE_ATTRIBUTES}
    result['report_schema_version'] = RESULTS_SCHEMA_VERSION
    return result


def validate_results(payload):
    """Accept unversioned legacy RESULTS, reject unsupported future schemas."""
    if not isinstance(payload, dict):
        raise UnsupportedReportVersion('RESULTS payload must be an object')
    version = payload.get('report_schema_version', 0)
    if type(version) is not int or version not in (0, RESULTS_SCHEMA_VERSION):
        raise UnsupportedReportVersion('Unsupported RESULTS schema version: ' + str(version))
    return payload


class ScoutJsonEncoder(json.JSONEncoder):
    """Deterministic JSON conversion without modifying original provider objects."""

    def default(self, value):
        if isinstance(value, (datetime.datetime, datetime.date)):
            # Preserve historical date representation for existing report readers.
            return str(value)
        if isinstance(value, (set, frozenset)):
            return sorted(value, key=lambda item: str(item))
        try:
            attributes = vars(value)
        except TypeError:
            return super().default(value)
        # Never use delattr: a second report or programmatic caller may still
        # require these attributes. Avoid exposing private SDK clients as well.
        return {key: item for key, item in attributes.items()
                if key not in _PRIVATE_ATTRIBUTES and not key.startswith('_')}


class ScoutResultEncoder:
    def __init__(self, report_name=None, report_dir=None, timestamp=None):
        self.report_name = report_name
        if self.report_name:
            self.report_name = report_name.replace('/', '_').replace('\\', '_')  # Issue 111
        self.report_dir = report_dir if report_dir else DEFAULT_REPORT_DIRECTORY
        self.current_time = datetime.datetime.now(dateutil.tz.tzlocal())
        self.timestamp = self.current_time.strftime("%Y-%m-%d_%Hh%M%z") if not timestamp else timestamp

    @staticmethod
    def to_dict(config):
        return json.loads(json.dumps(config, separators=(',', ': '), sort_keys=True,
                                     allow_nan=False, cls=ScoutJsonEncoder))


class SqlLiteEncoder(ScoutResultEncoder):
    def load_from_file(self, config_type, config_path=None):
        if not config_path:
            config_path, _ = get_filename(config_type, self.report_name, self.report_dir,
                                          file_extension='db')
        if not os.path.isfile(config_path):
            raise FileNotFoundError(config_path)
        with SqliteDict(config_path, flag='r', decode=decode_report_pickle) as database:
            payload = dict(database)
        return validate_results(payload) if config_type == 'RESULTS' else payload

    def save_to_file(self, config, config_type, force_write, _debug):
        config_path, first_line = get_filename(config_type, self.report_name, self.report_dir, file_extension="db")
        print_info('Saving data to %s' % config_path)
        try:
            with self.__open_file(config_path, force_write) as database:
                result_dict = (prepare_results(config) if config_type == 'RESULTS'
                               else self.to_dict(config))
                for k, v in result_dict.items():
                    database[k] = v
                database.commit()
        except Exception as e:
            print_exception(e)

    @staticmethod
    def __open_file(config_filename, force_write):
        """

        :param config_filename:
        :param force_write:
        :param quiet:
        :return:
        """
        if prompt_for_overwrite(config_filename, force_write):
            try:
                config_dirname = os.path.dirname(config_filename)
                if not os.path.isdir(config_dirname):
                    os.makedirs(config_dirname)
                if os.path.exists(config_filename):
                    os.remove(config_filename)
                return SqliteDict(config_filename)
            except Exception as e:
                print_exception(e)
        else:
            return None


class JavaScriptEncoder(ScoutResultEncoder):
    """
    Reader/Writer for JS and JSON files
    """

    def load_from_file(self, file_type, file_path=None, first_line=None):
        if not file_path:
            file_path, first_line = get_filename(file_type, self.report_name, self.report_dir)
        with open(file_path) as f:
            json_payload = f.readlines()
            if first_line:
                json_payload.pop(0)
            json_payload = ''.join(json_payload)
        payload = json.loads(json_payload)
        return validate_results(payload) if file_type == 'RESULTS' else payload

    def save_to_file(self, content, file_type, force_write, debug):
        config_path, first_line = get_filename(file_type, self.report_name, self.report_dir)
        print_info('Saving data to %s' % config_path)
        try:
            with self.__open_file(config_path, force_write) as f:
                if first_line:
                    print('%s' % first_line, file=f)
                payload = (prepare_results(content) if file_type == 'RESULTS'
                           else self.to_dict(content))
                print('%s' % json.dumps(payload, indent=4 if debug else None,
                                        separators=(',', ': '), sort_keys=True,
                                        allow_nan=False), file=f)
        except AttributeError as e:
            # __open_file returned None
            pass
        except Exception as e:
            print_exception(e)

    @staticmethod
    def __open_file(config_filename, force_write):
        """

        :param config_filename:
        :param force_write:
        :param quiet:
        :return:
        """
        if prompt_for_overwrite(config_filename, force_write):
            try:
                config_dirname = os.path.dirname(config_filename)
                if not os.path.isdir(config_dirname):
                    os.makedirs(config_dirname)
                return open(config_filename, 'wt')
            except Exception as e:
                print_exception(e)
        else:
            return None
