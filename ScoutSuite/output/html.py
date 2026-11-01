import datetime
import os
import shutil
import zipfile
import stat
from pathlib import Path, PurePosixPath

import dateutil.tz

from ScoutSuite import DEFAULT_INCLUDES_DIRECTORY
from ScoutSuite import DEFAULT_REPORT_DIRECTORY, DEFAULT_REPORT_RESULTS_DIRECTORY, DEFAULT_INCLUDES_DIRECTORY
from ScoutSuite import ERRORS_LIST
from ScoutSuite.core.console import print_info, print_exception
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.output.result_encoder import JavaScriptEncoder, SqlLiteEncoder
from ScoutSuite.output.utils import get_filename, prompt_for_overwrite



MAX_REPORT_ARCHIVE_FILES = 2000
MAX_REPORT_ARCHIVE_BYTES = 128 * 1024 * 1024


def safe_extract_report_assets(archive, destination):
    """Extract trusted packaged assets only, rejecting links, traversal and zip bombs."""
    root = Path(destination).resolve()
    approved = ('inc-bootstrap/', 'inc-fontawesome/', 'inc-handlebars/',
                'inc-jquery/', 'inc-scoutsuite/')
    total = 0
    infos = archive.infolist()
    if len(infos) > MAX_REPORT_ARCHIVE_FILES:
        raise ValueError('Report asset archive exceeds file count limit')
    for info in infos:
        name = info.filename
        path = PurePosixPath(name)
        mode = (info.external_attr >> 16) & 0xFFFF
        if (not name or '\\' in name or path.is_absolute() or
                any(part in ('', '.', '..') for part in name.rstrip('/').split('/')) or
                not name.startswith(approved) or
                (mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))):
            raise ValueError('Invalid report archive member')
        target = root.joinpath(*path.parts)
        if not target.resolve().is_relative_to(root):
            raise ValueError('Report archive member escapes destination')
        total += info.file_size
        if total > MAX_REPORT_ARCHIVE_BYTES:
            raise ValueError('Report asset archive exceeds uncompressed size limit')
        for parent in target.parents:
            if parent == root:
                break
            if parent.is_symlink():
                raise ValueError('Report archive parent is a symlink')
        if target.is_symlink():
            raise ValueError('Report archive destination is a symlink')
    for info in infos:
        target = root.joinpath(*PurePosixPath(info.filename).parts)
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, open(target, 'wb') as output:
                shutil.copyfileobj(source, output)


class HTMLReport:
    """
    Base HTML report
    """

    def __init__(self, report_name=None, report_dir=None, timestamp=False, exceptions=None, result_format=None):

        self.report_name = report_name
        self.report_name = report_name.replace('/', '_').replace('\\', '_')  # Issue 111
        self.report_dir = report_dir if report_dir else DEFAULT_REPORT_DIRECTORY
        self.current_time = datetime.datetime.now(dateutil.tz.tzlocal())
        self.timestamp = self.current_time.strftime("%Y-%m-%d_%Hh%M%z") if not timestamp else timestamp

        # exceptions = {} if exceptions is None else exceptions
        self.exceptions = exceptions if exceptions else {}
        self.scout_report_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
        self.html_data_path = os.path.join(self.scout_report_data_path, 'html')
        self.exceptions_encoder = JavaScriptEncoder(self.report_name, report_dir, timestamp)

        if result_format == "sqlite":
            self.encoder = SqlLiteEncoder(self.report_name, report_dir, timestamp)
        else:
            self.encoder = JavaScriptEncoder(self.report_name, report_dir, timestamp)

    def get_content_from_folder(self, templates_type):
        contents = ''
        template_dir = os.path.join(self.html_data_path, templates_type)
        template_files = [os.path.join(template_dir, f) for f in sorted(os.listdir(template_dir)) if
                          os.path.isfile(os.path.join(template_dir, f))]
        for filename in template_files:
            try:
                with open('%s' % filename) as f:
                    contents = contents + f.read()
            except Exception as e:
                print_exception(f'Error reading filename {filename}: {e}')
        return contents

    def get_content_from_file(self, filename):
        contents = ''
        template_dir = os.path.join(self.html_data_path, 'conditionals')
        filename = template_dir + filename
        try:
            with open('%s' % filename) as f:
                contents = contents + f.read()
        except Exception as e:
            print_exception(f'Error reading filename {filename}: {e}')
        return contents

    def prepare_html_report_dir(self):
        if not os.path.isdir(self.report_dir):
            os.makedirs(self.report_dir)
        run_results_dir = os.path.join(self.report_dir, DEFAULT_REPORT_RESULTS_DIRECTORY)
        if not os.path.isdir(run_results_dir):
            os.makedirs(run_results_dir)
        # Copy static 3rd-party files
        archive = os.path.join(self.scout_report_data_path, 'includes.zip')
        with zipfile.ZipFile(archive) as zip_ref:
            safe_extract_report_assets(zip_ref, self.report_dir)
        # Copy static files
        inc_scout_dir = os.path.join(self.report_dir, DEFAULT_INCLUDES_DIRECTORY)
        src_inc_scout_dir = os.path.join(self.scout_report_data_path, DEFAULT_INCLUDES_DIRECTORY)
        if os.path.isdir(inc_scout_dir):
            shutil.rmtree(inc_scout_dir)
        shutil.copytree(src_inc_scout_dir, inc_scout_dir)


class ScoutReport(HTMLReport):
    """
    Scout HTML report
    """

    def __init__(self, provider, report_name=None, report_dir=None, timestamp=False, exceptions=None,
                 result_format='json'):
        exceptions = {} if exceptions is None else exceptions
        self.provider = provider
        self.result_format = result_format

        super().__init__(report_name, report_dir, timestamp, exceptions, result_format)

    def save(self, config, exceptions, force_write=False, debug=False):
        self.prepare_html_report_dir()
        self.encoder.save_to_file(config, 'RESULTS', force_write, debug)
        self.exceptions_encoder.save_to_file(exceptions, 'EXCEPTIONS', force_write, debug)
        context = get_current_run_context()
        errors = context.errors if context is not None else ERRORS_LIST
        if errors:
            self.exceptions_encoder.save_to_file(errors, 'ERRORS', force_write, debug=True)
        return self.create_html_report(force_write)

    def create_html_report(self, force_write):
        contents = ''
        # Use the script corresponding to the result format
        contents += self.get_content_from_file('/%s_format.html' % self.result_format)
        # Use all scripts under html/partials/
        contents += self.get_content_from_folder('partials')
        contents += self.get_content_from_folder('partials/%s' % self.provider)
        # Use all scripts under html/summaries/
        contents += self.get_content_from_folder('summaries')
        contents += self.get_content_from_folder('summaries/%s' % self.provider)
        new_file, first_line = get_filename('REPORT', self.report_name, self.report_dir)
        print_info('Creating %s' % new_file)
        if prompt_for_overwrite(new_file, force_write):
            if os.path.exists(new_file):
                os.remove(new_file)
            with open(os.path.join(self.html_data_path, 'report.html')) as f:
                with open(new_file, 'wt') as nf:
                    for line in f:
                        newline = line
                        newline = newline.replace('<!-- CONTENTS PLACEHOLDER -->', contents)
                        newline = newline.replace('<!-- RESULTS PLACEHOLDER -->',
                                                  get_filename('RESULTS',
                                                               self.report_name,
                                                               self.report_dir,
                                                               relative_path=True)[0])
                        newline = newline.replace('<!-- EXCEPTIONS PLACEHOLDER -->',
                                                  get_filename('EXCEPTIONS',
                                                               self.report_name,
                                                               self.report_dir,
                                                               relative_path=True)[0])
                        newline = newline.replace('<!-- SQLITE JS PLACEHOLDER -->',
                                                  f'{DEFAULT_INCLUDES_DIRECTORY}/sqlite.js')
                        nf.write(newline)
        return new_file
