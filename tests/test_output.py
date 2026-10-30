from pathlib import Path
import unittest

from ScoutSuite.output.html import HTMLReport
from ScoutSuite.output.utils import get_filename


class TestScoutOutput(unittest.TestCase):
    def test_html_report(self):
        report = HTMLReport(report_name='test')
        self.assertEqual(report.report_name, 'test')
        self.assertIn('json', report.get_content_from_folder(templates_type='conditionals'))
        self.assertIn('json', report.get_content_from_file(filename='/json_format.html'))

    def test_get_filename(self):
        cases = [('REPORT', False, 'report.html', None),
                 ('RESULTS', False, 'scoutsuite-results/scoutsuite_results.js', 'scoutsuite_results ='),
                 ('RESULTS', True, 'scoutsuite-results/scoutsuite_results.js', 'scoutsuite_results ='),
                 ('EXCEPTIONS', False, 'scoutsuite-results/scoutsuite_exceptions.js', 'exceptions ='),
                 ('EXCEPTIONS', True, 'scoutsuite-results/scoutsuite_exceptions.js', 'exceptions ='),
                 ('ERRORS', False, 'scoutsuite-results/scoutsuite_errors.json', None),
                 ('ERRORS', True, 'scoutsuite-results/scoutsuite_errors.json', None)]
        for kind, relative, suffix, first_line in cases:
            with self.subTest(kind=kind, relative=relative):
                filename, header = get_filename(kind, relative_path=relative)
                expected = Path(suffix) if relative else Path('scoutsuite-report') / suffix
                self.assertEqual(Path(filename), expected)
                self.assertEqual(header, first_line)
