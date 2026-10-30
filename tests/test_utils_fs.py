import datetime
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ScoutSuite.core.fs import CustomJSONEncoder, load_data, read_ip_ranges, save_blob_as_json


class TestOpinelFsClass(unittest.TestCase):
    def test_CustomJSONEncoder(self):
        date = datetime.datetime(2017, 6, 12)
        blob = {'foo': 'bar', 'date': date}
        self.assertEqual(json.loads(json.dumps(blob, cls=CustomJSONEncoder)), {'foo': 'bar', 'date': str(date)})
        self.assertEqual(json.loads(json.dumps({'foo': {'bar': 'baz'}}, cls=CustomJSONEncoder)),
                         {'foo': {'bar': 'baz'}})

    def test_load_data(self):
        fixture = str(Path(__file__).parent / 'data/protocols.json')
        self.assertIn('protocols', load_data(fixture, local_file=True))
        self.assertEqual(load_data(fixture, 'protocols', local_file=True)['-2'], 'TEST')
        self.assertEqual(load_data('protocols.json', 'protocols')['1'], 'ICMP')
        self.assertTrue(load_data('aws/ip-ranges/aws.json', 'prefixes'))

    def test_read_ip_ranges(self):
        cases = [('tests/data/ip-ranges-1.json', True, [], False, 'ip-ranges-1a.json'),
                 ('tests/data/ip-ranges-1.json', True, [], True, 'ip-ranges-1b.json'),
                 ('tests/data/ip-ranges-1.json', True, [['field_a', 'equal', 'a1']], True, 'ip-ranges-1c.json'),
                 ('aws/ip-ranges/aws.json', False, [['ip_prefix', 'equal', '23.20.0.0/14']], False, 'ip-ranges-a.json'),
                 ('tests/data/ip-ranges-3.json', True, [], True, 'ip-ranges-3.json')]
        for filename, local, conditions, ip_only, expected in cases:
            with self.subTest(filename=filename, ip_only=ip_only, conditions=conditions):
                result = read_ip_ranges(filename, local_file=local, ip_only=ip_only, conditions=conditions)
                expected_file = Path(__file__).parent / 'results/read_ip_ranges' / expected
                self.assertEqual(result, json.loads(expected_file.read_text()))

    def test_save_blob_as_json(self):
        # Existing defect, deferred to M09: the helper truncates the file and logs JSON
        # instead of writing it. Characterize both effects without changing scanner behavior.
        with tempfile.TemporaryDirectory(prefix='scoutsuite-fs-') as directory:
            filename = Path(directory) / 'output.json'
            date = datetime.datetime(2020, 1, 1)
            with patch('ScoutSuite.core.fs.print_info') as log:
                save_blob_as_json(str(filename), {'foo': 'bar', 'date': date}, True)
                self.assertEqual(filename.read_text(), '')
                self.assertEqual(json.loads(log.call_args.args[0]), {'foo': 'bar', 'date': str(date)})
                save_blob_as_json(str(filename), {'foo': 'updated'}, True)
                self.assertEqual(filename.read_text(), '')
                self.assertEqual(json.loads(log.call_args.args[0]), {'foo': 'updated'})
                self.assertEqual(log.call_count, 2)
