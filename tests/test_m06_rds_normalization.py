"""M06 golden normalization: RDS cached resources remain reusable."""
from copy import deepcopy
from unittest import TestCase

from ScoutSuite.providers.aws.resources.rds.instances import RDSInstances
from ScoutSuite.providers.aws.resources.rds.snapshots import Snapshots


class TestRDSNormalizedCompatibility(TestCase):
    def test_instance_normalization_is_repeatable(self):
        raw = {'DBInstanceIdentifier': 'db-primary',
               'DBInstanceArn': 'arn:aws:rds:eu-central-1:1:db:db-primary',
               'DBSubnetGroup': {'VpcId': 'vpc-a'},
               'MultiAZ': False, 'PubliclyAccessible': False}
        original = deepcopy(raw)
        parser = RDSInstances.__new__(RDSInstances)
        first_key, first = parser._parse_instance(raw)
        second_key, second = parser._parse_instance(raw)
        self.assertEqual(raw, original)
        self.assertEqual(first_key, second_key)
        self.assertEqual(first, second)
        self.assertEqual(first['name'], 'db-primary')
        self.assertFalse(first['PubliclyAccessible'])

    def test_regular_snapshot_string_id_and_no_mutation(self):
        raw = {'DBSnapshotIdentifier': 'snapshot-a',
               'DBSnapshotArn': 'arn:aws:rds:eu-central-1:1:snapshot:snapshot-a',
               'DBInstanceIdentifier': 'db-a',
               'VpcId': 'vpc-a', 'Attributes': {'restore': 'private'},
               'Encrypted': True}
        original = deepcopy(raw)
        parser = Snapshots.__new__(Snapshots)
        key, first = parser._parse_snapshot(raw)
        _, second = parser._parse_snapshot(raw)
        self.assertEqual(key, 'snapshot-a')
        self.assertEqual(first['id'], 'snapshot-a')
        self.assertEqual(first['name'], 'snapshot-a')
        self.assertEqual(first, second)
        self.assertEqual(raw, original)

    def test_cluster_snapshot_with_missing_optional_fields(self):
        parser = Snapshots.__new__(Snapshots)
        raw = {'DBClusterSnapshotIdentifier': 'cluster-snap',
               'DBClusterIdentifier': 'aurora-cluster',
               'StorageEncrypted': True}
        key, snapshot = parser._parse_snapshot(raw)
        self.assertEqual(key, 'cluster-snap')
        self.assertTrue(snapshot['is_cluster'])
        self.assertTrue(snapshot['Encrypted'])
        self.assertIsNone(snapshot['arn'])
        self.assertEqual(snapshot['attributes'], {})
        self.assertEqual(snapshot['vpc_id'], 'EC2-Classic')
        self.assertEqual(raw['DBClusterSnapshotIdentifier'], 'cluster-snap')
