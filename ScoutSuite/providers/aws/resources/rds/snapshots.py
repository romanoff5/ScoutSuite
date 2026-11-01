from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSResources


class Snapshots(AWSResources):
    def __init__(self, facade: AWSFacade, region: str, vpc: str):
        super().__init__(facade)
        self.region = region
        self.vpc = vpc

    async def fetch_all(self):
        raw_snapshots = await self.facade.rds.get_snapshots(self.region, self.vpc)
        for raw_snapshot in raw_snapshots:
            name, resource = self._parse_snapshot(raw_snapshot)
            self[name] = resource

    def _parse_snapshot(self, raw_snapshot):
        # Cached AWS responses may be normalized more than once.
        is_cluster = 'DBClusterSnapshotIdentifier' in raw_snapshot
        snapshot_id = raw_snapshot.get(
            'DBClusterSnapshotIdentifier' if is_cluster else 'DBSnapshotIdentifier'
        )
        if not snapshot_id:
            raise ValueError('RDS snapshot is missing its identifier')

        snapshot = {
            'arn': raw_snapshot.get(
                'DBClusterSnapshotArn' if is_cluster else 'DBSnapshotArn'
            ),
            'id': snapshot_id,
            'name': snapshot_id,
            'vpc_id': raw_snapshot.get('VpcId', 'EC2-Classic'),
            'attributes': raw_snapshot.get('Attributes') or {},
            'is_cluster': is_cluster
        }

        for field in ('DBInstanceIdentifier', 'SnapshotCreateTime',
                      'Encrypted', 'OptionGroupName'):
            snapshot[field] = raw_snapshot.get(field)
        if is_cluster:
            snapshot['DBClusterIdentifier'] = raw_snapshot.get('DBClusterIdentifier')
            snapshot['Encrypted'] = raw_snapshot.get(
                'StorageEncrypted', raw_snapshot.get('Encrypted')
            )
        return snapshot_id, snapshot
