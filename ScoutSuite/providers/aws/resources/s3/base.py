from ScoutSuite.providers.aws.facade.base import AWSFacade
from ScoutSuite.providers.aws.resources.base import AWSCompositeResources
from .buckets import Buckets
from .exposure import combine_public_access_blocks, annotate_bucket_exposure


class S3(AWSCompositeResources):
    _children = [
        (Buckets, 'buckets')
    ]

    def __init__(self, facade: AWSFacade):
        super().__init__(facade)
        self.service = 's3'

    async def fetch_all(self, partition_name='aws', **kwargs):
        # Keep track of regions as S3 is both a global and regional service
        self.facade.s3.regions = kwargs.get('regions')
        self['public_access_block_configuration'] = self.facade.s3.get_s3_public_access_block(self.facade.owner_id)
        await self._fetch_children(self)

    async def finalize(self):
        account = self.get('public_access_block_configuration')
        for bucket in self.get('buckets', {}).values():
            # Keep raw bucket settings separate from the computed effective
            # account+bucket values. Never mutate the SDK response in-place.
            original = bucket.get('public_access_block_configuration')
            bucket['bucket_public_access_block_configuration'] = (
                dict(original) if isinstance(original, dict) else None
            )
            bucket['public_access_block_configuration'] = (
                combine_public_access_blocks(account, original)
            )
            annotate_bucket_exposure(bucket)
