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
        self['bucket_inventory_status'] = getattr(
            self.facade.s3, 'bucket_inventory_status', 'unknown')
        self['advanced'] = await self.facade.s3_advanced.collect(
            self.facade, regions=kwargs.get('regions'),
            excluded_regions=kwargs.get('excluded_regions'),
            partition_name=partition_name)

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
            pab = bucket['public_access_block_configuration']
            flags = ('BlockPublicAcls', 'IgnorePublicAcls',
                     'BlockPublicPolicy', 'RestrictPublicBuckets')
            # A single observed false setting is a configuration gap.
            # Unknown settings must not be treated as all public access blocked.
            if any(pab.get(name) is False for name in flags):
                bucket['effective_bpa_review'] = 'missing'
            elif all(pab.get(name) is True for name in flags):
                bucket['effective_bpa_review'] = 'complete'
            else:
                bucket['effective_bpa_review'] = 'unknown'
            annotate_bucket_exposure(bucket)
