from ScoutSuite.core.console import print_exception
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.facade.pagination import collect_token_pages, PaginationError


class CloudFront(AWSBaseFacade):
    async def get_distributions(self):
        client = AWSFacadeUtils.get_client('cloudfront', self.session)
        if client is None:
            return []
        try:
            return await collect_token_pages(
                client.list_distributions,
                items_path=('DistributionList', 'Items'),
                input_token='Marker',
                output_token=('DistributionList', 'NextMarker'),
                truncated_path=('DistributionList', 'IsTruncated'),
                first_kwargs={'MaxItems': '100'},
                scope='cloudfront'
            )
        except PaginationError as error:
            print_exception(
                'Unable to retrieve complete CloudFront distribution list '
                f'({error.reason_code})'
            )
            return error.items
