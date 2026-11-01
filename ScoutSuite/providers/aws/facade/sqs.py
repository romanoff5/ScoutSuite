from botocore.exceptions import ClientError

from ScoutSuite.core.console import print_exception, print_warning
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.facade.pagination import collect_token_pages, PaginationError
from ScoutSuite.providers.utils import run_concurrently, map_concurrently


class SQSFacade(AWSBaseFacade):
    async def get_queues(self, region: str, attribute_names: []):
        client = AWSFacadeUtils.get_client('sqs', self.session, region)
        if client is None:
            return []
        try:
            queue_urls = await collect_token_pages(
                client.list_queues,
                items_path=('QueueUrls',),
                input_token='NextToken',
                output_token=('NextToken',),
                first_kwargs={'MaxResults': 1000},
                scope='sqs'
            )
        except PaginationError as error:
            print_exception('Unable to retrieve complete SQS queue list '
                            f'({error.reason_code})')
            queue_urls = error.items

        results = await map_concurrently(
            self._get_queue_attributes, queue_urls,
            region=region, attribute_names=attribute_names
        )
        return [item for item in results if item is not None]

    async def _get_queue_attributes(self, queue_url: str, region: str, attribute_names: []):
        client = AWSFacadeUtils.get_client('sqs', self.session, region)
        if client is None:
            return None
        try:
            response = await run_concurrently(
                lambda: client.get_queue_attributes(
                    QueueUrl=queue_url, AttributeNames=attribute_names
                )
            )
            attributes = response['Attributes']
            if not isinstance(attributes, dict) or not attributes.get('QueueArn'):
                raise ValueError('MalformedAttributes')
            return queue_url, attributes
        except ClientError as error:
            code = error.response.get('Error', {}).get('Code', '')
            if code in ('AWS.SimpleQueueService.NonExistentQueue',
                        'QueueDoesNotExist', 'NonExistentQueue'):
                print_warning('SQS queue disappeared during enumeration')
                reason = 'QueueDeleted'
            else:
                print_exception('Failed to retrieve SQS queue attributes')
                reason = 'QueueAttributes'
        except (KeyError, TypeError, ValueError):
            print_exception('Malformed SQS queue attributes')
            reason = 'MalformedAttributes'
        except Exception:
            print_exception('Failed to retrieve SQS queue attributes')
            reason = 'QueueAttributes'
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue('partial', 'sqs', reason)
        return None
