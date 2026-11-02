"""M10-F: bounded, read-only ECS regional cluster inventory."""
import re

from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently


PAGE_SIZE = 100
MAX_PAGES = 50
MAX_CLUSTERS = PAGE_SIZE * MAX_PAGES
INCLUDE = ['CONFIGURATIONS', 'SETTINGS', 'STATISTICS', 'TAGS']
DENIED = ('AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation')
UNSUPPORTED = ('UnsupportedOperationException', 'UnknownOperationException')


class ECSPublicFacade(AWSBaseFacade):
    def __init__(self, session, owner_id):
        super().__init__(session)
        self.owner_id = owner_id

    @staticmethod
    def issue(status, reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue(status, 'ecs', reason)

    def error(self, operation, error, partial):
        if isinstance(error, ClientError):
            code = error.response.get('Error', {}).get('Code', '')
            state = 'denied' if code in DENIED else (
                'unsupported' if code in UNSUPPORTED else 'failed')
        else:
            state = 'failed'
        self.issue('partial' if partial else state, operation + state.capitalize())

    async def get_clusters(self, region):
        if (not isinstance(self.owner_id, str)
                or re.fullmatch(r'[0-9]{12}', self.owner_id) is None):
            self.issue('failed', 'InvalidAccountId')
            return []
        client = AWSFacadeUtils.get_client('ecs', self.session, region)
        if client is None:
            self.issue('failed', 'ClientConstruction')
            return []

        arns, seen, tokens = [], set(), set()
        token = None
        for _ in range(MAX_PAGES):
            params = {'maxResults': PAGE_SIZE}
            if token is not None:
                params['nextToken'] = token
            try:
                page = await run_concurrently(
                    lambda params=params: client.list_clusters(**params))
            except Exception as error:
                self.error('ListClusters', error, bool(arns))
                break
            batch = page.get('clusterArns') if isinstance(page, dict) else None
            if not isinstance(batch, list) or len(batch) > PAGE_SIZE:
                self.issue('partial' if arns else 'failed', 'MalformedClusterList')
                break
            for arn in batch:
                if not isinstance(arn, str) or not arn.startswith('arn:'):
                    self.issue('partial', 'MalformedClusterArn')
                    continue
                if len(arn.split(':')) < 6 or arn.split(':')[4] != self.owner_id:
                    self.issue('partial', 'UnexpectedClusterAccount')
                    continue
                if arn in seen:
                    self.issue('partial', 'DuplicateCluster')
                    continue
                if len(arns) >= MAX_CLUSTERS:
                    self.issue('partial', 'ClusterLimit')
                    return await self._describe(client, arns)
                seen.add(arn)
                arns.append(arn)
            following = page.get('nextToken')
            if following is None or following == '':
                break
            if (not isinstance(following, str) or len(following) > 4096
                    or following in tokens):
                self.issue('partial', 'InvalidPaginationToken')
                break
            tokens.add(following)
            token = following
        else:
            self.issue('partial', 'PageLimit')
        return await self._describe(client, arns)

    async def _describe(self, client, arns):
        results, listed = [], set(arns)
        for offset in range(0, len(arns), PAGE_SIZE):
            chunk = arns[offset:offset + PAGE_SIZE]
            try:
                response = await run_concurrently(
                    lambda chunk=chunk: client.describe_clusters(
                        clusters=chunk, include=INCLUDE))
            except Exception as error:
                self.error('DescribeClusters', error, bool(results))
                continue
            clusters = response.get('clusters') if isinstance(response, dict) else None
            failures = response.get('failures', []) if isinstance(response, dict) else None
            if not isinstance(clusters, list) or not isinstance(failures, list):
                self.issue('partial', 'MalformedClusterDetails')
                continue
            if failures:
                self.issue('partial', 'ClusterDescriptionFailures')
            seen_chunk = set()
            for row in clusters:
                arn = row.get('clusterArn') if isinstance(row, dict) else None
                if (not isinstance(arn, str) or arn not in listed or arn not in chunk
                        or arn in seen_chunk):
                    self.issue('partial', 'UnexpectedClusterDetail')
                    continue
                seen_chunk.add(arn)
                results.append(row)
            if len(seen_chunk) != len(chunk):
                self.issue('partial', 'MissingClusterDetails')
        return results
