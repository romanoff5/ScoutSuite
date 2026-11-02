"""M10-G: bounded read-only EKS regional cluster inventory."""
import re

from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently


MAX_PAGES = 20
PAGE_SIZE = 100
MAX_CLUSTERS = 1000
DENIED = ('AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation')
UNSUPPORTED = ('UnsupportedOperationException', 'UnknownOperationException')


class EKSPublicFacade(AWSBaseFacade):
    def __init__(self, session, owner_id):
        super().__init__(session)
        self.owner_id = owner_id

    @staticmethod
    def issue(status, reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue(status, 'eks', reason)

    def error(self, operation, error, partial=False):
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
        client = AWSFacadeUtils.get_client('eks', self.session, region)
        if client is None:
            self.issue('failed', 'ClientConstruction')
            return []
        names, seen, tokens = [], set(), set()
        token = None
        for _ in range(MAX_PAGES):
            params = {'maxResults': PAGE_SIZE}
            if token is not None:
                params['nextToken'] = token
            try:
                page = await run_concurrently(
                    lambda params=params: client.list_clusters(**params))
            except Exception as error:
                self.error('ListClusters', error, partial=bool(names))
                break
            rows = page.get('clusters') if isinstance(page, dict) else None
            if not isinstance(rows, list) or len(rows) > PAGE_SIZE:
                self.issue('partial' if names else 'failed', 'MalformedClusterList')
                break
            stopped = False
            for name in rows:
                if not isinstance(name, str) or not name:
                    self.issue('partial', 'MalformedClusterName')
                    continue
                if name in seen:
                    self.issue('partial', 'DuplicateClusterName')
                    continue
                if len(names) >= MAX_CLUSTERS:
                    self.issue('partial', 'ClusterLimit')
                    stopped = True
                    break
                seen.add(name)
                names.append(name)
            if stopped:
                break
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
        results = []
        for name in names:
            try:
                response = await run_concurrently(
                    lambda name=name: client.describe_cluster(name=name))
            except Exception as error:
                self.error('DescribeCluster', error, partial=True)
                continue
            cluster = response.get('cluster') if isinstance(response, dict) else None
            arn = cluster.get('arn') if isinstance(cluster, dict) else None
            if not isinstance(cluster, dict) or cluster.get('name') != name or not isinstance(arn, str):
                self.issue('partial', 'MalformedClusterDetail')
                continue
            parts = arn.split(':', 5)
            if (len(parts) != 6 or parts[2] != 'eks'
                    or parts[3] != region or parts[4] != self.owner_id):
                self.issue('partial', 'UnexpectedClusterAccount')
                continue
            results.append(cluster)
        return results
