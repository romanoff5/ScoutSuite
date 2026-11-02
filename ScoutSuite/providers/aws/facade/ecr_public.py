"""M10-E: bounded, read-only ECR private repository metadata."""
import re

from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently


MAX_PAGES = 100
PAGE_SIZE = 100
MAX_REPOSITORIES = MAX_PAGES * PAGE_SIZE
DENIED = ('AccessDeniedException', 'AccessDenied', 'UnauthorizedOperation')
UNSUPPORTED = ('UnsupportedOperationException', 'UnknownOperationException')


class ECRPublicFacade(AWSBaseFacade):
    def __init__(self, session, owner_id):
        super().__init__(session)
        self.owner_id = owner_id

    @staticmethod
    def issue(status, reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue(status, 'ecr', reason)

    async def get_repositories(self, region):
        """Enumerate only current registry; never infer completeness on failure."""
        if (not isinstance(self.owner_id, str)
                or re.fullmatch(r'[0-9]{12}', self.owner_id) is None):
            self.issue('failed', 'InvalidAccountId')
            return []

        client = AWSFacadeUtils.get_client('ecr', self.session, region)
        if client is None:
            self.issue('failed', 'ClientConstruction')
            return []

        resources, seen_arns, seen_tokens = [], set(), set()
        token = None
        for _ in range(MAX_PAGES):
            params = {'registryId': self.owner_id, 'maxResults': PAGE_SIZE}
            if token is not None:
                params['nextToken'] = token
            try:
                response = await run_concurrently(
                    lambda params=params: client.describe_repositories(**params))
            except ClientError as error:
                code = error.response.get('Error', {}).get('Code', '')
                kind = ('denied' if code in DENIED else
                        'unsupported' if code in UNSUPPORTED else 'failed')
                self.issue('partial' if resources else kind,
                           'DescribeRepositories' + kind.capitalize())
                break
            except Exception:
                self.issue('partial' if resources else 'failed',
                           'DescribeRepositoriesError')
                break

            rows = response.get('repositories') if isinstance(response, dict) else None
            if not isinstance(rows, list) or len(rows) > PAGE_SIZE:
                self.issue('partial' if resources else 'failed', 'MalformedRepositoryPage')
                break
            stop = False
            for row in rows:
                if not isinstance(row, dict):
                    self.issue('partial', 'MalformedRepository')
                    continue
                arn, name = row.get('repositoryArn'), row.get('repositoryName')
                owner = row.get('registryId')
                if (not isinstance(arn, str) or not arn.startswith('arn:')
                        or not isinstance(name, str) or not name):
                    self.issue('partial', 'MalformedRepository')
                    continue
                if owner != self.owner_id:
                    self.issue('partial', 'UnexpectedRegistry')
                    continue
                if arn in seen_arns:
                    self.issue('partial', 'DuplicateRepository')
                    continue
                if len(resources) >= MAX_REPOSITORIES:
                    self.issue('partial', 'RepositoryLimit')
                    stop = True
                    break
                seen_arns.add(arn)
                resources.append(row)
            if stop:
                break
            following = response.get('nextToken')
            if following is None or following == '':
                break
            if (not isinstance(following, str) or len(following) > 4096
                    or following in seen_tokens):
                self.issue('partial', 'InvalidPaginationToken')
                break
            seen_tokens.add(following)
            token = following
        else:
            self.issue('partial', 'PageLimit')
        return resources
