"""Read-only bounded IAM Access Analyzer inventory (M10-A)."""
from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently


MAX_PAGES = 20
MAX_ANALYZERS = 2000


class AccessAnalyzerFacade(AWSBaseFacade):
    async def get_analyzers(self, region):
        context = get_current_run_context()

        def issue(status, reason):
            if context is not None:
                context.record_collection_issue(status, 'accessanalyzer', reason)

        client = AWSFacadeUtils.get_client('accessanalyzer', self.session, region)
        if client is None:
            issue('failed', 'ClientConstruction')
            return []

        items = []
        seen_tokens = set()
        token = None
        for _ in range(MAX_PAGES):
            args = {'maxResults': 100}
            if token is not None:
                args['nextToken'] = token
            try:
                page = await run_concurrently(lambda args=args: client.list_analyzers(**args))
            except ClientError as error:
                code = error.response.get('Error', {}).get('Code', 'ClientError')
                if code in ('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation'):
                    issue('partial' if items else 'denied', 'AccessDenied')
                elif code in ('UnsupportedOperation', 'UnknownOperationException'):
                    issue('partial' if items else 'unsupported', 'UnsupportedOperation')
                else:
                    issue('partial' if items else 'failed', 'APIError')
                return items
            except Exception:
                issue('partial' if items else 'failed', 'APIError')
                return items

            batch = page.get('analyzers') if isinstance(page, dict) else None
            if not isinstance(batch, list) or any(not isinstance(a, dict) for a in batch):
                issue('partial' if items else 'failed', 'MalformedPage')
                return items
            if len(items) + len(batch) > MAX_ANALYZERS:
                issue('partial', 'ResultLimit')
                return items
            items.extend(batch)
            next_token = page.get('nextToken')
            if not next_token:
                return items
            if not isinstance(next_token, str) or next_token in seen_tokens:
                issue('partial', 'InvalidPaginationToken')
                return items
            seen_tokens.add(next_token)
            token = next_token

        issue('partial', 'PageLimit')
        return items
