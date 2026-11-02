"""Read-only bounded IAM Access Analyzer inventory (M10-A)."""
from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently


MAX_PAGES = 500
MAX_ANALYZERS = 50000


class AccessAnalyzerFacade(AWSBaseFacade):
    async def get_analyzers(self, region):
        context = get_current_run_context()

        def issue(status, reason):
            if context is not None:
                context.record_collection_issue(status, 'accessanalyzer', reason)

        client = AWSFacadeUtils.get_client('accessanalyzer', self.session, region)
        if client is None:
            issue('failed', 'ClientConstruction')
            self._record_census(region, False, 0)
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
                self._record_census(region, False, len(items))
                return items
            except Exception:
                issue('partial' if items else 'failed', 'APIError')
                self._record_census(region, False, len(items))
                return items

            batch = page.get('analyzers') if isinstance(page, dict) else None
            if not isinstance(batch, list) or any(not isinstance(a, dict) for a in batch):
                issue('partial' if items else 'failed', 'MalformedPage')
                self._record_census(region, False, len(items))
                return items
            if len(items) + len(batch) > MAX_ANALYZERS:
                issue('partial', 'ResultLimit')
                self._record_census(region, False, len(items))
                return items
            items.extend(batch)
            next_token = page.get('nextToken')
            if not next_token:
                self._record_census(region, True, len(items))
                return items
            if not isinstance(next_token, str) or next_token in seen_tokens:
                issue('partial', 'InvalidPaginationToken')
                self._record_census(region, False, len(items))
                return items
            seen_tokens.add(next_token)
            token = next_token

        issue('partial', 'PageLimit')
        self._record_census(region, False, len(items))
        return items

    def _record_census(self, region, complete, count):
        """Region-level proof that the analyzer inventory is complete.

        An empty list after a denial or a failed page is never evidence that
        no analyzer is configured; only a fully enumerated region is.
        """
        if not hasattr(self, 'analyzer_census'):
            self.analyzer_census = {}
        self.analyzer_census[region] = {'complete': bool(complete), 'count': count}
