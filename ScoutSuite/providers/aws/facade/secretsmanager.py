"""Read-only Secrets Manager metadata (RC9).

Only ListSecrets, DescribeSecret and GetResourcePolicy are called. They return
metadata; GetSecretValue / BatchGetSecretValue are never called, so no secret
value can reach the report. Every listing, detail or policy failure is recorded
as a collection issue and leaves the affected evidence UNKNOWN.
"""
import json

from botocore.exceptions import ClientError

from ScoutSuite.core.console import print_exception
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import map_concurrently, run_concurrently

# The default per-Region secret quota is 500,000; 100 per page covers it.
MAX_PAGES = 5000
SCOPE = 'secretsmanager'


def _record(status, reason):
    context = get_current_run_context()
    if context is not None:
        context.record_collection_issue(status, SCOPE, reason)


def _kind(error):
    code = error.response.get('Error', {}).get('Code', '') if isinstance(error, ClientError) else ''
    if code in ('AccessDenied', 'AccessDeniedException'):
        return 'denied', 'AccessDenied'
    return 'failed', 'Error'


class SecretsManagerFacade(AWSBaseFacade):
    async def get_secrets(self, region):
        client = AWSFacadeUtils.get_client(SCOPE, self.session, region)
        if client is None:
            return []
        secrets, seen, tokens, token = [], set(), set(), None
        for _ in range(MAX_PAGES):
            params = {'MaxResults': 100, 'IncludePlannedDeletion': True}
            if token is not None:
                params['NextToken'] = token
            try:
                response = await run_concurrently(lambda params=params: client.list_secrets(**params))
            except Exception as e:
                status, suffix = _kind(e)
                _record('partial' if secrets else status, 'ListSecrets' + suffix)
                print_exception(f'Failed to list Secrets Manager secrets: {e}')
                break
            page = response.get('SecretList') if isinstance(response, dict) else None
            if not isinstance(page, list):
                _record('partial' if secrets else 'failed', 'MalformedSecretList')
                break
            for entry in page:
                arn = entry.get('ARN') if isinstance(entry, dict) else None
                if not isinstance(arn, str) or not arn:
                    _record('partial', 'MalformedSecret')
                    continue
                if arn not in seen:
                    seen.add(arn)
                    secrets.append(entry)
            following = response.get('NextToken')
            if not following:
                break
            if not isinstance(following, str) or following in tokens:
                _record('partial', 'InvalidPaginationToken')
                break
            tokens.add(following)
            token = following
        else:
            _record('partial', 'PageLimit')

        secrets = await map_concurrently(self._describe_secret, secrets, region=region)
        return await map_concurrently(self._add_policy, secrets, region=region)

    async def _describe_secret(self, secret: dict, region: str):
        client = AWSFacadeUtils.get_client(SCOPE, self.session, region)
        try:
            details = await run_concurrently(lambda: client.describe_secret(SecretId=secret['ARN']))
        except Exception as e:
            status, suffix = _kind(e)
            _record(status, 'DescribeSecret' + suffix)
            print_exception(f'Failed to describe Secrets Manager secret: {e}')
            return dict(secret, _details_status='unknown')
        details = {key: value for key, value in details.items() if key != 'ResponseMetadata'}
        # The listing entry fills any field the detail response omits.
        return dict(secret, **details, _details_status='complete')

    async def _add_policy(self, secret: dict, region: str):
        client = AWSFacadeUtils.get_client(SCOPE, self.session, region)
        try:
            response = await run_concurrently(lambda: client.get_resource_policy(SecretId=secret['ARN']))
        except Exception as e:
            status, suffix = _kind(e)
            _record(status, 'GetResourcePolicy' + suffix)
            print_exception(f'Failed to get Secrets Manager secret policy: {e}')
            return dict(secret, policy={}, _policy_status='unknown')
        document = response.get('ResourcePolicy')
        if not document:
            return dict(secret, policy={}, _policy_status='none')
        try:
            policy = json.loads(document)
        except (TypeError, ValueError):
            _record('failed', 'MalformedResourcePolicy')
            return dict(secret, policy={}, _policy_status='unknown')
        if not isinstance(policy, dict):
            _record('failed', 'MalformedResourcePolicy')
            return dict(secret, policy={}, _policy_status='unknown')
        return dict(secret, policy=policy, _policy_status='present')
