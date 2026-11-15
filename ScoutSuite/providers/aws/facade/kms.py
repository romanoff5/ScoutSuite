from ScoutSuite.core.console import print_exception
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently, get_and_set_concurrently
import json
from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context




class KMSFacade(AWSBaseFacade):

    async def get_keys(self, region: str):

        try:
            keys = await AWSFacadeUtils.get_all_pages('kms', region, self.session, 'list_keys', 'Keys')
            await get_and_set_concurrently(
                [self._get_and_set_key_policy,
                 self._get_and_set_key_metadata,
                 self._get_and_set_key_aliases],
                keys, region=region)
        except Exception as e:
            print_exception(f'Failed to get KMS keys: {e}')
            keys = []
        return keys

    async def _get_and_set_key_policy(self, key: {}, region: str):
        client = AWSFacadeUtils.get_client('kms', self.session, region)
        try:
            response = await run_concurrently(
                lambda: client.get_key_policy(KeyId=key['KeyId'],
                                              PolicyName='default'))
            parsed = json.loads(response.get('Policy'))
            if not isinstance(parsed, dict):
                key['policy_collection_status'] = 'partial'
            else:
                key['policy'] = parsed
                key['policy_collection_status'] = 'complete'
        except Exception as e:
            key['policy_collection_status'] = 'failed'
            print_exception(f'Failed to get KMS key policy: {e}')

    async def _get_and_set_key_metadata(self, key: {}, region: str):
        client = AWSFacadeUtils.get_client('kms', self.session, region)
        try:
            key['metadata'] = await run_concurrently(lambda: client.describe_key(KeyId=key['KeyId']))
        except Exception as e:
            print_exception(f'Failed to describe KMS key: {e}')

    async def _get_and_set_key_aliases(self, key: {}, region: str):
        client = AWSFacadeUtils.get_client('kms', self.session, region)
        try:
            response = await run_concurrently(
                lambda: client.list_aliases(KeyId=key['KeyId'])
            )
            key['aliases'] = response.get('Aliases')
        except Exception as e:
            print_exception(f'Failed to get KMS aliases: {e}')

    def _grant_issue(self, region, error_code):
        context = get_current_run_context()
        if context is not None:
            status = 'denied' if error_code in (
                'AccessDenied', 'AccessDeniedException', 'NotAuthorizedException') else 'partial'
            context.record_collection_issue(status, 'kms', 'ListGrants' + error_code,
                                            region=region)

    async def get_grants_with_status(self, region: str, key_id: str):
        """P5 audit: bounded KMS ListGrants with an explicit completeness result.

        The generic paginator intentionally converts AccessDenied into [] for
        regular resource collections, so its result cannot establish an empty
        KMS grant inventory. Use the underlying read-only API directly.
        """
        client = AWSFacadeUtils.get_client('kms', self.session, region)
        if client is None:
            self._grant_issue(region, 'ClientConstructionFailed')
            return [], 'unknown'
        marker, seen_markers, seen_ids, records = None, set(), set(), []
        for _ in range(20):
            args = {'KeyId': key_id, 'Limit': 100}
            if marker is not None:
                args['Marker'] = marker
            try:
                response = await run_concurrently(
                    lambda args=args: client.list_grants(**args))
            except Exception as exc:
                code = (exc.response.get('Error', {}).get('Code', 'ClientError')
                        if isinstance(exc, ClientError) else type(exc).__name__)
                self._grant_issue(region, code)
                print_exception('KMS ListGrants incomplete: ' + code)
                return records, 'partial'
            rows = response.get('Grants') if isinstance(response, dict) else None
            if not isinstance(rows, list) or len(rows) > 100:
                self._grant_issue(region, 'MalformedResponse')
                return records, 'partial'
            for row in rows:
                ident = row.get('GrantId') if isinstance(row, dict) else None
                if (not isinstance(ident, str) or not ident or ident in seen_ids):
                    self._grant_issue(region, 'InvalidGrant')
                    return records, 'partial'
                seen_ids.add(ident)
                records.append(row)
            truncated = response.get('Truncated')
            if truncated is False:
                return records, 'complete'
            following = response.get('NextMarker')
            if (truncated is not True or not isinstance(following, str)
                    or not following or len(following) > 1024
                    or following in seen_markers):
                self._grant_issue(region, 'InvalidPagination')
                return records, 'partial'
            seen_markers.add(following)
            marker = following
        self._grant_issue(region, 'PageLimit')
        return records, 'partial'

    async def get_grants(self, region: str, key_id: str):
        # Preserve the legacy list-returning API for non-census callers.
        records, _ = await self.get_grants_with_status(region, key_id)
        return records

    async def get_key_rotation_status(self, region: str, key_id: str):
        client = AWSFacadeUtils.get_client('kms', self.session, region)
        try:
            return await run_concurrently(
                lambda: client.get_key_rotation_status(KeyId=key_id))
        except Exception as e:
            print_exception(f'Failed to get KMS key rotation: {e}')
