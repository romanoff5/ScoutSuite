"""P2 bounded, read-only Athena workgroup configuration evidence."""
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently


class AthenaAuditFacade(AWSBaseFacade):
    def _issue(self, code):
        ctx = get_current_run_context()
        if ctx is not None:
            ctx.record_collection_issue('partial', 'athena', code)

    async def inventory_workgroups(self, region):
        client = AWSFacadeUtils.get_client('athena', self.session, region)
        if client is None:
            self._issue('AthenaClientUnavailable')
            return {'status': 'unknown', 'work_groups': []}

        def collect():
            summaries = []
            seen = set()
            token = None
            complete = True
            for _ in range(25):
                args = {'MaxResults': 50}
                if token:
                    args['NextToken'] = token
                page = client.list_work_groups(**args)
                groups = page.get('WorkGroups')
                if not isinstance(groups, list):
                    raise ValueError('MalformedAthenaWorkgroupPage')
                summaries.extend(groups)
                if len(summaries) > 1000:
                    summaries = summaries[:1000]
                    complete = False
                    break
                new_token = page.get('NextToken')
                if not new_token:
                    break
                if not isinstance(new_token, str) or new_token in seen:
                    complete = False
                    break
                seen.add(new_token)
                token = new_token
            else:
                complete = False
            groups = []
            for item in summaries:
                name = item.get('Name') if isinstance(item, dict) else None
                if not isinstance(name, str) or not name:
                    complete = False
                    continue
                record = {'name': name, 'state': item.get('State'),
                          'enforcement_status': 'unknown',
                          'query_result_kms_status': 'unknown'}
                try:
                    detail = client.get_work_group(WorkGroup=name)
                    config = (detail.get('WorkGroup') or {}).get('Configuration')
                    if not isinstance(config, dict):
                        raise ValueError('MalformedAthenaWorkgroupDetail')
                    enforced = config.get('EnforceWorkGroupConfiguration')
                    if item.get('State') == 'DISABLED':
                        record['enforcement_status'] = 'not_applicable'
                        record['query_result_kms_status'] = 'not_applicable'
                    elif item.get('State') == 'ENABLED':
                        record['enforcement_status'] = (
                            'enforced' if enforced is True else
                            'not_enforced' if enforced is False else 'unknown')
                        encryption = (config.get('ResultConfiguration') or {}).get(
                            'EncryptionConfiguration')
                        if enforced is True:
                            if isinstance(encryption, dict):
                                option = encryption.get('EncryptionOption')
                                key = encryption.get('KmsKey')
                                record['query_result_kms_status'] = (
                                    'kms_enforced' if option in ('SSE_KMS', 'CSE_KMS')
                                    and isinstance(key, str) and key
                                    else 'kms_not_enforced' if option == 'SSE_S3'
                                    else 'unknown')
                            elif encryption is None:
                                # SSE-S3 is a common default, not plaintext.
                                record['query_result_kms_status'] = 'kms_not_enforced'
                        elif enforced is False:
                            record['query_result_kms_status'] = 'kms_not_enforced'
                except Exception:
                    complete = False
                groups.append(record)
            return {'status': 'complete' if complete else 'partial',
                    'work_groups': groups}

        try:
            result = await run_concurrently(collect)
        except Exception as exc:
            AWSFacadeUtils.record_listing_failure('athena', exc, 'ListOrGetAthenaWorkgroups')
            self._issue('AthenaWorkgroupInventoryIncomplete')
            return {'status': 'unknown', 'work_groups': []}
        if result['status'] != 'complete':
            self._issue('AthenaWorkgroupInventoryPartial')
        return result
