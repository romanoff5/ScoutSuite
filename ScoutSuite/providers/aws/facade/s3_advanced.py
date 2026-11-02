"""M10-Q: read-only S3 advanced control-plane inventory.

No S3 object/body, grant credentials or sampled data is retrieved. A denied or
failed API never produces a verified empty inventory or a passing exposure test.
"""
import asyncio
import json

from botocore.exceptions import ClientError

from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently
from ScoutSuite.providers.utils import get_non_provider_id

ABSENT = object()
DENIED_CODES = {'AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation',
                'Forbidden', 'AllAccessDisabled'}
UNSUPPORTED_CODES = {'NotImplemented', 'NotImplementedException',
                     'UnsupportedOperation', 'UnsupportedOperationException',
                     'InvalidAction', 'UnknownOperationException'}
POLICY_ABSENT_CODES = {'NoSuchAccessPointPolicy', 'NoSuchMultiRegionAccessPointPolicy',
                       'NoSuchBucketPolicy', 'NoSuchAccessGrantsInstanceResourcePolicy'}
PAGE_SIZE = 100
REGION_CONCURRENCY = 4


def _as_policy(raw):
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


class S3AdvancedFacade:
    def __init__(self, session, account_id):
        self.session = session
        self.account_id = account_id

    @staticmethod
    def _issue(status, operation, region):
        # RunContext accepts a strict 64-char identifier; preserve distinct
        # failures with a stable digest, without altering raw resource evidence.
        import hashlib
        import re
        reason = re.sub(r'[^A-Za-z0-9_.-]', '-', operation + '-' + region)
        if len(reason) > 64:
            reason = reason[:55] + '-' + hashlib.sha256(reason.encode()).hexdigest()[:8]
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue(status, 's3', reason)

    async def _call(self, client, operation, region, *, policy_absence=False, **params):
        if client is None:
            self._issue('failed', operation + 'ClientUnavailable', region)
            return None
        method = ''.join(('_' + c.lower()) if c.isupper() else c
                         for c in operation).lstrip('_')
        try:
            value = await run_concurrently(lambda: getattr(client, method)(**params))
            if not isinstance(value, dict):
                self._issue('failed', operation + 'MalformedResponse', region)
                return None
            return value
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code', 'ClientError')
            if policy_absence and code in POLICY_ABSENT_CODES:
                return ABSENT
            status = ('denied' if code in DENIED_CODES else
                      'unsupported' if code in UNSUPPORTED_CODES else 'failed')
            self._issue(status, operation + ':' + code, region)
        except Exception:
            self._issue('failed', operation + 'Failed', region)
        return None

    async def _pages(self, client, operation, field, region, *,
                     input_token='NextToken', output_token='NextToken',
                     page_size='MaxResults', **params):
        items, seen, token = [], set(), None
        while True:
            args = dict(params)
            args[page_size] = PAGE_SIZE
            if token:
                args[input_token] = token
            response = await self._call(client, operation, region, **args)
            if response is None:
                return items, False
            page = response.get(field)
            if not isinstance(page, list):
                self._issue('failed', operation + 'MalformedItems', region)
                return items, False
            items.extend(page)
            next_token = response.get(output_token)
            if not next_token:
                return items, True
            if not isinstance(next_token, str) or next_token in seen:
                self._issue('partial', operation + 'InvalidPaginationToken', region)
                return items, False
            seen.add(next_token)
            token = next_token

    def _index(self, items, region, collection, key_field, *, name_field=None):
        index, complete = {}, True
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get(key_field), str) or not item[key_field]:
                self._issue('partial', collection + 'InvalidIdentity', region)
                complete = False
                continue
            name = item.get(name_field or key_field) or item[key_field]
            key = get_non_provider_id(item[key_field])
            if key in index:
                self._issue('partial', collection + 'DuplicateIdentity', region)
                complete = False
                continue
            index[key] = {'id': key, 'name': name, 'region': region, **item}
        return index, complete

    async def _access_point(self, client, record, region, *, directory=False):
        name = record['Name']
        params = {'AccountId': self.account_id, 'Name': name}
        detail = await self._call(client, 'GetAccessPoint', region, **params)
        record['detail_verified'] = detail is not None
        if detail is not None:
            record.update(detail)
        status = await self._call(client, 'GetAccessPointPolicyStatus', region, **params)
        public = (status.get('PolicyStatus') or {}).get('IsPublic') if status else None
        if not isinstance(public, bool) and status is not None:
            self._issue('partial', 'GetAccessPointPolicyStatusMalformed', region)
        record['policy_public'] = public if isinstance(public, bool) else None
        record['public_policy_review'] = public is True
        policy = await self._call(client, 'GetAccessPointPolicy', region,
                                  policy_absence=True, **params)
        record['policy_status'] = ('absent' if policy is ABSENT else
                                   'verified' if policy is not None else 'unknown')
        if isinstance(policy, dict):
            record['policy_document'] = _as_policy(policy.get('Policy'))
            if record['policy_document'] is None:
                record['policy_status'] = 'unknown'
                self._issue('partial', 'GetAccessPointPolicyMalformed', region)
        if directory:
            scope = await self._call(client, 'GetAccessPointScope', region, **params)
            record['scope_verified'] = scope is not None and isinstance(scope.get('Scope'), dict)
            record['scope'] = scope.get('Scope') if record['scope_verified'] else None
        record['detail_complete'] = bool(
            record['detail_verified'] and isinstance(public, bool)
            and record['policy_status'] != 'unknown'
            and (not directory or record.get('scope_verified')))

    async def _directory_bucket(self, client, record, region):
        name = record['Name']
        record['policy_status'] = 'unknown'
        policy = await self._call(client, 'GetBucketPolicy', region,
                                  policy_absence=True, Bucket=name)
        if policy is ABSENT:
            record['policy_status'] = 'absent'
        elif isinstance(policy, dict):
            parsed = _as_policy(policy.get('Policy'))
            if parsed is not None:
                record['policy_document'] = parsed
                record['policy_status'] = 'verified'
            else:
                self._issue('partial', 'GetDirectoryBucketPolicyMalformed', region)
        encryption = await self._call(client, 'GetBucketEncryption', region, Bucket=name)
        record['encryption_verified'] = bool(
            isinstance(encryption, dict)
            and isinstance(encryption.get('ServerSideEncryptionConfiguration'), dict))
        record['encryption_configuration'] = (
            encryption.get('ServerSideEncryptionConfiguration')
            if record['encryption_verified'] else None)
        record['security_status'] = 'not_evaluated'
        record['detail_complete'] = bool(record['policy_status'] != 'unknown'
                                         and record['encryption_verified'])

    async def _scan_region(self, region):
        ctrl = AWSFacadeUtils.get_client('s3control', self.session, region)
        s3 = AWSFacadeUtils.get_client('s3', self.session, region)
        data = {'id': region, 'name': region, 'region': region,
                'access_points': {}, 'directory_access_points': {},
                'directory_buckets': {}, 'access_grants_instances': {},
                'access_grants_locations': {}, 'access_grants': {},
                'collection': {}}
        definitions = [
            ('access_points', ctrl, 'ListAccessPoints', 'AccessPointList',
             'Name', 'NextToken', 'NextToken', 'MaxResults'),
            ('directory_access_points', ctrl, 'ListAccessPointsForDirectoryBuckets',
             'AccessPointList', 'Name', 'NextToken', 'NextToken', 'MaxResults'),
            ('directory_buckets', s3, 'ListDirectoryBuckets',
             'Buckets', 'Name', 'ContinuationToken', 'ContinuationToken',
             'MaxDirectoryBuckets'),
            ('access_grants_instances', ctrl, 'ListAccessGrantsInstances',
             'AccessGrantsInstancesList', 'AccessGrantsInstanceArn',
             'NextToken', 'NextToken', 'MaxResults')]
        for collection, client, op, field, identity, it, ot, size in definitions:
            params = {'AccountId': self.account_id} if client is ctrl and collection != 'directory_buckets' else {}
            rows, pages_complete = await self._pages(
                client, op, field, region, input_token=it, output_token=ot,
                page_size=size, **params)
            index, identities_complete = self._index(rows, region, op, identity)
            data[collection] = index
            data['collection'][collection] = (
                'complete' if pages_complete and identities_complete else 'incomplete')
        for point in data['access_points'].values():
            await self._access_point(ctrl, point, region)
        for point in data['directory_access_points'].values():
            await self._access_point(ctrl, point, region, directory=True)
        for bucket in data['directory_buckets'].values():
            await self._directory_bucket(s3, bucket, region)

        # A verified empty instance list is NOT an API access failure.
        if data['collection']['access_grants_instances'] == 'complete' and not data['access_grants_instances']:
            data['collection']['access_grants_locations'] = 'not_configured'
            data['collection']['access_grants'] = 'not_configured'
            data['access_grants_resource_policy_status'] = 'not_configured'
        elif data['collection']['access_grants_instances'] != 'complete' and not data['access_grants_instances']:
            for key in ('access_grants_locations', 'access_grants'):
                data['collection'][key] = 'incomplete'
            data['access_grants_resource_policy_status'] = 'unknown'
        else:
            for collection, op, field, identity in [
                ('access_grants_locations', 'ListAccessGrantsLocations',
                 'AccessGrantsLocationsList', 'AccessGrantsLocationArn'),
                ('access_grants', 'ListAccessGrants',
                 'AccessGrantsList', 'AccessGrantArn')]:
                rows, complete = await self._pages(
                    ctrl, op, field, region, AccountId=self.account_id)
                index, valid = self._index(rows, region, op, identity)
                data[collection] = index
                data['collection'][collection] = (
                    'complete' if complete and valid else 'incomplete')
            for grant in data['access_grants'].values():
                grant['broad_write_review'] = (
                    grant.get('Permission') in ('WRITE', 'READWRITE')
                    and grant.get('GrantScope') == 's3://')
            policy = await self._call(
                ctrl, 'GetAccessGrantsInstanceResourcePolicy', region,
                policy_absence=True, AccountId=self.account_id)
            data['access_grants_resource_policy_status'] = (
                'absent' if policy is ABSENT else
                'verified' if isinstance(policy, dict) else 'unknown')
            if isinstance(policy, dict):
                data['access_grants_resource_policy'] = _as_policy(policy.get('Policy'))
                if data['access_grants_resource_policy'] is None:
                    data['access_grants_resource_policy_status'] = 'unknown'
                    self._issue('partial', 'AccessGrantsResourcePolicyMalformed', region)
            details = await self._call(ctrl, 'GetAccessGrantsInstance', region,
                                       AccountId=self.account_id)
            data['access_grants_instance_detail_verified'] = details is not None
            if details is not None:
                data['access_grants_instance_detail'] = details

        for collection in ('access_points', 'directory_access_points', 'directory_buckets'):
            if any(not item.get('detail_complete') for item in data[collection].values()):
                data['collection'][collection] = 'incomplete'
        data['coverage_status'] = (
            'complete' if all(value in ('complete', 'not_configured')
                              for value in data['collection'].values())
            and (not data['access_grants_instances']
                 or (data.get('access_grants_instance_detail_verified')
                     and data['access_grants_resource_policy_status'] != 'unknown'))
            else 'incomplete')
        for name in ('access_points', 'directory_access_points',
                     'directory_buckets', 'access_grants_instances',
                     'access_grants_locations', 'access_grants'):
            data[name + '_count'] = len(data[name])
        return data

    async def _mrap(self, partition_name):
        result = {'collection_status': 'unknown', 'items': {}}
        if partition_name != 'aws':
            self._issue('unsupported', 'MRAPPartitionNotSupported', partition_name)
            result['collection_status'] = 'unsupported'
            return result
        # MRAP control plane MUST use US West (Oregon), irrespective of scan region filters.
        region = 'us-west-2'
        client = AWSFacadeUtils.get_client('s3control', self.session, region)
        rows, complete = await self._pages(
            client, 'ListMultiRegionAccessPoints', 'AccessPoints', region,
            AccountId=self.account_id)
        data, identities_complete = self._index(
            rows, region, 'ListMultiRegionAccessPoints', 'Name')
        for record in data.values():
            params = {'AccountId': self.account_id, 'Name': record['Name']}
            detail = await self._call(client, 'GetMultiRegionAccessPoint', region, **params)
            record['detail_verified'] = bool(
                isinstance(detail, dict) and isinstance(detail.get('AccessPoint'), dict))
            if record['detail_verified']:
                record.update(detail['AccessPoint'])
            policy_status = await self._call(
                client, 'GetMultiRegionAccessPointPolicyStatus', region, **params)
            public = ((policy_status.get('Established') or {}).get('IsPublic')
                      if policy_status else None)
            record['policy_public'] = public if isinstance(public, bool) else None
            record['public_policy_review'] = public is True
            policy = await self._call(client, 'GetMultiRegionAccessPointPolicy', region,
                                      policy_absence=True, **params)
            record['policy_status'] = (
                'absent' if policy is ABSENT else
                'verified' if policy is not None else 'unknown')
            if isinstance(policy, dict):
                record['policy_document'] = _as_policy(policy.get('Policy'))
                if record['policy_document'] is None:
                    record['policy_status'] = 'unknown'
                    self._issue('partial', 'GetMultiRegionAccessPointPolicyMalformed', region)
            record['detail_complete'] = (
                record['detail_verified'] and isinstance(public, bool)
                and record['policy_status'] != 'unknown')
        result['items'] = data
        result['collection_status'] = (
            'complete' if complete and identities_complete
            and all(item['detail_complete'] for item in data.values())
            else 'incomplete')
        return result

    async def collect(self, facade, *, regions=None, excluded_regions=None,
                      partition_name='aws'):
        try:
            selected = await facade.build_region_list(
                's3control', regions, excluded_regions, partition_name)
        except Exception:
            self._issue('failed', 'S3ControlRegionDiscovery', partition_name)
            selected = []
        semaphore = asyncio.Semaphore(REGION_CONCURRENCY)

        async def regional(region):
            async with semaphore:
                try:
                    return await self._scan_region(region)
                except Exception:
                    self._issue('failed', 'AdvancedRegionCollection', region)
                    return {'id': region, 'name': region, 'region': region,
                            'coverage_status': 'incomplete', 'collection': {},
                            'access_points': {}, 'directory_access_points': {},
                            'directory_buckets': {}, 'access_grants_instances': {},
                            'access_grants_locations': {}, 'access_grants': {}}

        entries = await asyncio.gather(*(regional(r) for r in selected))
        mrap = await self._mrap(partition_name)
        inventory = {
            'regions': dict(zip(selected, entries)),
            'multi_region_access_points': mrap['items'],
            'mrap_collection_status': mrap['collection_status'],
            'regional_discovery_status': (
                'complete' if selected else 'unknown'),
        }
        inventory['coverage_status'] = (
            'complete' if inventory['regional_discovery_status'] == 'complete'
            and all(x['coverage_status'] == 'complete' for x in entries)
            and mrap['collection_status'] == 'complete' else 'incomplete')
        inventory['regions_count'] = len(selected)
        inventory['multi_region_access_points_count'] = len(mrap['items'])
        for group in ('access_points', 'directory_access_points',
                      'directory_buckets', 'access_grants_instances',
                      'access_grants_locations', 'access_grants'):
            inventory[group + '_count'] = sum(
                len(item.get(group, {})) for item in entries)
        return inventory
