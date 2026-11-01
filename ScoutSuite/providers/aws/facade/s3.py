import json

from botocore.exceptions import ClientError

from ScoutSuite.core.console import print_exception, print_debug, print_warning
from ScoutSuite.providers.aws.facade.basefacade import AWSBaseFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.facade.pagination import collect_token_pages, PaginationError
from ScoutSuite.core.run_context import get_current_run_context
from ScoutSuite.providers.utils import run_concurrently, get_and_set_concurrently


class S3Facade(AWSBaseFacade):
    async def get_buckets(self):
        try:
            # If there are regions specified, try for each of them until one works.
            # Otherwise, try all the available regions until one works.
            # This is required in case there's an IAM policy that denies access to APIs on a regional basis,
            # as per https://github.com/nccgroup/ScoutSuite/issues/727
            buckets = []
            exception = None
            region_list = self.regions if self.regions else await run_concurrently(lambda: self.session.get_available_regions('s3'))
            for region in region_list:
                try:
                    client = AWSFacadeUtils.get_client('s3', self.session, region)
                    buckets = await self._list_bucket_pages(client, record_failure=False)
                except Exception as e:
                    exception = e
                else:
                    exception = None  # Fix for https://github.com/nccgroup/ScoutSuite/issues/916#issuecomment-728783965
                    break
            if exception:
                from ScoutSuite.core.run_context import get_current_run_context
                context = get_current_run_context()
                if context is not None:
                    context.record_collection_issue('failed', 's3', 'ListBuckets')
                print_exception('Failed to list S3 buckets in all candidate regions')
                return []
            if not buckets:
                return []
        except Exception as e:
            print_exception(f'Failed to list buckets: {e}')
            return []
        else:
            # We need first to retrieve bucket locations before retrieving bucket details
            await get_and_set_concurrently([self._get_and_set_s3_bucket_location], buckets, region=region)

            # Then we can retrieve bucket details concurrently
            await get_and_set_concurrently(
                [self._get_and_set_s3_bucket_logging,
                 self._get_and_set_s3_bucket_versioning,
                 self._get_and_set_s3_bucket_webhosting,
                 self._get_and_set_s3_bucket_default_encryption,
                 self._get_and_set_s3_acls,
                 self._get_and_set_s3_bucket_policy,
                 self._get_and_set_s3_bucket_tags,
                 self._get_and_set_s3_bucket_block_public_access,
                 self._get_and_set_s3_bucket_ownership,
                 self._get_and_set_s3_bucket_policy_status],
                buckets)

            # Non-async post-processing
            for bucket in buckets:
                self._set_s3_bucket_secure_transport(bucket)
            # Try to update CreationDate of all buckets with the correct values from 'us-east-1'
            await self._get_and_set_s3_bucket_creationdate(buckets)

            return buckets

    @staticmethod
    async def _list_bucket_pages(client, *, record_failure=True):
        return await collect_token_pages(
            client.list_buckets, items_path=('Buckets',),
            input_token='ContinuationToken', output_token=('ContinuationToken',),
            first_kwargs={'MaxBuckets': 1000}, scope='s3',
            record_failure=record_failure
        )

    async def _get_and_set_s3_bucket_location(self, bucket: {}, region=None):
        client = AWSFacadeUtils.get_client('s3', self.session, region)
        try:
            location = await run_concurrently(lambda: client.get_bucket_location(Bucket=bucket['Name']))
        except Exception as e:
            if 'NoSuchBucket' in str(e) or 'InvalidToken' in str(e):
                print_warning('Failed to get bucket location for {}: {}'.format(bucket['Name'], e))
            else:
                print_exception('Failed to get bucket location for {}: {}'.format(bucket['Name'], e))
            location = None

        if location:
            region = location['LocationConstraint'] if location['LocationConstraint'] else 'us-east-1'

            # Fixes issue #59: location constraint can be either EU or eu-west-1 for Ireland...
            if region == 'EU':
                region = 'eu-west-1'
        else:
            region = None

        bucket['region'] = region

    async def _get_and_set_s3_bucket_logging(self, bucket: {}):
        client = AWSFacadeUtils.get_client('s3', self.session, bucket['region'], )
        try:
            logging = await run_concurrently(lambda: client.get_bucket_logging(Bucket=bucket['Name']))
        except Exception as e:
            if 'NoSuchBucket' in str(e) or 'InvalidToken' in str(e):
                print_warning('Failed to get logging configuration for {}: {}'.format(bucket['Name'], e))
            else:
                print_exception('Failed to get logging configuration for {}: {}'.format(bucket['Name'], e))
            bucket['logging'] = 'Unknown'
        else:
            if 'LoggingEnabled' in logging:
                bucket['logging'] = \
                    logging['LoggingEnabled']['TargetBucket'] + '/' + logging['LoggingEnabled']['TargetPrefix']
            else:
                bucket['logging'] = 'Disabled'

    async def _get_and_set_s3_bucket_versioning(self, bucket: {}):
        client = AWSFacadeUtils.get_client('s3', self.session, bucket['region'])
        try:
            versioning = await run_concurrently(lambda: client.get_bucket_versioning(Bucket=bucket['Name']))
            bucket['versioning_status_enabled'] = self._status_to_bool(versioning.get('Status'))
            bucket['version_mfa_delete_enabled'] = self._status_to_bool(versioning.get('MFADelete'))
        except Exception as e:
            if 'NoSuchBucket' in str(e) or 'InvalidToken' in str(e):
                print_warning('Failed to get versioning configuration for {}: {}'.format(bucket['Name'], e))
            else:
                print_exception('Failed to get versioning configuration for {}: {}'.format(bucket['Name'], e))
            bucket['versioning_status_enabled'] = None
            bucket['version_mfa_delete_enabled'] = None

    async def _get_and_set_s3_bucket_webhosting(self, bucket: {}):
        client = AWSFacadeUtils.get_client('s3', self.session, bucket['region'])
        try:
            result = await run_concurrently(lambda: client.get_bucket_website(Bucket=bucket['Name']))
            bucket['web_hosting_enabled'] = 'IndexDocument' in result
        except Exception as e:
            if "NoSuchWebsiteConfiguration" in str(e):
                bucket['web_hosting_enabled'] = False
            else:
                if 'NoSuchBucket' in str(e) or 'InvalidToken' in str(e):
                    print_warning('Failed to get web hosting configuration for {}: {}'.format(bucket['Name'], e))
                else:
                    print_exception('Failed to get web hosting configuration for {}: {}'.format(bucket['Name'], e))

    async def _get_and_set_s3_bucket_default_encryption(self, bucket: {}):
        """S3 guarantees SSE-S3 baseline for new writes since January 2023."""
        bucket['default_encryption_enabled'] = None
        bucket['default_encryption_algorithm'] = None
        bucket['default_encryption_key'] = None
        bucket['encryption_evidence'] = 'unverified'
        client = AWSFacadeUtils.get_client('s3', self.session, bucket.get('region'))
        if client is None:
            self._record_context_issue('BucketEncryption')
            return
        try:
            config = await run_concurrently(
                lambda: client.get_bucket_encryption(Bucket=bucket['Name'])
            )
            rules = (config.get('ServerSideEncryptionConfiguration') or {}).get('Rules')
            if not isinstance(rules, list) or len(rules) != 1:
                raise ValueError('MalformedEncryptionConfiguration')
            default = rules[0].get('ApplyServerSideEncryptionByDefault')
            if not isinstance(default, dict):
                raise ValueError('MalformedEncryptionConfiguration')
            algorithm = default.get('SSEAlgorithm')
            if algorithm not in ('AES256', 'aws:kms', 'aws:kms:dsse'):
                raise ValueError('UnknownEncryptionAlgorithm')
            bucket['default_encryption_enabled'] = True
            bucket['default_encryption_algorithm'] = algorithm
            bucket['default_encryption_key'] = default.get('KMSMasterKeyID')
            bucket['encryption_evidence'] = 'api'
        except ClientError as error:
            code = error.response.get('Error', {}).get('Code')
            if code == 'ServerSideEncryptionConfigurationNotFoundError':
                # This is no longer evidence of an unencrypted bucket.
                # It describes new writes, not historical object encryption.
                bucket['default_encryption_enabled'] = True
                bucket['default_encryption_algorithm'] = 'AES256'
                bucket['encryption_evidence'] = 'aws_baseline'
            else:
                self._record_context_issue('BucketEncryption')
                print_exception('Unable to verify S3 bucket encryption')
        except Exception:
            self._record_context_issue('BucketEncryption')
            print_exception('Malformed or unavailable S3 encryption configuration')

    async def _get_and_set_s3_acls(self, bucket: {}, key_name=None):
        bucket_name = bucket['Name']
        client = AWSFacadeUtils.get_client('s3', self.session, bucket['region'])
        try:
            grantees = {}
            if key_name:
                grants = await run_concurrently(lambda: client.get_object_acl(Bucket=bucket_name, Key=key_name))
            else:
                grants = await run_concurrently(lambda: client.get_bucket_acl(Bucket=bucket_name))
            for grant in grants['Grants']:
                if 'ID' in grant['Grantee']:
                    grantee = grant['Grantee']['ID']
                    display_name = grant['Grantee']['DisplayName'] if \
                        'DisplayName' in grant['Grantee'] else grant['Grantee']['ID']
                elif 'URI' in grant['Grantee']:
                    grantee = grant['Grantee']['URI'].split('/')[-1]
                    display_name = self._s3_group_to_string(grant['Grantee']['URI'])
                else:
                    grantee = display_name = 'Unknown'
                permission = grant['Permission']
                grantees.setdefault(grantee, {})
                grantees[grantee]['DisplayName'] = display_name
                if 'URI' in grant['Grantee']:
                    grantees[grantee]['URI'] = grant['Grantee']['URI']
                grantees[grantee].setdefault('permissions', self._init_s3_permissions())
                self._set_s3_permissions(grantees[grantee]['permissions'], permission)
            bucket['grantees'] = grantees
            bucket['acl_collection_status'] = 'success'
        except Exception as e:
            if 'NoSuchBucket' in str(e) or 'InvalidToken' in str(e):
                print_warning(f'Failed to get ACL configuration for {bucket_name}: {e}')
            else:
                print_exception(f'Failed to get ACL configuration for {bucket_name}: {e}')
            bucket['grantees'] = {}
            bucket['acl_collection_status'] = 'failed'
            self._record_context_issue('BucketACL')

    async def _get_and_set_s3_bucket_policy(self, bucket: {}):
        bucket['policy_collection_status'] = 'failed'
        client = AWSFacadeUtils.get_client('s3', self.session, bucket.get('region'))
        if client is None:
            self._record_context_issue('BucketPolicy')
            return
        try:
            response = await run_concurrently(
                lambda: client.get_bucket_policy(Bucket=bucket['Name'])
            )
            policy = json.loads(response['Policy'])
            if not isinstance(policy, dict) or 'Statement' not in policy:
                raise ValueError('MalformedBucketPolicy')
            bucket['policy'] = policy
            bucket['policy_collection_status'] = 'success'
        except ClientError as error:
            if error.response.get('Error', {}).get('Code') == 'NoSuchBucketPolicy':
                bucket['policy_collection_status'] = 'absent'
            else:
                self._record_context_issue('BucketPolicy')
                print_exception('Unable to verify S3 bucket policy')
        except Exception:
            self._record_context_issue('BucketPolicy')
            print_exception('Malformed or unavailable S3 bucket policy')

    async def _get_and_set_s3_bucket_tags(self, bucket: {}):
        client = AWSFacadeUtils.get_client('s3', self.session, bucket['region'])
        try:
            bucket_tagset = await run_concurrently(lambda: client.get_bucket_tagging(Bucket=bucket['Name']))
            bucket['tags'] = {x['Key']: x['Value'] for x in bucket_tagset['TagSet']}
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchTagSet':
                if 'NoSuchBucket' in str(e) or 'InvalidToken' in str(e):
                    print_warning('Failed to get bucket tags for {}: {}'.format(bucket['Name'], e))
                else:
                    print_exception('Failed to get bucket tags for {}: {}'.format(bucket['Name'], e))
        except Exception as e:
            if 'NoSuchBucket' in str(e) or 'InvalidToken' in str(e):
                print_warning('Failed to get bucket tags for {}: {}'.format(bucket['Name'], e))
            else:
                print_exception('Failed to get bucket tags for {}: {}'.format(bucket['Name'], e))
            bucket['tags'] = {}

    @staticmethod
    def _record_context_issue(reason):
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue('partial', 's3', reason)

    @staticmethod
    def _absent_access_block():
        return {
            'BlockPublicAcls': False, 'IgnorePublicAcls': False,
            'BlockPublicPolicy': False, 'RestrictPublicBuckets': False
        }

    async def _get_and_set_s3_bucket_block_public_access(self, bucket: {}):
        client = AWSFacadeUtils.get_client('s3', self.session, bucket.get('region'))
        bucket['public_access_block_configuration'] = None
        if client is None:
            self._record_context_issue('BucketPublicAccessBlock')
            return
        try:
            result = await run_concurrently(
                lambda: client.get_public_access_block(Bucket=bucket['Name'])
            )
            bucket['public_access_block_configuration'] = result[
                'PublicAccessBlockConfiguration']
        except ClientError as error:
            code = error.response.get('Error', {}).get('Code')
            if code == 'NoSuchPublicAccessBlockConfiguration':
                bucket['public_access_block_configuration'] = self._absent_access_block()
            else:
                self._record_context_issue('BucketPublicAccessBlock')
                print_exception('Unable to verify S3 bucket public-access settings')
        except Exception:
            self._record_context_issue('BucketPublicAccessBlock')
            print_exception('Unable to verify S3 bucket public-access settings')

    async def _get_and_set_s3_bucket_ownership(self, bucket: {}):
        client = AWSFacadeUtils.get_client('s3', self.session, bucket.get('region'))
        bucket['object_ownership'] = None
        if client is None:
            self._record_context_issue('BucketOwnership')
            return
        try:
            response = await run_concurrently(
                lambda: client.get_bucket_ownership_controls(Bucket=bucket['Name'])
            )
            rules = (response.get('OwnershipControls') or {}).get('Rules', [])
            values = [rule.get('ObjectOwnership') for rule in rules if isinstance(rule, dict)]
            bucket['object_ownership'] = values[0] if len(values) == 1 else None
        except ClientError as error:
            if error.response.get('Error', {}).get('Code') != 'OwnershipControlsNotFoundError':
                self._record_context_issue('BucketOwnership')
                print_exception('Unable to retrieve S3 object ownership configuration')
        except Exception:
            self._record_context_issue('BucketOwnership')
            print_exception('Unable to retrieve S3 object ownership configuration')

    async def _get_and_set_s3_bucket_policy_status(self, bucket: {}):
        client = AWSFacadeUtils.get_client('s3', self.session, bucket.get('region'))
        bucket['policy_is_public'] = None
        if client is None:
            self._record_context_issue('BucketPolicyStatus')
            return
        try:
            response = await run_concurrently(
                lambda: client.get_bucket_policy_status(Bucket=bucket['Name'])
            )
            value = (response.get('PolicyStatus') or {}).get('IsPublic')
            if not isinstance(value, bool):
                self._record_context_issue('BucketPolicyStatus')
            else:
                bucket['policy_is_public'] = value
        except ClientError as error:
            code = error.response.get('Error', {}).get('Code')
            if code == 'NoSuchBucketPolicy':
                bucket['policy_is_public'] = False
            else:
                self._record_context_issue('BucketPolicyStatus')
                print_exception('Unable to verify S3 bucket policy exposure')
        except Exception:
            self._record_context_issue('BucketPolicyStatus')
            print_exception('Unable to verify S3 bucket policy exposure')

    async def _get_and_set_s3_bucket_creationdate(self, buckets):
        # Preserve original CreationDate on lookup failure. Unlike the
        # historical unpaginated request, this retrieves the complete catalog.
        client = AWSFacadeUtils.get_client('s3', self.session, 'us-east-1')
        if client is None:
            return
        try:
            listing = await self._list_bucket_pages(client)
        except PaginationError as error:
            listing = error.items
            print_debug('Unable to retrieve the complete S3 creation date catalog')
        lookup = {item['Name']: item.get('CreationDate')
                  for item in listing if isinstance(item, dict) and 'Name' in item}
        for bucket in buckets:
            bucket['CreationDate'] = lookup.get(bucket['Name']) or bucket.get('CreationDate')

    @staticmethod
    def _policy_enforces_secure_transport(bucket):
        """Prove an unconditional deny of HTTP for bucket AND object requests."""
        policy = bucket.get('policy')
        if not isinstance(policy, dict):
            return False
        statements = policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list):
            return False
        name = bucket.get('Name') or bucket.get('name')
        if not name:
            return False
        for statement in statements:
            if not isinstance(statement, dict) or statement.get('Effect') != 'Deny':
                continue
            principal = statement.get('Principal')
            if principal not in ('*', {'AWS': '*'}):
                continue
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            if not isinstance(actions, list) or not any(
                action in ('*', 's3:*') for action in actions
            ):
                continue
            resources = statement.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]
            if not isinstance(resources, list):
                continue
            has_bucket = any(
                value == '*' or value.endswith(':s3:::' + name)
                for value in resources if isinstance(value, str)
            )
            has_objects = any(
                value == '*' or value.endswith(':s3:::' + name + '/*')
                for value in resources if isinstance(value, str)
            )
            if not has_bucket or not has_objects:
                continue
            conditions = statement.get('Condition', {})
            if not isinstance(conditions, dict) or set(conditions) != {'Bool'}:
                continue
            bools = conditions.get('Bool')
            if not isinstance(bools, dict):
                continue
            normalized = {k.lower(): v for k, v in bools.items()
                          if isinstance(k, str)}
            if set(normalized) - {'aws:securetransport', 'aws:principalisawsservice'}:
                continue
            secure = normalized.get('aws:securetransport')
            if str(secure).lower() != 'false':
                continue
            if ('aws:principalisawsservice' in normalized and
                    str(normalized['aws:principalisawsservice']).lower() != 'false'):
                continue
            return True
        return False

    def _set_s3_bucket_secure_transport(self, bucket: {}):
        state = bucket.get('policy_collection_status')
        if state == 'absent':
            bucket['secure_transport_enabled'] = False
        elif state == 'success':
            bucket['secure_transport_enabled'] = self._policy_enforces_secure_transport(
                bucket
            )
        else:
            bucket['secure_transport_enabled'] = None
            self._record_context_issue('SecureTransportEvidence')

    def get_s3_public_access_block(self, account_id):
        # The S3 Control endpoint must belong to the credentials' partition.
        region = getattr(self.session, 'region_name', None) or 'us-east-1'
        if region.startswith('cn-'):
            region = 'cn-north-1'
        elif region.startswith('us-gov-'):
            region = 'us-gov-west-1'
        else:
            region = 'us-east-1'
        client = AWSFacadeUtils.get_client('s3control', self.session, region)
        if client is None:
            self._record_context_issue('AccountPublicAccessBlock')
            return None
        try:
            result = client.get_public_access_block(AccountId=account_id)
            return result['PublicAccessBlockConfiguration']
        except ClientError as error:
            code = error.response.get('Error', {}).get('Code')
            if code == 'NoSuchPublicAccessBlockConfiguration':
                return self._absent_access_block()
            self._record_context_issue('AccountPublicAccessBlock')
            print_exception('Unable to verify S3 account public-access settings')
            return None
        except Exception:
            self._record_context_issue('AccountPublicAccessBlock')
            print_exception('Unable to verify S3 account public-access settings')
            return None

    @staticmethod
    def _init_s3_permissions():
        permissions = {'read': False, 'write': False, 'read_acp': False, 'write_acp': False}
        return permissions

    @staticmethod
    def _set_s3_permissions(permissions: str, name: str):
        if name == 'READ' or name == 'FULL_CONTROL':
            permissions['read'] = True
        if name == 'WRITE' or name == 'FULL_CONTROL':
            permissions['write'] = True
        if name == 'READ_ACP' or name == 'FULL_CONTROL':
            permissions['read_acp'] = True
        if name == 'WRITE_ACP' or name == 'FULL_CONTROL':
            permissions['write_acp'] = True

    @staticmethod
    def _s3_group_to_string(uri: str):
        if uri == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
            return 'Authenticated users'
        elif uri == 'http://acs.amazonaws.com/groups/global/AllUsers':
            return 'Everyone'
        elif uri == 'http://acs.amazonaws.com/groups/s3/LogDelivery':
            return 'Log delivery'
        else:
            return uri

    @staticmethod
    def _status_to_bool(value: str):
        """ Converts a string to True if it is equal to 'Enabled' or to False otherwise. """
        return value == 'Enabled'
