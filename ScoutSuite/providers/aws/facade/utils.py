import boto3
from botocore.exceptions import ClientError, ReadTimeoutError, ConnectTimeoutError, EndpointConnectionError
from botocore.config import Config

from ScoutSuite.core.conditions import print_exception
from ScoutSuite.providers.utils import run_concurrently
from ScoutSuite.core.run_context import get_current_run_context, safe_collection_issue_code


DENIED_CODES = ('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation',
                'AuthorizationError', 'AccessDeniedFault')
UNSUPPORTED_CODES = ('UnsupportedOperation', 'UnknownOperationException', 'InvalidAction')


class AWSFacadeUtils:
    # No process-global client cache: credentials are isolated by RunContext.

    @staticmethod
    def record_listing_failure(scope: str, error: Exception, operation: str,
                               region: str = None) -> None:
        """Record a swallowed inventory-listing error as incomplete collection.

        Only the sanitized error code is stored, never the SDK message.
        """
        context = get_current_run_context()
        if context is None:
            return
        code = error.response.get('Error', {}).get('Code', '') if isinstance(error, ClientError) else ''
        kind = 'denied' if code in DENIED_CODES else 'unsupported' if code in UNSUPPORTED_CODES else 'failed'
        context.record_collection_issue(
            kind, scope, safe_collection_issue_code(operation + (code or 'Error')),
            region=region)

    @staticmethod
    async def get_all_pages(service: str, region: str, session: boto3.session.Session, paginator_name: str,
                            entity: str, **paginator_args):
        """
        Gets all the entities from a paginator given an entity key

        :param service:str: Name of the AWS service (ec2, iam, etc.)
        :param region:str: Region
        :param session:boto3.session.Session: Boto3 session used to authenticate the client
        :param paginator_name:str: Name of the paginator
        :param entity:str: Key used to retreive the entities in the paginator's response
        :param **paginator_args: Arguments passed to the paginator

        :return: A list of the fetched entities.
        """

        results = await AWSFacadeUtils.get_multiple_entities_from_all_pages(
            service, region, session, paginator_name, [entity], **paginator_args)
        if len(results) > 0:
            return results[entity]
        else:
            return []

    @staticmethod
    async def get_multiple_entities_from_all_pages(service: str, region: str, session: boto3.session.Session,
                                                   paginator_name: str, entities: list, **paginator_args):
        """
        Gets all the entities from a paginator given multiple entitiy keys
            :param service:str: Name of the AWS service (ec2, iam, etc.)
            :param region:str: Region
            :param session:boto3.session.Session: Boto3 session used to authenticate the client
            :param paginator_name:str: Name of the paginator
            :param entities:list: Keys used to retreive the entities in the paginator's response
            :param **paginator_args: Arguments passed to the paginator

            :return: A dictionary with the entity keys as keys, and the fetched entities lists as values.
        """

        # Creation failures must not be confused with an empty successful page.
        empty = {key: [] for key in entities}
        context = get_current_run_context()
        client = AWSFacadeUtils.get_client(service, session, region)
        if client is None:
            if context is not None:
                context.record_collection_issue('failed', service, 'ClientConstruction', region=region)
            return empty
        try:
            paginator = client.get_paginator(paginator_name).paginate(**paginator_args)
            return await run_concurrently(lambda: AWSFacadeUtils._get_all_pages_from_paginator(paginator, entities))
        except ClientError as error:
            code = error.response.get('Error', {}).get('Code', 'ClientError')
            if code in DENIED_CODES:
                if context is not None:
                    context.record_collection_issue('denied', service, 'AccessDenied', region=region)
                print_exception('Paginator access denied for ' + service)
                return empty
            if code in UNSUPPORTED_CODES:
                if context is not None:
                    context.record_collection_issue('unsupported', service, 'UnsupportedOperation', region=region)
                print_exception('Paginator operation unsupported for ' + service)
                return empty
            # Re-raised: the caller decides. Some codes are expected answers
            # (e.g. Redshift/ElastiCache InvalidParameterValue for VPC-only
            # accounts); callers that treat the error as a failure record it
            # with record_listing_failure.
            raise
        except (ReadTimeoutError, ConnectTimeoutError, EndpointConnectionError):
            if context is not None:
                context.record_collection_issue('failed', service, 'Timeout', region=region)
            print_exception('Paginator timeout for ' + service)
            return empty
        except (KeyError, TypeError):
            if context is not None:
                context.record_collection_issue('failed', service, 'MalformedPage', region=region)
            print_exception('Malformed paginator page for ' + service)
            return empty

    @staticmethod
    def _get_all_pages_from_paginator(paginator, entities: list):
        resources = {entity: [] for entity in entities}

        # There's an API call hidden behind each iteration:
        for page in paginator:
            for entity in entities:
                resources[entity].extend(page[entity])

        return resources

    @staticmethod
    def get_client(service: str, session: boto3.session.Session, region: str = None):
        """
        Instantiates an AWS API client

        :param service: Service targeted, e.g. ec2
        :param session: The aws session
        :param region:  Region desired, e.g. us-east-2

        :return:
        """

        try:
            def create():
                # Explicit finite SDK timeouts and a bounded, single retry layer.
                config = Config(
                    connect_timeout=5, read_timeout=30,
                    retries={'mode': 'standard', 'total_max_attempts': 3}
                )
                if region:
                    client = session.client(service, region_name=region, config=config)
                else:
                    client = session.client(service, config=config)
                # Registered once for each run-scoped, cached client. Botocore
                # emits after-call for final responses, including HTTP errors.
                # Never persist parameters, parsed payloads, request IDs or secrets.
                if context is not None and context.provider == 'aws':
                    events = getattr(getattr(client, 'meta', None), 'events', None)
                    if events is not None:
                        location = region or getattr(client.meta, 'region_name', None) or 'global'

                        def observe(http_response=None, parsed=None, event_name=None, **_kw):
                            try:
                                if http_response is None or not isinstance(event_name, str):
                                    return
                                status_code = getattr(http_response, 'status_code', None)
                                error = parsed.get('Error', {}) if isinstance(parsed, dict) else {}
                                code = error.get('Code') if isinstance(error, dict) else None
                                operation = event_name.rsplit('.', 1)[-1]
                                expected_absences = {
                                    ('s3', 'GetPublicAccessBlock',
                                     'NoSuchPublicAccessBlockConfiguration'),
                                    ('s3', 'GetBucketEncryption',
                                     'ServerSideEncryptionConfigurationNotFoundError'),
                                    ('backup', 'GetBackupVaultAccessPolicy',
                                     'ResourceNotFoundException'),
                                }
                                if (service, operation, code) in expected_absences:
                                    outcome = 'absent'
                                elif code in DENIED_CODES or status_code in (401, 403):
                                    outcome = 'denied'
                                elif code in UNSUPPORTED_CODES:
                                    outcome = 'unsupported'
                                elif isinstance(status_code, int) and status_code >= 400:
                                    outcome = 'failed'
                                elif isinstance(status_code, int) and status_code < 400:
                                    outcome = 'success'
                                else:
                                    return
                                context.record_aws_api(service, location, operation, outcome)
                            except (AttributeError, TypeError, ValueError):
                                # Telemetry must not interfere with AWS API calls.
                                pass

                        events.register('after-call.*.*', observe)
                return client

            context = get_current_run_context()
            if context is None:
                return create()
            return context.get_cached_client(session, service, region, create)
        except Exception as e:
            context = get_current_run_context()
            if context is not None:
                context.record_collection_issue('failed', service, 'ClientConstruction')
            print_exception(f'Failed to create client for the {service} service: {e}')
            return None
