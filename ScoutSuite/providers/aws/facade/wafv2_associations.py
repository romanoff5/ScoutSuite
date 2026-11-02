"""Read-only WAFv2 association discovery; bounded and evidence-aware.

Regional WAFv2 resource associations are unpaginated; CloudFront uses
its own paginated ListDistributionsByWebACLId API. A missing answer is
unknown, never a zero-association finding.
"""
from botocore.exceptions import ClientError

from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.utils import run_concurrently


# Exactly the resource types supported by the pinned Botocore WAFv2 model.
# Do not silently claim this covers newly introduced AWS resource types.
REGIONAL_TYPES = (
    'APPLICATION_LOAD_BALANCER', 'API_GATEWAY', 'APPSYNC',
    'COGNITO_USER_POOL', 'APP_RUNNER_SERVICE',
    'VERIFIED_ACCESS_INSTANCE', 'AMPLIFY',
)
MAX_ASSOCIATIONS_PER_TYPE = 10000
CLOUDFRONT_PAGES = 100
CLOUDFRONT_PAGE_SIZE = '100'
DENIED = frozenset(('AccessDeniedException', 'AccessDenied',
                    'UnauthorizedOperation', 'WAFInvalidPermissionException'))


def _valid_arn(arn):
    return isinstance(arn, str) and arn.startswith('arn:') and len(arn.split(':', 5)) == 6


def _issue(facade, operation, error=None):
    if isinstance(error, ClientError):
        code = error.response.get('Error', {}).get('Code', '')
        reason = 'Denied' if code in DENIED else 'Error'
    else:
        reason = 'Error'
    facade.issue('partial', operation + reason)


async def discover_associations(facade, waf_client, region, scope, web_acl_arn):
    """Return confirmed resource associations and a scoped completeness state."""
    if scope == 'REGIONAL':
        resources, unknown_types = await _regional(
            facade, waf_client, web_acl_arn)
        checked_types = list(REGIONAL_TYPES)
    elif scope == 'CLOUDFRONT' and region == 'us-east-1':
        resources, unknown_types = await _cloudfront(facade, web_acl_arn)
        checked_types = ['CLOUDFRONT']
    else:
        facade.issue('partial', 'UnsupportedAssociationScope')
        resources, unknown_types, checked_types = [], [scope], [scope]
    complete = not unknown_types
    return {
        'association_status': (
            'associated' if resources else
            'unused_candidate' if complete else 'unknown'),
        'association_scope_complete': complete,
        'associated_resources': resources,
        'associated_resource_count': len(resources),
        'checked_resource_types': checked_types,
        'unknown_resource_types': unknown_types,
    }


async def _regional(facade, client, web_acl_arn):
    resources, unknown = [], []
    for kind in REGIONAL_TYPES:
        try:
            response = await run_concurrently(
                lambda kind=kind: client.list_resources_for_web_acl(
                    WebACLArn=web_acl_arn, ResourceType=kind))
        except Exception as error:
            _issue(facade, 'ListResources' + kind, error)
            unknown.append(kind)
            continue
        arns = response.get('ResourceArns') if isinstance(response, dict) else None
        if not isinstance(arns, list):
            facade.issue('partial', 'MalformedAssociations' + kind)
            unknown.append(kind)
            continue
        if len(arns) > MAX_ASSOCIATIONS_PER_TYPE:
            facade.issue('partial', 'AssociationLimit' + kind)
            unknown.append(kind)
        seen = set()
        for arn in arns[:MAX_ASSOCIATIONS_PER_TYPE]:
            if not _valid_arn(arn) or arn in seen:
                facade.issue('partial', 'InvalidAssociation' + kind)
                if kind not in unknown:
                    unknown.append(kind)
                continue
            seen.add(arn)
            resources.append({'resource_type': kind, 'resource_arn': arn})
    return resources, unknown


async def _cloudfront(facade, web_acl_arn):
    client = AWSFacadeUtils.get_client('cloudfront', facade.session, 'us-east-1')
    if client is None:
        facade.issue('partial', 'CloudFrontClientUnavailable')
        return [], ['CLOUDFRONT']
    resources, seen, tokens = [], set(), set()
    marker = None
    for _ in range(CLOUDFRONT_PAGES):
        params = {'WebACLId': web_acl_arn, 'MaxItems': CLOUDFRONT_PAGE_SIZE}
        if marker is not None:
            params['Marker'] = marker
        try:
            response = await run_concurrently(
                lambda params=params: client.list_distributions_by_web_acl_id(
                    **params))
        except Exception as error:
            _issue(facade, 'ListCloudFrontDistributions', error)
            return resources, ['CLOUDFRONT']
        listing = response.get('DistributionList') if isinstance(response, dict) else None
        if not isinstance(listing, dict):
            facade.issue('partial', 'MalformedCloudFrontDistributionList')
            return resources, ['CLOUDFRONT']
        quantity = listing.get('Quantity')
        truncated = listing.get('IsTruncated')
        items = listing.get('Items', [])
        if (not isinstance(quantity, int) or isinstance(quantity, bool)
                or quantity < 0 or not isinstance(truncated, bool)
                or not isinstance(items, list) or len(items) > 100
                or (quantity > 0 and not items)):
            facade.issue('partial', 'MalformedCloudFrontDistributionPage')
            return resources, ['CLOUDFRONT']
        for row in items:
            if not isinstance(row, dict):
                facade.issue('partial', 'MalformedCloudFrontDistribution')
                return resources, ['CLOUDFRONT']
            arn, identifier = row.get('ARN'), row.get('Id')
            parts = arn.split(':', 5) if _valid_arn(arn) else []
            if (len(parts) != 6 or parts[2] != 'cloudfront'
                    or parts[4] != facade.owner_id
                    or not parts[5].startswith('distribution/')
                    or parts[5].split('/')[-1] != identifier
                    or not isinstance(identifier, str) or not identifier
                    or (row.get('WebACLId') not in (None, web_acl_arn))
                    or arn in seen):
                facade.issue('partial', 'InvalidCloudFrontDistribution')
                return resources, ['CLOUDFRONT']
            seen.add(arn)
            resources.append({
                'resource_type': 'CLOUDFRONT',
                'resource_arn': arn,
                'distribution_id': identifier,
                'domain_name': row.get('DomainName'),
                'distribution_status': row.get('Status'),
            })
        if not truncated:
            return resources, []
        following = listing.get('NextMarker')
        if (not isinstance(following, str) or not following
                or len(following) > 4096 or following in tokens):
            facade.issue('partial', 'InvalidCloudFrontPagination')
            return resources, ['CLOUDFRONT']
        tokens.add(following)
        marker = following
    facade.issue('partial', 'CloudFrontPageLimit')
    return resources, ['CLOUDFRONT']
