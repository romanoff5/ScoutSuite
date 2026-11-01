"""Conservative, read-only S3 bucket exposure evidence.

These fields describe *bucket-level observed vectors*, not a global proof
of public inaccessibility (access points and object ACLs require other APIs).
"""
from ScoutSuite.core.run_context import get_current_run_context


PUBLIC_ACCESS_KEYS = (
    'BlockPublicAcls', 'IgnorePublicAcls',
    'BlockPublicPolicy', 'RestrictPublicBuckets'
)


def combine_public_access_blocks(account, bucket):
    """Effective most-restrictive S3 BPA, retaining unknown information.

    BlockPublicAcls/BlockPublicPolicy are preventative; do not mistake them
    for retroactive suppression of preexisting ACLs/policies.
    """
    result = {}
    for name in PUBLIC_ACCESS_KEYS:
        a = account.get(name) if isinstance(account, dict) else None
        b = bucket.get(name) if isinstance(bucket, dict) else None
        if a is True or b is True:
            result[name] = True
        elif a is False and b is False:
            result[name] = False
        else:
            result[name] = None
    return result


def _has_public_acl(bucket):
    if bucket.get('acl_collection_status') != 'success':
        return None
    grants = bucket.get('grantees')
    if not isinstance(grants, dict):
        return None
    for entry in grants.values():
        if not isinstance(entry, dict):
            return None
        uri = entry.get('URI', '')
        if uri not in (
            'http://acs.amazonaws.com/groups/global/AllUsers',
            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
        ):
            continue
        permissions = entry.get('permissions')
        if not isinstance(permissions, dict):
            return None
        if any(value is True for value in permissions.values()):
            return True
    return False


def classify_bucket_exposure(bucket):
    """Return (status, reasons) without treating incomplete reads as safe."""
    if not isinstance(bucket, dict):
        return 'unknown', ['BucketDataUnknown']
    pab = bucket.get('public_access_block_configuration') or {}
    policy_public = bucket.get('policy_is_public')
    restricted = pab.get('RestrictPublicBuckets')
    ignore_acls = pab.get('IgnorePublicAcls')
    owner_enforced = bucket.get('object_ownership') == 'BucketOwnerEnforced'
    reasons = []
    unknown = False

    if policy_public is True:
        if restricted is False:
            reasons.append('PublicBucketPolicy')
        elif restricted is not True:
            unknown = True
    elif policy_public is not False:
        unknown = True

    public_acl = _has_public_acl(bucket)
    if not owner_enforced:
        if public_acl is True:
            if ignore_acls is False:
                reasons.append('EffectivePublicBucketACL')
            elif ignore_acls is not True:
                unknown = True
        elif public_acl is None:
            unknown = True

    if reasons:
        return 'exposed', reasons
    if unknown:
        return 'unknown', ['ExposureEvidenceIncomplete']
    return 'no_bucket_level_exposure_detected', []


def annotate_bucket_exposure(bucket):
    status, reasons = classify_bucket_exposure(bucket)
    bucket['public_exposure_status'] = status
    bucket['public_exposure_reasons'] = reasons
    if status == 'unknown':
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue('partial', 's3', 'ExposureEvidenceUnknown')
