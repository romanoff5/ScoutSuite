"""Additive evidence classification for explicitly versioned security rules.

Does not rewrite legacy findings or infer compliance from missing resources.
Every supported policy has a narrow named contract and remains read-only.
"""
import json
from functools import lru_cache
from pathlib import Path

from ScoutSuite.core.run_context import get_current_run_context


def _walk_resources(current, parts, prefix=()):
    """Yield (stable report path, resource dict) for a rule's existing path."""
    if not parts:
        yield '.'.join(prefix), current
        return
    if not isinstance(current, dict):
        return
    key, *remaining = parts
    if key == 'id':
        for resource_id, child in current.items():
            yield from _walk_resources(child, remaining, prefix + (str(resource_id),))
    elif key in current:
        yield from _walk_resources(current[key], remaining, prefix + (key,))


def classify_kms_automatic_rotation(key):
    """Classify eligibility before treating rotation_enabled as evidence.

    Return one of secure, insecure, unknown or not_applicable.
    """
    if not isinstance(key, dict):
        return 'unknown'
    manager = key.get('key_manager')
    enabled = key.get('key_enabled')
    if manager not in ('AWS', 'CUSTOMER') or enabled not in (True, False):
        return 'unknown'
    if manager == 'AWS' or enabled is False:
        return 'not_applicable'

    # For a customer-managed key, missing attributes are not proof of
    # ineligibility. Explicit nonmatching attributes are not applicable.
    expected = {'origin': 'AWS_KMS', 'key_spec': 'SYMMETRIC_DEFAULT',
                'key_usage': 'ENCRYPT_DECRYPT'}
    if any(key.get(field) is None for field in expected):
        return 'unknown'
    if any(key[field] != value for field, value in expected.items()):
        return 'not_applicable'

    status = key.get('rotation_status')
    rotation = key.get('rotation_enabled')
    if status == 'enabled' and rotation is True:
        return 'secure'
    if status == 'disabled' and rotation is False:
        return 'insecure'
    # Conflict, denied, malformed response, missing status or false-positive
    # not_supported on an otherwise eligible key: cannot assert compliance.
    return 'unknown'


def classify_cloudtrail_data_events(trail):
    """Unknown selectors are not evidence that CloudTrail data logging is on."""
    if not isinstance(trail, dict):
        return 'unknown'
    if trail.get('selector_collection_status') == 'failed':
        return 'unknown'
    enabled = trail.get('DataEventsEnabled')
    if enabled is True:
        return 'secure'
    if enabled is False:
        return 'insecure'
    return 'unknown'


def classify_cloudtrail_data_coverage(trail):
    """Avoid false clean when wildcard selector evidence was unavailable."""
    if not isinstance(trail, dict):
        return 'unknown'
    if trail.get('selector_collection_status') == 'failed':
        return 'unknown'
    coverage = trail.get('wildcard_data_logging')
    if coverage is True:
        return 'secure'
    if coverage is False:
        return 'insecure'
    return 'unknown'


@lru_cache(maxsize=1)
def _rds_ca_catalog():
    path = (Path(__file__).resolve().parents[1] / 'providers/aws/rules/catalogs'
            / 'rds-ca-2026-11.json')
    catalog = json.loads(path.read_text(encoding='utf-8'))
    if catalog.get('schema_version') != 1 or not catalog.get('catalog_version'):
        raise ValueError('Unsupported RDS CA reference catalog')
    current = catalog.get('current_ca', [])
    deprecated = catalog.get('deprecated_ca', [])
    if (not current or not deprecated or set(current) & set(deprecated)
            or len(set(current)) != len(current)
            or len(set(deprecated)) != len(deprecated)):
        raise ValueError('Invalid RDS CA reference catalog')
    return frozenset(current), frozenset(deprecated)


def classify_rds_ca_lifecycle(instance):
    """Current, deprecated or unknown CA; never invent validity for new names."""
    if not isinstance(instance, dict):
        return 'unknown'
    identifier = instance.get('CACertificateIdentifier')
    if not isinstance(identifier, str) or not identifier:
        return 'unknown'
    current, deprecated = _rds_ca_catalog()
    if identifier in current:
        return 'secure'
    if identifier in deprecated:
        return 'insecure'
    return 'unknown'


@lru_cache(maxsize=1)
def _alb_tls_catalog():
    path = (Path(__file__).resolve().parents[1] / 'providers/aws/rules/catalogs'
            / 'alb-tls-2026-11.json')
    catalog = json.loads(path.read_text(encoding='utf-8'))
    if catalog.get('schema_version') != 1 or not catalog.get('catalog_version'):
        raise ValueError('Unsupported ALB TLS protocol catalog')
    secure = catalog.get('allows_tls_1_2_or_newer_only', [])
    legacy = catalog.get('allows_tls_before_1_2', [])
    if (not secure or not legacy or set(secure) & set(legacy)
            or len(set(secure)) != len(secure)
            or len(set(legacy)) != len(legacy)):
        raise ValueError('Invalid ALB TLS protocol catalog')
    return frozenset(secure), frozenset(legacy)


def classify_alb_listener_tls(listener):
    """Evaluate protocol floor only, not cipher strength or FIPS compliance."""
    if not isinstance(listener, dict):
        return 'unknown'
    protocol = listener.get('Protocol')
    if protocol in ('HTTP', 'TCP', 'UDP', 'TCP_UDP'):
        return 'not_applicable'
    if protocol not in ('HTTPS', 'TLS'):
        return 'unknown'
    policy = listener.get('SslPolicy')
    if not isinstance(policy, str) or not policy:
        return 'unknown'
    secure, legacy = _alb_tls_catalog()
    if policy in secure:
        return 'secure'
    if policy in legacy:
        return 'insecure'
    return 'unknown'


def classify_s3_encryption(bucket):
    """Check observed new-write encryption, not all historical S3 objects."""
    if not isinstance(bucket, dict):
        return 'unknown'
    evidence = bucket.get('encryption_evidence')
    algorithm = bucket.get('default_encryption_algorithm')
    enabled = bucket.get('default_encryption_enabled')
    if (enabled is True and evidence in ('api', 'aws_baseline')
            and algorithm in ('AES256', 'aws:kms', 'aws:kms:dsse')):
        return 'secure'
    # A positively observed disabled configuration could be insecure, but
    # absence of an explicit configuration is SSE-S3 since January 2023.
    if enabled is False and evidence == 'api':
        return 'insecure'
    return 'unknown'


def classify_s3_secure_transport(bucket):
    if not isinstance(bucket, dict):
        return 'unknown'
    status = bucket.get('secure_transport_enabled')
    if status is True:
        return 'secure'
    if status is False:
        return 'insecure'
    return 'unknown'


def classify_s3_bucket_exposure(bucket):
    if not isinstance(bucket, dict):
        return 'unknown'
    state = bucket.get('public_exposure_status')
    if state == 'exposed':
        return 'insecure'
    if state == 'no_bucket_level_exposure_detected':
        return 'secure'
    return 'unknown'


CLASSIFIERS = {
    'kms-automatic-rotation-v1': classify_kms_automatic_rotation,
    'cloudtrail-data-events-v1': classify_cloudtrail_data_events,
    'cloudtrail-data-coverage-v1': classify_cloudtrail_data_coverage,
    'rds-ca-lifecycle-v1': classify_rds_ca_lifecycle,
    'alb-listener-tls-v1': classify_alb_listener_tls,
    's3-new-write-encryption-v1': classify_s3_encryption,
    's3-secure-transport-v1': classify_s3_secure_transport,
    's3-bucket-level-exposure-v1': classify_s3_bucket_exposure,
}


def evaluate_rule_evidence(rule, services):
    """Evaluate optional status metadata without changing flagged item IDs."""
    policy = getattr(rule, 'evidence_policy', None)
    if policy is None:
        return None
    if policy not in CLASSIFIERS:
        raise ValueError('Unsupported rule evidence policy: ' + str(policy))

    counts = {key: 0 for key in ('secure', 'insecure', 'unknown', 'not_applicable')}
    unknown_paths = []
    parts = rule.path.split('.')
    # SSL policy is a scalar; classification needs the parent listener
    # Protocol to distinguish HTTP/not-applicable from HTTPS/unknown.
    if policy == 'alb-listener-tls-v1':
        if not parts or parts[-1] != 'SslPolicy':
            raise ValueError('Unexpected ALB security-policy rule path')
        parts = parts[:-1]
    for path, resource in _walk_resources(services, parts):
        status = CLASSIFIERS[policy](resource)
        counts[status] += 1
        if status == 'unknown':
            unknown_paths.append(path)

    total = sum(counts.values())
    if counts['unknown']:
        status = 'incomplete'
        context = get_current_run_context()
        if context is not None:
            context.record_collection_issue('partial', rule.path.split('.')[0],
                                            'RuleEvidenceUnknown')
    elif not total:
        status = 'not_applicable'  # No applicable resources, not a compliance pass.
    elif counts['secure'] + counts['insecure'] == 0:
        status = 'not_applicable'
    else:
        status = 'evaluated'

    return {
        'version': 1,
        'policy': policy,
        'assessment_status': status,
        'counts': counts,
        'unknown_resources': unknown_paths,
        'evaluated_resources': counts['secure'] + counts['insecure'],
        'compliance_verified': False,
    }
