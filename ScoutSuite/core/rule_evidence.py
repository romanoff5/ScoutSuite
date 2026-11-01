"""Additive evidence classification for explicitly versioned security rules.

Does not rewrite legacy findings or infer compliance from missing resources.
Every supported policy has a narrow named contract and remains read-only.
"""
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


CLASSIFIERS = {
    'kms-automatic-rotation-v1': classify_kms_automatic_rotation,
    'cloudtrail-data-events-v1': classify_cloudtrail_data_events,
    'cloudtrail-data-coverage-v1': classify_cloudtrail_data_coverage,
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
    for path, resource in _walk_resources(services, rule.path.split('.')):
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
