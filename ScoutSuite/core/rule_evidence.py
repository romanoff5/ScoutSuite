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



def classify_imds_v2(instance):
    """Classify effective per-instance metadata settings from DescribeInstances."""
    if not isinstance(instance, dict):
        return 'unknown'
    options = instance.get('metadata_options')
    if not isinstance(options, dict) or not options:
        return 'unknown'
    if options.get('State') not in (None, 'applied'):
        return 'unknown'
    endpoint = options.get('HttpEndpoint')
    if endpoint == 'disabled':
        return 'not_applicable'
    if endpoint not in (None, 'enabled'):
        return 'unknown'
    tokens = options.get('HttpTokens')
    if tokens == 'required':
        return 'secure'
    if tokens == 'optional':
        return 'insecure'
    return 'unknown'


@lru_cache(maxsize=1)
def _lambda_runtime_catalog():
    path = (Path(__file__).resolve().parents[1] / 'providers/aws/rules/catalogs'
            / 'lambda-runtimes-2026-11.json')
    data = json.loads(path.read_text(encoding='utf-8'))
    dates = data.get('deprecation_dates')
    if data.get('schema_version') != 1 or not data.get('catalog_version') or not isinstance(dates, dict):
        raise ValueError('Invalid Lambda runtime catalog')
    from datetime import date
    return {runtime: date.fromisoformat(value) for runtime, value in dates.items()}


def classify_lambda_runtime(function, as_of=None):
    """ZIP managed runtimes only. Image packages have no inspectable runtime."""
    if not isinstance(function, dict):
        return 'unknown'
    if function.get('package_type') == 'Image':
        return 'not_applicable'
    if function.get('package_type') not in (None, 'Zip'):
        return 'unknown'
    runtime = function.get('runtime')
    if not isinstance(runtime, str) or not runtime:
        return 'unknown'
    from datetime import datetime, timezone
    if as_of is None:
        as_of = datetime.now(timezone.utc).date()
    elif isinstance(as_of, datetime):
        as_of = as_of.date()
    deprecation = _lambda_runtime_catalog().get(runtime)
    if deprecation is None:
        return 'unknown'
    return 'insecure' if as_of >= deprecation else 'secure'


@lru_cache(maxsize=1)
def _classic_elb_catalog():
    path = (Path(__file__).resolve().parents[1] / 'providers/aws/rules/catalogs'
            / 'classic-elb-tls-2026-11.json')
    catalog = json.loads(path.read_text(encoding='utf-8'))
    secure = catalog.get('allows_tls_1_2_or_newer_only', [])
    old = catalog.get('allows_tls_before_1_2', [])
    if (catalog.get('schema_version') != 1 or not secure or not old
            or set(secure) & set(old)):
        raise ValueError('Invalid Classic ELB TLS catalog')
    return frozenset(secure), frozenset(old)


def classify_classic_elb_policy(policy):
    """Prefer real SSL policy attributes; never reuse ALB policy allowlists."""
    if not isinstance(policy, dict):
        return 'unknown'
    kind = policy.get('PolicyTypeName')
    if kind is not None and kind != 'SSLNegotiationPolicyType':
        return 'not_applicable'
    attrs = policy.get('PolicyAttributeDescriptions')
    if not isinstance(attrs, list):
        return 'unknown'
    attributes = {}
    for item in attrs:
        if isinstance(item, dict) and isinstance(item.get('AttributeName'), str):
            attributes[item['AttributeName']] = item.get('AttributeValue')
    reference = attributes.get('Reference-Security-Policy')
    # Use the policy's own name only for the documented predefined policies.
    name = reference or policy.get('PolicyName') or policy.get('name')
    secure, old = _classic_elb_catalog()
    if name in secure:
        return 'secure'
    if name in old:
        return 'insecure'
    if reference:
        return 'unknown'
    legacy = ('Protocol-SSLv3', 'Protocol-TLSv1', 'Protocol-TLSv1.1')
    if any(attributes.get(protocol) == 'true' for protocol in legacy):
        return 'insecure'
    if (all(attributes.get(protocol) == 'false' for protocol in legacy)
            and attributes.get('Protocol-TLSv1.2') == 'true'):
        return 'secure'
    return 'unknown'


def classify_access_analyzer(analyzer):
    """Current account-visible analyzer state; CREATING or unknown is incomplete."""
    if not isinstance(analyzer, dict):
        return 'unknown'
    state = analyzer.get('status')
    if state == 'ACTIVE':
        return 'secure'
    if state in ('FAILED', 'DISABLED'):
        return 'insecure'
    return 'unknown'


def classify_securityhub_standard(standard):
    """Only READY is healthy; FAILED/INCOMPLETE are confirmed unhealthy."""
    if not isinstance(standard, dict):
        return 'unknown'
    status = standard.get('status')
    if status == 'READY':
        return 'secure'
    if status in ('FAILED', 'INCOMPLETE'):
        return 'insecure'
    return 'unknown'


def classify_ecr_registry_scanning(registry):
    if not isinstance(registry, dict):
        return 'unknown'
    if registry.get('scan_type') == 'ENHANCED':
        return 'secure'
    if registry.get('scan_type') == 'BASIC':
        return 'insecure'
    return 'unknown'


def classify_ecs_task_privilege(task):
    if not isinstance(task, dict):
        return 'unknown'
    if task.get('has_privileged_container') is True:
        return 'insecure'
    if task.get('privilege_observation_complete') is not True:
        return 'unknown'
    if task.get('has_privileged_container') is False:
        return 'secure'
    return 'unknown'


def classify_eks_control_plane_audit(cluster):
    if not isinstance(cluster, dict):
        return 'unknown'
    status = cluster.get('audit_logging_enabled')
    if status is True:
        return 'secure'
    if status is False:
        return 'insecure'
    return 'unknown'


def classify_wafv2_association(web_acl):
    """Unknown API/resource coverage must never imply an unused Web ACL."""
    if not isinstance(web_acl, dict):
        return 'unknown'
    status = web_acl.get('association_status')
    resources = web_acl.get('associated_resources')
    if not isinstance(resources, list):
        return 'unknown'
    if status == 'associated' and resources:
        return 'secure'
    if (status == 'unused_candidate' and not resources
            and web_acl.get('association_scope_complete') is True):
        return 'insecure'
    return 'unknown'


def classify_wafv2_empty_allow(web_acl):
    """A verified empty, non-FMS Web ACL with ALLOW default cannot filter."""
    if not isinstance(web_acl, dict):
        return 'unknown'
    action = web_acl.get('default_action')
    count = web_acl.get('rule_count')
    managed = web_acl.get('managed_by_firewall_manager')
    before = web_acl.get('firewall_manager_pre_rules_count')
    after = web_acl.get('firewall_manager_post_rules_count')
    if action not in ('ALLOW', 'BLOCK') or not isinstance(count, int) or count < 0:
        return 'unknown'
    if managed is True or (before not in (None, 0)) or (after not in (None, 0)):
        return 'unknown'
    if managed is not False:
        return 'unknown'
    if action == 'ALLOW' and count == 0:
        return 'insecure'
    return 'secure'


def classify_eks_api_endpoint(cluster):
    """Public endpoint exposure requires explicit CIDR evidence."""
    if not isinstance(cluster, dict):
        return 'unknown'
    public = cluster.get('public_endpoint_access')
    if public is False:
        return 'secure'
    if public is not True:
        return 'unknown'
    cidrs = cluster.get('public_access_cidrs')
    if not isinstance(cidrs, list) or not cidrs or any(
            not isinstance(value, str) for value in cidrs):
        return 'unknown'
    if any(value in ('0.0.0.0/0', '::/0') for value in cidrs):
        return 'insecure'
    return 'secure'


def classify_ecs_container_insights(cluster):
    """Only explicit ECS Container Insights settings constitute evidence."""
    if not isinstance(cluster, dict):
        return 'unknown'
    mode = cluster.get('container_insights')
    if mode in ('enabled', 'enhanced'):
        return 'secure'
    if mode == 'disabled':
        return 'insecure'
    return 'unknown'


def classify_ecr_tag_mutability(repository):
    """Only plain MUTABLE is an actionable tag-overwrite configuration warning."""
    if not isinstance(repository, dict):
        return 'unknown'
    mode = repository.get('image_tag_mutability')
    if mode == 'MUTABLE':
        return 'insecure'
    if mode == 'IMMUTABLE':
        return 'secure'
    # Mixed policies, absent data and unexpected values require review.
    return 'unknown'


def classify_guardduty_detector(detector):
    """Disabled is a confirmed finding; unknown and missing status never pass."""
    if not isinstance(detector, dict):
        return 'unknown'
    state = detector.get('status')
    if state == 'ENABLED':
        return 'secure'
    if state == 'DISABLED':
        return 'insecure'
    return 'unknown'


def classify_organizations_features(organization):
    """All-features is the prerequisite for organization policy governance."""
    if not isinstance(organization, dict):
        return 'unknown'
    value = organization.get('feature_set')
    if value == 'ALL':
        return 'secure'
    if value == 'CONSOLIDATED_BILLING':
        return 'insecure'
    return 'unknown'


def classify_organizations_scp(root):
    """Never turn missing/transitioning SCP evidence into a clean result."""
    if not isinstance(root, dict):
        return 'unknown'
    status = root.get('scp_status')
    if status == 'ENABLED':
        return 'secure'
    if status in ('DISABLED', 'NOT_ENABLED'):
        return 'insecure'
    if status == 'NOT_APPLICABLE':
        return 'not_applicable'
    return 'unknown'



def classify_inspector2_account(account):
    """An incomplete or transitional Inspector2 state is never a verified pass."""
    if not isinstance(account, dict):
        return 'unknown'
    state = account.get('status')
    if state == 'ENABLED':
        return 'secure'
    if state in ('DISABLED', 'SUSPENDED'):
        return 'insecure'
    return 'unknown'


def classify_inspector2_coverage(resource):
    """Only confirmed INACTIVE scan records are flagged."""
    if not isinstance(resource, dict):
        return 'unknown'
    status = resource.get('scan_status')
    if status == 'ACTIVE':
        return 'secure'
    if status == 'INACTIVE':
        return 'insecure'
    return 'unknown'


def classify_inspector2_member(member):
    """Member account visibility is not equivalent to healthy account state."""
    if not isinstance(member, dict):
        return 'unknown'
    status = member.get('account_status')
    if status == 'ENABLED':
        return 'secure'
    if status in ('DISABLED', 'SUSPENDED'):
        return 'insecure'
    return 'unknown'


CLASSIFIERS = {
    'inspector2-member-state-v1': classify_inspector2_member,
    'inspector2-account-state-v1': classify_inspector2_account,
    # Account and individual scan enrollment share the same AWS state model.
    # Reuse one classifier instead of duplicating semantics.
    'inspector2-scan-type-state-v1': classify_inspector2_account,
    'inspector2-coverage-state-v1': classify_inspector2_coverage,
    'organizations-features-v1': classify_organizations_features,
    'organizations-root-scp-v1': classify_organizations_scp,
    'guardduty-detector-state-v1': classify_guardduty_detector,
    'ecr-tag-mutability-v1': classify_ecr_tag_mutability,
    'ecs-container-insights-v1': classify_ecs_container_insights,
    'eks-api-endpoint-v1': classify_eks_api_endpoint,
    'ecr-registry-scanning-v1': classify_ecr_registry_scanning,
    'ecs-task-privileged-v1': classify_ecs_task_privilege,
    'eks-control-plane-audit-v1': classify_eks_control_plane_audit,
    'wafv2-empty-allow-v1': classify_wafv2_empty_allow,
    'wafv2-association-v1': classify_wafv2_association,
    'securityhub-standard-state-v1': classify_securityhub_standard,
    'access-analyzer-state-v1': classify_access_analyzer,
    'ec2-imds-v2-v1': classify_imds_v2,
    'lambda-managed-runtime-v1': classify_lambda_runtime,
    'classic-elb-tls-v1': classify_classic_elb_policy,
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
    if policy in ('alb-listener-tls-v1', 'ec2-imds-v2-v1',
                  'lambda-managed-runtime-v1', 'classic-elb-tls-v1'):
        expected_field = {
            'alb-listener-tls-v1': 'SslPolicy',
            'ec2-imds-v2-v1': 'imds_v2_status',
            'lambda-managed-runtime-v1': 'runtime_lifecycle_status',
            'classic-elb-tls-v1': 'reference_security_policy',
        }[policy]
        if not parts or parts[-1] != expected_field:
            raise ValueError('Unexpected rule evidence path')
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
