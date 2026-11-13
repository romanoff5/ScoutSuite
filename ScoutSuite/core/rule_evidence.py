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


def classify_rds_deletion_protection(instance):
    """Only standalone DB instances; cluster members need DBCluster evidence."""
    if not isinstance(instance, dict):
        return 'unknown'
    membership = instance.get('is_cluster_member')
    if membership is True:
        return 'not_applicable'
    if membership is not False:
        return 'unknown'
    value = instance.get('DeletionProtection')
    if value is True:
        return 'secure'
    if value is False:
        return 'insecure'
    return 'unknown'


def classify_rds_cluster_deletion_protection(cluster):
    """Aurora and Multi-AZ DB clusters, counted once per DBClusterIdentifier."""
    if not isinstance(cluster, dict):
        return 'unknown'
    value = cluster.get('DeletionProtection')
    if value is True:
        return 'secure'
    if value is False:
        return 'insecure'
    return 'unknown'


def classify_efs_encryption(filesystem):
    """AWS EFS DescribeFileSystems Encrypted state; missing is not clean."""
    if not isinstance(filesystem, dict):
        return 'unknown'
    value = filesystem.get('Encrypted')
    if value is True:
        return 'secure'
    if value is False:
        return 'insecure'
    return 'unknown'


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


def classify_s3_block_public_access(bucket):
    """Evaluate effective S3 BPA across the four flags, never infer no public access."""
    if not isinstance(bucket, dict):
        return 'unknown'
    state = bucket.get('effective_bpa_review')
    if state == 'complete':
        return 'secure'
    if state == 'missing':
        return 'insecure'
    return 'unknown'


def classify_guardduty_region(region):
    """No detector in a fully enumerated Region; denials stay UNKNOWN."""
    if not isinstance(region, dict) or region.get('detector_census_status') != 'complete':
        return 'unknown'
    status = region.get('guardduty_status')
    if status == 'not_enabled':
        return 'insecure'
    if status in ('enabled', 'detector_disabled'):
        return 'secure'  # Detector exists; its state has a separate rule.
    return 'unknown'


def _secret_field(secret, field, verdicts):
    if not isinstance(secret, dict):
        return 'unknown'
    return verdicts.get(secret.get(field), 'unknown')


def classify_secret_rotation(secret):
    """Rotation of a live secret; undescribed secrets stay UNKNOWN."""
    return _secret_field(secret, 'rotation_status', {
        'enabled': 'secure', 'disabled': 'insecure', 'scheduled_for_deletion': 'not_applicable'})


def classify_secret_unused(secret):
    """No retrieval within the threshold, or never retrieved since creation beyond it."""
    return _secret_field(secret, 'unused_status', {
        'unused': 'insecure', 'in_use': 'secure', 'recently_created': 'secure',
        'scheduled_for_deletion': 'not_applicable'})


def classify_secret_policy_public(secret):
    """Allow to '*' (or NotPrincipal) without a caller-binding condition; unreadable policy is UNKNOWN."""
    return _secret_field(secret, 'policy_exposure', {
        'public': 'insecure', 'cross_account': 'secure', 'conditional': 'secure',
        'private': 'secure', 'none': 'secure'})


def classify_secret_policy_cross_account(secret):
    """Named principals outside the owning account; public policies have their own rule."""
    return _secret_field(secret, 'policy_exposure', {
        'cross_account': 'insecure', 'public': 'not_applicable', 'conditional': 'secure',
        'private': 'secure', 'none': 'secure'})


def _secret_detection_status(resource, field):
    if not isinstance(resource, dict):
        return 'unknown'
    return {'detected': 'insecure', 'none': 'secure', 'no_user_data': 'not_applicable',
            'no_variables': 'not_applicable'}.get(resource.get(field), 'unknown')


def classify_ec2_user_data_secrets(instance):
    """Masked detections in readable user data; unreadable/undecodable stays UNKNOWN."""
    return _secret_detection_status(instance, 'user_data_secret_status')


def classify_lambda_environment_secrets(function):
    return _secret_detection_status(function, 'env_secret_status')


def classify_ecs_environment_secrets(task):
    return _secret_detection_status(task, 'environment_secret_status')


def classify_alb_waf_protection(lb):
    """Internet-facing ALB reachable from 0.0.0.0/0 or ::/0 with no AWS WAF web ACL."""
    if not isinstance(lb, dict):
        return 'unknown'
    return {'open_without_waf': 'insecure', 'aws_waf': 'secure', 'external_waf_likely': 'secure',
            'restricted_origin': 'secure', 'not_internet_facing': 'not_applicable',
            'not_applicable': 'not_applicable'}.get(lb.get('waf_protection_status'), 'unknown')


def classify_accessanalyzer_region(region):
    """No visible analyzer in a fully enumerated Region; denials stay UNKNOWN."""
    if not isinstance(region, dict) or region.get('analyzer_census_status') != 'complete':
        return 'unknown'
    status = region.get('analyzer_status')
    if status == 'not_configured':
        return 'insecure'
    if status in ('active', 'inactive_only'):
        return 'secure'  # Analyzer exists; its state has a separate rule.
    return 'unknown'


def classify_securityhub_subscription(region):
    """Known subscription or explicit AWS not-subscribed response, not a permissions guess."""
    if not isinstance(region, dict):
        return 'unknown'
    status = region.get('hub_subscription_status')
    if status == 'enabled':
        return 'secure'
    if status == 'not_subscribed':
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



def classify_cloudwatch_security_metric_alerting(region):
    """No false PASS for incomplete inventories or unverified filter-alarm links."""
    if not isinstance(region, dict):
        return 'unknown'
    if (region.get('metric_filters_collection_status') != 'complete'
            or region.get('metric_alarms_collection_status') != 'complete'):
        return 'unknown'
    state = region.get('security_metric_alerting_status')
    if state in ('missing', 'unlinked_security_filters'):
        return 'insecure'
    # Alternative filter syntax, metric math, and apparent linked alarms all
    # require manual end-to-end verification; none is a verified PASS.
    return 'unknown'


def classify_acm_expiring_cert(cert):
    """In-use certificate expiry evidence: missing NotAfter is UNKNOWN."""
    if not isinstance(cert, dict):
        return 'unknown'
    usage = cert.get('InUseBy')
    if not isinstance(usage, list):
        return 'unknown'
    if not usage:
        return 'not_applicable'
    return {'expiring_soon': 'insecure', 'expired': 'insecure',
            'valid': 'secure'}.get(cert.get('expiry_status'), 'unknown')


def classify_acm_imported_renewal(cert):
    """Imported ACM certificates are not automatically renewed by ACM."""
    if not isinstance(cert, dict):
        return 'unknown'
    return {'review_due': 'insecure', 'not_due': 'secure',
            'not_applicable': 'not_applicable'}.get(
                cert.get('renewal_review_status'), 'unknown')


def classify_ec2_direct_public_https(instance):
    """Direct inbound HTTPS is an exposure candidate, not verified reachability."""
    if not isinstance(instance, dict):
        return 'unknown'
    return {'exposed': 'insecure', 'not_exposed': 'secure',
            'not_applicable': 'not_applicable'}.get(
                instance.get('public_https_status'), 'unknown')


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


def classify_cloudtrail_root_write_event(event):
    if not isinstance(event,dict):
        return 'unknown'
    if event.get('root_identity_verified') is True and event.get('management_write_verified') is True:
        return 'insecure'  # Historical event observed, not proof of ongoing misuse.
    return 'unknown'


def classify_rds_proxy_tls(proxy):
    if not isinstance(proxy,dict):
        return 'unknown'
    return {'disabled':'insecure','enforced':'secure'}.get(
        proxy.get('tls_status'),'unknown')


def classify_service_role_trust(role):
    if not isinstance(role, dict):
        return 'unknown'
    return {'missing': 'insecure', 'scoped': 'secure',
            'not_applicable': 'not_applicable'}.get(
                role.get('service_trust_scope_status'), 'unknown')


def classify_persistent_iam_key(user):
    if not isinstance(user, dict):
        return 'unknown'
    return {'active': 'insecure', 'none': 'secure'}.get(
        user.get('persistent_key_review_status'), 'unknown')


def classify_ecs_writable_root(task):
    if not isinstance(task, dict):
        return 'unknown'
    status = task.get('writable_root_filesystem_status')
    if status == 'not_applicable':
        return 'not_applicable'
    if task.get('writable_root_filesystem_observation_complete') is not True:
        return 'unknown'
    return {'writable': 'insecure', 'read_only': 'secure'}.get(status, 'unknown')


def classify_waf_explicit_rate(web_acl):
    """Only explicitly configured ACL rules; other mitigations are not assessed."""
    if not isinstance(web_acl, dict):
        return 'unknown'
    return {'present': 'secure', 'not_present': 'insecure'}.get(
        web_acl.get('explicit_rate_based_rule_status'), 'unknown')


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


def classify_backup_vault_lock(vault):
    """Only explicit Vault Lock state is evidence; absent does not imply clean."""
    if not isinstance(vault, dict):
        return 'unknown'
    state = vault.get('locked')
    if state is True:
        return 'secure'
    if state is False:
        return 'insecure'
    return 'unknown'


def classify_identitycenter_admin_assignment(assignment):
    """Warn on a confirmed AWS-managed AdministratorAccess assignment only."""
    if not isinstance(assignment, dict):
        return 'unknown'
    if assignment.get('administrator_access_managed_policy') is True:
        return 'insecure'
    if assignment.get('policy_collection_complete') is True:
        return 'not_applicable'  # Custom/inline privilege is not evaluated.
    return 'unknown'


def classify_identitycenter_admin(assignment):
    """Finding if explicitly observed; otherwise unknown on incomplete scope."""
    if not isinstance(assignment, dict):
        return 'unknown'
    if assignment.get('admin_candidate') is True:
        return 'insecure'
    if (assignment.get('policy_analysis_complete') is True
            and assignment.get('principal_resolved') is True
            and assignment.get('organization_coverage_status') == 'complete'):
        return 'secure'
    return 'unknown'


def classify_identitycenter_broad(assignment):
    if not isinstance(assignment, dict):
        return 'unknown'
    if assignment.get('broad_permissions_candidate') is True:
        return 'insecure'
    if (assignment.get('policy_analysis_complete') is True
            and assignment.get('principal_resolved') is True
            and assignment.get('organization_coverage_status') == 'complete'):
        return 'secure'
    return 'unknown'


def classify_identitycenter_cross_account(assignment):
    if not isinstance(assignment, dict):
        return 'unknown'
    if assignment.get('cross_account_admin_candidate') is True:
        return 'insecure'
    if (assignment.get('policy_analysis_complete') is True
            and assignment.get('principal_resolved') is True
            and assignment.get('organization_coverage_status') == 'complete'):
        return 'secure'
    return 'unknown'



def classify_ssm_unmanaged(node):
    if not isinstance(node, dict):
        return 'unknown'
    if node.get('unmanaged_running_ec2') is True and node.get('ssm_managed') is False:
        return 'insecure'
    if node.get('ssm_managed') is True:
        return 'secure'  # SSM registration observed, not proof of patch health.
    if node.get('ec2_state') in ('stopped', 'stopping', 'terminated', 'shutting-down'):
        return 'not_applicable'
    return 'unknown'


def classify_ssm_offline(node):
    if not isinstance(node, dict):
        return 'unknown'
    if node.get('ssm_managed') is not True:
        return 'not_applicable' if node.get('ssm_managed') is False else 'unknown'
    if node.get('ping_status') == 'ConnectionLost':
        return 'insecure'
    if node.get('ping_status') == 'Online' and node.get('agent_ping_fresh') is True:
        return 'secure'
    return 'unknown'


def classify_ssm_scan_unverified(node):
    if not isinstance(node, dict):
        return 'unknown'
    if node.get('ssm_managed') is False:
        return 'not_applicable'
    if node.get('ssm_managed') is not True:
        return 'unknown'
    if node.get('patch_compliant_evidence') is True:
        return 'secure'
    if node.get('scan_unverified') is True:
        return 'insecure'  # Missing evidence, not proof the scan never occurred.
    return 'unknown'


def classify_ssm_security_noncompliant(node):
    if not isinstance(node, dict):
        return 'unknown'
    patch = node.get('patch_state')
    if node.get('ssm_managed') is False:
        return 'not_applicable'
    if not isinstance(patch, dict):
        return 'unknown'
    counts = (patch.get('CriticalNonCompliantCount'),
              patch.get('SecurityNonCompliantCount'))
    if any(type(count) is int and count > 0 for count in counts):
        return 'insecure'
    if node.get('patch_compliant_evidence') is True and counts == (0, 0):
        return 'secure'
    return 'unknown'


def classify_ssm_missing_patches(node):
    if not isinstance(node, dict):
        return 'unknown'
    if node.get('ssm_managed') is False:
        return 'not_applicable'
    patch = node.get('patch_state')
    if not isinstance(patch, dict):
        return 'unknown'
    fields = ('MissingCount', 'FailedCount', 'InstalledPendingRebootCount',
              'InstalledRejectedCount')
    values = [patch.get(field) for field in fields]
    if any(type(value) is int and value > 0 for value in values):
        return 'insecure'
    if (node.get('patch_compliant_evidence') is True
            and all(type(value) is int and value == 0 for value in values)):
        return 'secure'
    return 'unknown'



def classify_m10q_ec2_inspector(instance):
    """Missing from a complete Inspector listing is an evidence gap, not ineligibility."""
    if not isinstance(instance, dict):
        return 'unknown'
    evidence = instance.get('m10q_inspector')
    if not isinstance(evidence, dict):
        return 'unknown'
    state = evidence.get('state')
    if state == 'not_reported':
        return 'insecure'
    if state == 'active_observed':
        return 'secure'  # Active coverage record, not a completed scan.
    if state == 'not_applicable':
        return 'not_applicable'
    # Inactive records have their own Inspector rule. Do not double-count.
    return 'unknown'


def classify_m10q_ecr_image_scanning(repository):
    """Config and Inspector enrollment never prove a particular image was scanned."""
    if not isinstance(repository, dict):
        return 'unknown'
    if repository.get('m10q_repository_scan_gap_candidate') is True:
        return 'insecure'
    return 'unknown'


def classify_m10q_s3_backup(bucket):
    """A recovery point and past job do not prove an ongoing backup schedule."""
    if not isinstance(bucket, dict):
        return 'unknown'
    evidence = bucket.get('m10q_backup')
    if not isinstance(evidence, dict):
        return 'unknown'
    if evidence.get('state') in ('not_reported', 'partial_evidence'):
        return 'insecure'
    return 'unknown'



def classify_m10q_s3_target_reference(point):
    """A missing target is actionable only with verified own-account census."""
    if not isinstance(point, dict):
        return 'unknown'
    evidence = point.get('m10q_bucket_target')
    if not isinstance(evidence, dict):
        return 'unknown'
    status = evidence.get('status')
    if status in ('not_in_local_bucket_inventory',
                  'not_in_local_directory_bucket_inventory'):
        return 'insecure'
    if status in ('observed_local_bucket', 'observed_directory_bucket'):
        return 'secure'  # Inventory reference, NOT evidence of safe access.
    if status == 'foreign_account':
        return 'not_applicable'
    return 'unknown'


def classify_macie_session(region):
    if not isinstance(region, dict) or region.get('session_verified') is not True:
        return 'unknown'
    if region.get('session_status') == 'ENABLED':
        return 'secure'
    if region.get('session_status') in ('NOT_ENABLED', 'PAUSED'):
        return 'insecure'
    return 'unknown'


def classify_macie_configuration(region):
    if classify_macie_session(region) == 'insecure':
        return 'not_applicable'
    if (classify_macie_session(region) != 'secure'
            or region.get('automated_discovery_verified') is not True):
        return 'unknown'
    if region.get('automated_discovery_status') == 'ENABLED':
        return 'secure'  # Configuration only, not successful classification.
    if (region.get('automated_discovery_status') == 'DISABLED'
            and region.get('jobs_complete') is True
            and type(region.get('jobs_count')) is int and region['jobs_count'] >= 0):
        return 'insecure' if region['jobs_count'] == 0 else 'secure'
    return 'unknown'


def classify_macie_bucket(bucket):
    if isinstance(bucket, dict) and bucket.get('coverage_status') in (
            'ERROR', 'STALE_ACTIVITY', 'NO_RECENT_ACTIVITY_EVIDENCE', 'NO_MONITORING_CONFIGURED'):
        return 'insecure'
    # Recent activity does not establish that objects were classified successfully.
    return 'unknown'


def classify_macie_recency(job):
    if not isinstance(job, dict):
        return 'unknown'
    if job.get('type') == 'ONE_TIME':
        return 'not_applicable'
    if job.get('type') != 'SCHEDULED':
        return 'unknown'
    if job.get('stale') is True:
        return 'insecure'
    age = job.get('last_run_age_days')
    if type(age) in (int, float) and 0 <= age <= 45:
        return 'secure'  # Run recency only, not successful classification.
    return 'unknown'


def classify_macie_execution(job):
    if not isinstance(job, dict):
        return 'unknown'
    if job.get('execution_issue') is True:
        return 'insecure'
    if job.get('execution_success_evidence') is True:
        return 'secure'  # No reported execution errors, not content coverage.
    return 'unknown'


# These published policies cover multiple rules, so bind each to its exact
# filename/path/observed field instead of guessing from unrelated resource flags.
SCOPED_POLICIES = {
    'networkfirewall-m10-m-v1': {
        'networkfirewall-broad-pass-rule.json': ('rule_groups', 'broad_pass'),
        'networkfirewall-stateless-default-pass.json': ('policies', 'stateless_default_pass'),
        'networkfirewall-fragment-default-pass.json': ('policies', 'stateless_fragment_default_pass'),
        'networkfirewall-logging-disabled.json': ('firewalls', 'logging_disabled'),
        'networkfirewall-no-route-references.json': ('firewalls', 'no_endpoint_routes'),
        'networkfirewall-routes-not-ready.json': ('firewalls', 'routing_not_ready'),
    },
    'bedrock-m10-r-v1': {
        'bedrock-invocation-logging-review.json': (None, 'invocation_logging_review'),
        'bedrock-agent-no-explicit-guardrail-review.json': ('agents', 'no_explicit_guardrail_review'),
    },
}


def _classify_scoped_review(resource, field):
    if not isinstance(resource, dict):
        return 'unknown'
    if field in ('no_endpoint_routes', 'routing_not_ready'):
        state = resource.get('routing_status')
        if state not in ('endpoint_referenced', 'inactive_or_unready', 'no_endpoint_routes'):
            return 'unknown'
        bad = 'no_endpoint_routes' if field == 'no_endpoint_routes' else 'inactive_or_unready'
        return 'insecure' if state == bad else 'secure'  # Routing references only.
    verified = {
        'logging_disabled': 'logging_complete',
        'broad_pass': 'detail_complete',
        'stateless_default_pass': 'detail_complete',
        'stateless_fragment_default_pass': 'detail_complete',
        'invocation_logging_review': 'logging_verified',
        'no_explicit_guardrail_review': 'detail_verified',
    }[field]
    if resource.get(verified) is not True:
        return 'unknown'
    if resource.get(field) is True:
        return 'insecure'
    if field == 'logging_disabled' and isinstance(resource.get('logging_destinations'), list):
        return 'secure' if resource['logging_destinations'] else 'unknown'
    if field in ('stateless_default_pass', 'stateless_fragment_default_pass'):
        actions = resource.get(field.replace('_pass', '_actions'))
        if isinstance(actions, list) and actions and all(isinstance(x, str) for x in actions):
            return 'insecure' if 'aws:pass' in actions else 'secure'
    if (field == 'no_explicit_guardrail_review'
            and isinstance(resource.get('guardrail_identifier'), str) and resource['guardrail_identifier']):
        return 'secure'  # Explicit attachment, not validated runtime effectiveness.
    if field == 'invocation_logging_review':
        config = resource.get('logging_config')
        if isinstance(config, dict) and any(config.get(k) is True for k in (
                'text_enabled', 'image_enabled', 'embedding_enabled', 'audio_enabled', 'video_enabled')):
            return 'secure'
    # A negative heuristic (e.g. no broad signature) is not verified protection.
    return 'unknown'


CLASSIFIERS = {
    'cis71-s3-bpa-v1': classify_s3_block_public_access,
    'cis71-securityhub-subscription-v1': classify_securityhub_subscription,
    'guardduty-region-enablement-v1': classify_guardduty_region,
    'accessanalyzer-region-configured-v1': classify_accessanalyzer_region,
    'ec2-user-data-secrets-v1': classify_ec2_user_data_secrets,
    'lambda-environment-secrets-v1': classify_lambda_environment_secrets,
    'ecs-environment-secrets-v1': classify_ecs_environment_secrets,
    'alb-waf-protection-v1': classify_alb_waf_protection,
    'secretsmanager-rotation-v1': classify_secret_rotation,
    'secretsmanager-unused-v1': classify_secret_unused,
    'secretsmanager-policy-public-v1': classify_secret_policy_public,
    'secretsmanager-policy-cross-account-v1': classify_secret_policy_cross_account,
    'cis71-rds-deletion-protection-v1': classify_rds_deletion_protection,
    'cis71-rds-cluster-deletion-protection-v1': classify_rds_cluster_deletion_protection,
    'cis71-efs-encryption-v1': classify_efs_encryption,
    'macie-session-v1': classify_macie_session,
    'macie-no-classification-v1': classify_macie_configuration,
    'macie-bucket-coverage-v1': classify_macie_bucket,
    'macie-job-recency-v1': classify_macie_recency,
    'macie-job-execution-v1': classify_macie_execution,
    'm10q-s3-target-reference-v2': classify_m10q_s3_target_reference,
    'm10q-ec2-inspector-coverage-v1': classify_m10q_ec2_inspector,
    'm10q-ecr-image-scan-evidence-v1': classify_m10q_ecr_image_scanning,
    'm10q-s3-backup-evidence-v1': classify_m10q_s3_backup,
    'ssm-unmanaged-ec2-v1': classify_ssm_unmanaged,
    'ssm-offline-agent-v1': classify_ssm_offline,
    'ssm-scan-unverified-v1': classify_ssm_scan_unverified,
    'ssm-security-patches-v1': classify_ssm_security_noncompliant,
    'ssm-missing-patches-v1': classify_ssm_missing_patches,
    'identitycenter-admin-assignment-v1': classify_identitycenter_admin,
    'identitycenter-broad-assignment-v1': classify_identitycenter_broad,
    'identitycenter-cross-account-admin-v1': classify_identitycenter_cross_account,
    'identitycenter-admin-managed-policy-v1': classify_identitycenter_admin_assignment,
    'backup-vault-lock-v1': classify_backup_vault_lock,
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
    'ecs-readonly-root-v1': classify_ecs_writable_root,
    'iam-service-trust-scope-v1': classify_service_role_trust,
    'rds-proxy-require-tls-v1': classify_rds_proxy_tls,
    'cloudtrail-root-write-history-v1': classify_cloudtrail_root_write_event,
    'iam-persistent-key-review-v1': classify_persistent_iam_key,
    'wafv2-explicit-rate-v1': classify_waf_explicit_rate,
    'eks-control-plane-audit-v1': classify_eks_control_plane_audit,
    'wafv2-empty-allow-v1': classify_wafv2_empty_allow,
    'wafv2-association-v1': classify_wafv2_association,
    'securityhub-standard-state-v1': classify_securityhub_standard,
    'access-analyzer-state-v1': classify_access_analyzer,
    'ec2-imds-v2-v1': classify_imds_v2,
    'ec2-direct-public-https-v1': classify_ec2_direct_public_https,
    'acm-expiry-45d-v1': classify_acm_expiring_cert,
    'acm-imported-renewal-90d-v1': classify_acm_imported_renewal,
    'cloudwatch-security-metric-alerting-v1': classify_cloudwatch_security_metric_alerting,
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
    if policy in SCOPED_POLICIES:
        binding = SCOPED_POLICIES[policy].get(getattr(rule, 'filename', None))
        if binding is None:
            raise ValueError('Unexpected scoped rule evidence filename')
        kind, field = binding
        service = 'networkfirewall' if policy == 'networkfirewall-m10-m-v1' else 'bedrock'
        expected_path = service + '.regions.id' + ('.' + kind + '.id' if kind else '')
        if rule.path != expected_path:
            raise ValueError('Unexpected rule evidence path')

        def classifier(resource):
            return _classify_scoped_review(resource, field)
    elif policy in CLASSIFIERS:
        classifier = CLASSIFIERS[policy]
    else:
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
        status = classifier(resource)
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
