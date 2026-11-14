"""P5-B: bounded claims and evidence-quality metadata for Scout findings.

A high-confidence AWS configuration observation is NOT proof of effective IAM
authorization, Internet reachability, notification delivery or RTO/RPO.
Only explicitly classified evidence policies can receive an assessed confidence.
This metadata is additive; it never changes finding IDs, severity or rule results.
"""

ATTACK_PATH_POLICIES = frozenset((
    'iam-p4b-passrole-v1',
    'iam-p4b-privileged-oidc-v1',
    'iam-p4b2-user-passrole-v1',
    'iam-p4b2-user-assumerole-v1',
    'iam-p4b2-role-assumerole-v1',
    'iam-p4b2-group-passrole-v1',
    'p3b-alb-backend-bypass-v1',
))
POTENTIAL_EXPOSURE_POLICIES = frozenset((
    'ec2-direct-public-https-v1',
))
TLS_POLICIES = frozenset(('p3b-alb-hostname-cert-v1',))
MONITORING_POLICIES = frozenset(('cloudwatch-security-metric-alerting-v1',))
RECOVERY_POLICIES = frozenset((
    'backup-workload-arn-evidence-v1',
    'backup-latest-restore-failure-v1',
    'backup-latest-validation-failure-v1',
    'backup-restore-testing-freshness-v1',
    'm10q-s3-backup-evidence-v1',
))


def _claim_kind(policy, finding):
    if finding.get('finding_category') == 'policy_dependent':
        return 'POLICY_REVIEW'
    if policy in ATTACK_PATH_POLICIES:
        return 'POTENTIAL_ATTACK_PATH'
    if policy in POTENTIAL_EXPOSURE_POLICIES:
        return 'POTENTIAL_NETWORK_EXPOSURE'
    if policy in MONITORING_POLICIES:
        return 'LOCAL_MONITORING_CONFIGURATION'
    if policy in RECOVERY_POLICIES:
        return 'BACKUP_RESTORE_OBSERVATION'
    if policy in TLS_POLICIES:
        return 'VISIBLE_HOSTNAME_CORRELATION'
    if policy:
        return 'OBSERVED_CONFIGURATION'
    return 'UNCLASSIFIED_LEGACY_RULE'


def build_finding_confidence(rule, finding):
    """Attach defensible epistemic claims; never infer PASS from missing data."""
    summary = finding.get('evaluation_summary')
    policy = getattr(rule, 'evidence_policy', None)
    kind = _claim_kind(policy, finding)
    incomplete = finding.get('assessment_status') == 'incomplete'
    flagged = finding.get('flagged_items', 0)
    counts = summary.get('counts') if isinstance(summary, dict) else None
    has_evidence = (isinstance(counts, dict)
                    and all(type(counts.get(k)) is int and counts[k] >= 0
                            for k in ('secure', 'insecure', 'unknown', 'not_applicable')))
    bad = counts['insecure'] if has_evidence else 0
    unknown = counts['unknown'] if has_evidence else 0
    quality = ('UNAVAILABLE' if not has_evidence else
               'PARTIAL' if unknown or incomplete else 'COMPLETE')
    codes = []
    verification, confidence = 'UNKNOWN', 'UNKNOWN'
    if not has_evidence:
        codes.append('NO_VERSIONED_EVIDENCE_POLICY')
    elif unknown or incomplete:
        codes.append('INCOMPLETE_ASSESSMENT_SCOPE')
    if has_evidence and flagged and not bad:
        codes.append('RULE_EVIDENCE_DISAGREEMENT')
    elif has_evidence and bad and not flagged:
        codes.append('RULE_EVIDENCE_DISAGREEMENT')
    elif has_evidence and flagged and bad:
        if kind in ('POTENTIAL_ATTACK_PATH', 'POTENTIAL_NETWORK_EXPOSURE'):
            verification, confidence = 'POTENTIAL', 'MEDIUM'
            codes.append('INVENTORY_CORRELATION_NOT_EXPLOIT_VERIFICATION')
        elif kind in ('BACKUP_RESTORE_OBSERVATION', 'VISIBLE_HOSTNAME_CORRELATION'):
            verification, confidence = 'OBSERVED_PARTIAL_SCOPE', 'MEDIUM'
            codes.append('OBSERVATION_DOES_NOT_VERIFY_OBJECTIVE')
        elif kind == 'POLICY_REVIEW':
            verification = ('POLICY_VIOLATION' if finding.get('severity_assigned')
                            else 'REVIEW')
            confidence = 'HIGH' if quality == 'COMPLETE' else 'MEDIUM'
            codes.append('ORG_POLICY_REQUIRED_FOR_SEVERITY')
        else:
            verification = 'CONFIRMED_CONFIGURATION'
            confidence = 'HIGH' if quality == 'COMPLETE' else 'MEDIUM'
            codes.append('DIRECT_CLASSIFIED_CONFIGURATION')
    elif has_evidence and not flagged and not bad:
        if unknown or incomplete:
            codes.append('UNKNOWN_NOT_PASS')
        elif counts['secure'] + counts['not_applicable'] == 0:
            verification, confidence = 'NOT_APPLICABLE', 'HIGH'
            codes.append('EMPTY_OR_INAPPLICABLE_SCOPE')
        else:
            verification, confidence = 'NO_MATCH_OBSERVED', 'HIGH'
            codes.append('RULE_SCOPE_ONLY_NOT_COMPLIANCE')
    if (has_evidence and flagged != bad
            and 'RULE_EVIDENCE_DISAGREEMENT' not in codes):
        codes.append('RULE_EVIDENCE_COUNT_DIFFERENCE')
        if confidence == 'HIGH':
            confidence = 'MEDIUM'

    result = {
        'schema_version': 1,
        'claim_type': kind,
        'verification_status': verification,
        'confidence': confidence,
        'evidence_quality': quality,
        'reason_codes': codes,
        'evidence_reference': 'evaluation_summary.observations',
        'effective_permission_verified': False,
        'external_reachability_verified': False,
        'compliance_verified': False,
    }
    if kind == 'POTENTIAL_ATTACK_PATH':
        result['iam_simulator_status'] = 'NOT_RUN'
        result['attack_execution_verified'] = False
    if kind == 'POTENTIAL_NETWORK_EXPOSURE':
        result['network_path_checks'] = {
            'routing': 'UNVERIFIED', 'nacl': 'UNVERIFIED',
            'host_firewall': 'UNVERIFIED', 'listener': 'UNVERIFIED',
        }
    if kind == 'LOCAL_MONITORING_CONFIGURATION':
        result['monitoring_assurance'] = {
            'local_cloudwatch': 'MISSING' if bad and flagged else 'EXTERNAL_UNVERIFIED',
            'external_siem': 'EXTERNAL_UNVERIFIED',
            'end_to_end_delivery': 'EXTERNAL_UNVERIFIED',
            'verified_configured': False,
        }
    if kind == 'BACKUP_RESTORE_OBSERVATION':
        result['recovery_assurance'] = {
            'backup_coverage': 'OBSERVATION_ONLY',
            'restore_execution': 'OBSERVATION_ONLY',
            'application_validation': 'UNKNOWN',
            'rpo_evidence': 'UNKNOWN',
            'rto_evidence': 'UNKNOWN',
        }
    if kind == 'VISIBLE_HOSTNAME_CORRELATION':
        result['hostname_assurance'] = {
            'source_scope': 'VISIBLE_ROUTE53_ALIAS_AND_ACM_ONLY',
            'production_hostname_census': 'UNVERIFIED',
            'sni_handshake': 'UNVERIFIED',
        }
    return result
