"""P5-B: synthetic evidence, confidence and epistemic boundaries."""
from pathlib import Path
from types import SimpleNamespace

from ScoutSuite.core.finding_confidence import build_finding_confidence
from ScoutSuite.core.rule_evidence import evaluate_rule_evidence

ROOT = Path(__file__).resolve().parents[1]


def rule(policy, path, name='synthetic.json'):
    return SimpleNamespace(evidence_policy=policy, path=path, filename=name)


def assessed(policy, *, hits=1, insecure=1, secure=0, unknown=0, status='evaluated',
             category=None, severity=False):
    test_rule = rule(policy, 'iam.users.id')
    report = {'flagged_items': hits, 'assessment_status': status,
              'evaluation_summary': {'counts': {
                  'insecure': insecure, 'secure': secure,
                  'unknown': unknown, 'not_applicable': 0}}}
    if category:
        report['finding_category'] = category
        report['severity_assigned'] = severity
    return build_finding_confidence(test_rule, report)


def test_config_is_confirmed_not_compliance_certified():
    result = assessed('iam-persistent-key-review-v1')
    assert result['claim_type'] == 'OBSERVED_CONFIGURATION'
    assert result['verification_status'] == 'CONFIRMED_CONFIGURATION'
    assert result['confidence'] == 'HIGH'
    assert result['compliance_verified'] is False


def test_attack_candidate_never_promoted_to_confirmed_permission():
    for policy in ('iam-p4b2-user-passrole-v1',
                   'iam-p4b2-user-assumerole-v1',
                   'p3b-alb-backend-bypass-v1'):
        result = assessed(policy)
        assert result['verification_status'] == 'POTENTIAL'
        assert result['confidence'] == 'MEDIUM'
        assert result['iam_simulator_status'] == 'NOT_RUN'
        assert result['attack_execution_verified'] is False


def test_incomplete_scope_is_partial_but_observed_bad_configuration_remains():
    result = assessed('iam-persistent-key-review-v1', unknown=2, status='incomplete')
    assert result['verification_status'] == 'CONFIRMED_CONFIGURATION'
    assert result['confidence'] == 'MEDIUM'
    assert result['evidence_quality'] == 'PARTIAL'
    assert 'INCOMPLETE_ASSESSMENT_SCOPE' in result['reason_codes']


def test_unknown_and_legacy_never_become_clean_pass():
    assert assessed('iam-persistent-key-review-v1', hits=0, insecure=0,
                    unknown=1)['verification_status'] == 'UNKNOWN'
    assert assessed(None, hits=4, insecure=0)['verification_status'] == 'UNKNOWN'
    assert assessed('iam-persistent-key-review-v1', hits=1, insecure=0)[
        'verification_status'] == 'UNKNOWN'


def test_non_flagged_finding_does_not_verify_compliance():
    result = assessed('iam-persistent-key-review-v1', hits=0, insecure=0, secure=2)
    assert result['verification_status'] == 'NO_MATCH_OBSERVED'
    assert result['compliance_verified'] is False


def test_policy_findings_remain_review_until_explicit_approved_threshold():
    generic = assessed('p2-cloudwatch-log-retention-v1', category='policy_dependent')
    assert generic['claim_type'] == 'POLICY_REVIEW'
    assert generic['verification_status'] == 'REVIEW'
    scoped = assessed('p2-cloudwatch-log-retention-v1', category='policy_dependent', severity=True)
    assert scoped['verification_status'] == 'POLICY_VIOLATION'


def test_monitoring_is_only_local_and_external_is_unverified():
    result = assessed('cloudwatch-security-metric-alerting-v1')
    assert result['monitoring_assurance']['local_cloudwatch'] == 'MISSING'
    assert result['monitoring_assurance']['external_siem'] == 'EXTERNAL_UNVERIFIED'
    assert result['monitoring_assurance']['verified_configured'] is False


def test_backup_does_not_prove_application_recovery_rpo_or_rto():
    result = assessed('backup-latest-restore-failure-v1')
    evidence = result['recovery_assurance']
    assert evidence['restore_execution'] == 'OBSERVATION_ONLY'
    assert evidence['application_validation'] == 'UNKNOWN'
    assert evidence['rto_evidence'] == evidence['rpo_evidence'] == 'UNKNOWN'


def test_hostname_correlation_is_not_production_dns_or_sni_proof():
    result = assessed('p3b-alb-hostname-cert-v1')
    assert result['hostname_assurance']['production_hostname_census'] == 'UNVERIFIED'
    assert result['hostname_assurance']['sni_handshake'] == 'UNVERIFIED'


def test_real_machine_readable_evidence_preserves_ids_not_secrets():
    arn = 'arn:aws:iam::123456789012:user/Builder'
    payload = {'iam': {'users': {
        'AIDA123': {'arn': arn, 'name': 'Builder',
                    'p4b2_user_passrole_status': 'candidate',
                    'access_token': 'NOT_FOR_REPORT'},
        'AIDA456': {'arn': 'arn:aws:iam::123456789012:user/Unknown',
                    'p4b2_user_passrole_status': 'unknown'},
    }}}
    summary = evaluate_rule_evidence(rule('iam-p4b2-user-passrole-v1', 'iam.users.id'), payload)
    assert summary['counts'] == {'secure': 0, 'insecure': 1, 'unknown': 1, 'not_applicable': 0}
    assert len(summary['observations']) == 2
    confirmed = summary['observations'][0]
    assert confirmed['resource_path'] == 'iam.users.AIDA123'
    assert confirmed['observed_attributes']['arn'] == arn
    assert confirmed['outcome'] == 'insecure'
    assert 'access_token' not in str(summary)


def test_html_dashboard_escapes_all_confidence_fields():
    text = (ROOT / 'ScoutSuite/output/data/html/partials/dashboard.html').read_text()
    assert '{{confidence_assessment.confidence}}' in text
    assert '{{confidence_assessment.verification_status}}' in text
    assert '{{{' not in text
