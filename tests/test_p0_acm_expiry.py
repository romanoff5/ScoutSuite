"""P0: UTC ACM expiry windows, imported cert renewal, and unknown evidence."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ScoutSuite.providers.aws.resources.acm.certificates import Certificates
from ScoutSuite.core.rule_evidence import classify_acm_expiring_cert, classify_acm_imported_renewal


NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


def certificate(days, kind='IMPORTED', usage=None):
    entry = {
        'DomainName': 'test.example.org', 'CertificateArn': 'arn:aws:acm:eu-central-1:000:certificate/test',
        'Type': kind, 'InUseBy': ['arn:aws:elasticloadbalancing:eu-central-1:000:loadbalancer/app/test']
        if usage is None else usage,
        'NotAfter': NOW + timedelta(days=days)
    }
    obj = Certificates.__new__(Certificates)
    parsed = dict(entry)
    parsed['expiry_status'], parsed['days_until_expiry'] = obj._expiry_evidence(parsed, NOW)
    parsed['renewal_review_status'] = obj._renewal_review(parsed)
    return parsed


def test_imported_in_use_certificate_due_in_40_days_is_detected():
    cert = certificate(40)
    assert cert['expiry_status'] == 'expiring_soon'
    assert cert['renewal_review_status'] == 'review_due'
    assert classify_acm_expiring_cert(cert) == 'insecure'
    assert classify_acm_imported_renewal(cert) == 'insecure'


def test_45_day_boundary_is_exact_and_imported_review_at_90():
    assert certificate(45)['expiry_status'] == 'expiring_soon'
    assert certificate(45, kind='AMAZON_ISSUED')['renewal_review_status'] == 'not_applicable'
    assert certificate(46)['expiry_status'] == 'valid'
    assert certificate(46)['renewal_review_status'] == 'review_due'
    assert certificate(91)['renewal_review_status'] == 'not_due'


def test_expired_and_unused_and_unknown_are_distinct():
    expired = certificate(-1)
    assert expired['expiry_status'] == 'expired'
    assert classify_acm_expiring_cert(expired) == 'insecure'
    assert classify_acm_imported_renewal(expired) == 'insecure'
    unused = certificate(3, usage=[])
    assert classify_acm_expiring_cert(unused) == 'not_applicable'
    assert classify_acm_imported_renewal(unused) == 'not_applicable'
    missing = certificate(40)
    missing['expiry_status'] = 'unknown'
    assert classify_acm_expiring_cert(missing) == 'unknown'
    missing['renewal_review_status'] = 'unknown'
    assert classify_acm_imported_renewal(missing) == 'unknown'


def test_date_inputs_and_parser_does_not_mutate_raw():
    obj = Certificates.__new__(Certificates)
    raw = {'DomainName': 'example.org', 'CertificateArn': 'cert-arn',
           'Type': 'IMPORTED', 'InUseBy': [], 'NotAfter': '2027-01-01T00:00:00Z'}
    key, resource = obj._parse_certificate(raw)
    assert 'expiry_status' not in raw
    assert resource['arn'] == 'cert-arn'
    assert isinstance(resource['days_until_expiry'], (int, float))
    assert obj._expiry_evidence({'NotAfter': 'not-a-date'}, NOW) == ('unknown', None)


def test_rules_registered_and_old_newer_than_bug_not_used():
    root = Path(__file__).resolve().parents[1] / 'ScoutSuite/providers/aws/rules'
    for filename in ('acm-certificate-with-close-expiration-date.json',
                     'acm-imported-certificate-renewal-review.json'):
        rule = json.loads((root / 'findings' / filename).read_text())
        assert 'evidence_policy' in rule
        assert 'newerThan' not in json.dumps(rule)
        for profile in ('default.json', 'detailed.json'):
            rules = json.loads((root / 'rulesets' / profile).read_text())['rules']
            assert rules[filename][0]['enabled'] is True
