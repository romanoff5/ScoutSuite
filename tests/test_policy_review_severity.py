"""Policy-dependent REVIEW is not a severity; explicit opt-in policy checks are."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ScoutSuite.core.processingengine import ProcessingEngine
from ScoutSuite.core.rule_evidence import classify_policy_log_retention
from ScoutSuite.core.ruleset import PolicyProfileError, Ruleset
from ScoutSuite.providers.base.provider import BaseProvider


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "ScoutSuite/providers/aws/rules/rulesets"
POLICY = RULES / "aws-compliance-policy-2026-11.json"
REVIEW_RULES = (
    "cloudwatch-log-group-unlimited-retention.json",
    "cloudwatch-log-group-no-customer-kms.json",
    "ec2-running-instances-share-ssh-key-name.json",
    "ec2-security-group-all-egress-to-world.json",
    "athena-workgroup-results-kms-not-enforced.json",
    "glue-catalog-kms-not-configured.json",
)


def _service(groups):
    return SimpleNamespace(
        services={"cloudwatch": {"regions": {"eu-central-1": {
            "log_groups": groups}}}},
        service_list=["cloudwatch"],
    )


def _groups():
    return {
        "unlimited": {"retention_status": "unlimited",
                      "retention_days": None, "customer_kms_status": "customer_kms"},
        "exact": {"retention_status": "configured",
                  "retention_days": 365, "customer_kms_status": "customer_kms"},
        "over": {"retention_status": "configured",
                 "retention_days": 366, "customer_kms_status": "customer_kms"},
        "denied": {"retention_status": "unknown",
                   "retention_days": None, "customer_kms_status": "unknown"},
    }


def test_default_and_detailed_do_not_assign_severity_to_policy_reviews():
    for name in ("default.json", "detailed.json"):
        rules = json.loads((RULES / name).read_text())["rules"]
        for key in REVIEW_RULES:
            assert rules[key][0]["enabled"] is True
            assert rules[key][0]["level"] == "review"


def test_review_default_flags_candidate_but_not_medium_severity(tmp_path):
    data = {"about": "single opt-in review test", "rules": {
        "cloudwatch-log-group-unlimited-retention.json": [
            {"enabled": True, "level": "review"}]}}
    path = tmp_path / "review.json"
    path.write_text(json.dumps(data))
    report = _service(_groups())
    ProcessingEngine(Ruleset("aws", filename=str(path))).run(report)
    f = report.services["cloudwatch"]["findings"][
        "cloudwatch-log-group-unlimited-retention"]
    assert f["flagged_items"] == 1
    assert f["level"] == "review"
    assert f["finding_disposition"] == "REVIEW"
    assert f["severity_assigned"] is False
    # Incomplete evidence is still INCOMPLETE, never a clean policy review.
    assert f["assessment_status"] == "incomplete"


def test_no_review_candidates_is_not_a_verified_pass(tmp_path):
    data = {"rules": {"cloudwatch-log-group-unlimited-retention.json": [
        {"enabled": True, "level": "review"}]}}
    path = tmp_path / "review-empty.json"
    path.write_text(json.dumps(data))
    report = _service({"finite": {
        "retention_status": "configured", "retention_days": 14}})
    ProcessingEngine(Ruleset("aws", filename=str(path))).run(report)
    f = report.services["cloudwatch"]["findings"][
        "cloudwatch-log-group-unlimited-retention"]
    assert f["flagged_items"] == 0
    assert f["assessment_status"] == "review"
    assert f["finding_disposition"] == "REVIEW"
    assert f["evaluation_summary"]["compliance_verified"] is False


def test_opt_in_retention_threshold_boundary_and_unknown():
    profile = Ruleset("aws", filename=str(POLICY))
    rule = profile.rules["cloudwatch-log-group-retention-exceeds-policy.json"][0]
    assert rule.args == ["365"]
    assert profile.profile_id == "aws-compliance-policy"
    assert profile.policy_thresholds["max_cloudwatch_retention_days"] == 365
    # Verify the loaded rule condition, including replacement of _ARG_0_.
    assert "365" in json.dumps(rule.conditions)
    assert "_ARG_0_" not in json.dumps(rule.conditions)
    report = _service(_groups())
    ProcessingEngine(profile).run(report)
    f = report.services["cloudwatch"]["findings"][
        "cloudwatch-log-group-retention-exceeds-policy"]
    assert f["level"] == "warning"
    assert f["flagged_items"] == 2
    assert f["finding_disposition"] == "POLICY_VIOLATION"
    assert f["policy_threshold"] == 365
    assert f["policy_profile"]["id"] == "aws-compliance-policy"
    assert f["severity_assigned"] is True
    assert f["evaluation_summary"]["counts"] == {
        "secure": 1, "insecure": 2, "unknown": 1, "not_applicable": 0}
    assert f["assessment_status"] == "incomplete"
    assert f["evaluation_summary"]["compliance_verified"] is False


@pytest.mark.parametrize("retention,expected", [
    ({"retention_status": "unlimited"}, "insecure"),
    ({"retention_status": "configured", "retention_days": 365}, "secure"),
    ({"retention_status": "configured", "retention_days": 366}, "insecure"),
    ({"retention_status": "configured", "retention_days": None}, "unknown"),
    ({"retention_status": "unknown", "retention_days": 90}, "unknown"),
    ({}, "unknown"),
])
def test_retention_classifier_has_no_false_pass(retention, expected):
    assert classify_policy_log_retention(retention, 365) == expected


@pytest.mark.parametrize("mutate", [
    lambda p: p["policy_thresholds"].update(max_cloudwatch_retention_days=0),
    lambda p: p["policy_thresholds"].update(max_cloudwatch_retention_days=True),
    lambda p: p["policy_thresholds"].update(max_cloudwatch_retention_days=366),
    lambda p: p["policy_thresholds"].update(unknown_requirement=True),
    lambda p: p["policy_thresholds"].update(require_cloudwatch_customer_kms=False),
    lambda p: p["rules"]["ec2-running-instances-share-ssh-key-name.json"][0].update(level="review"),
    lambda p: p["rules"].update({"iam-root-account-no-mfa.json": [{"enabled": True, "level": "danger"}]}),
])
def test_invalid_or_mismatched_policy_rejected(tmp_path, mutate):
    p = json.loads(POLICY.read_text())
    mutate(p)
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(p))
    with pytest.raises(PolicyProfileError):
        Ruleset("aws", filename=str(path))


def test_policy_thresholds_not_silently_accepted_by_unrelated_profiles(tmp_path):
    p = json.loads(POLICY.read_text())
    p["profile_id"] = "other-profile"
    path = tmp_path / "unrelated.json"
    path.write_text(json.dumps(p))
    with pytest.raises(PolicyProfileError):
        Ruleset("aws", filename=str(path))
    p.pop("profile_id")
    p.pop("profile_version")
    path.write_text(json.dumps(p))
    with pytest.raises(PolicyProfileError):
        Ruleset("aws", filename=str(path))


def test_review_summary_not_promoted_to_issues_or_passed():
    base = {"checked_items": 3, "flagged_items": 2, "review_items": 2,
            "review_rules": 1, "incomplete_rules": 0, "collection_issues": 0,
            "resources_count": 3}
    assert BaseProvider._service_status(base) == "review_required"
    assert BaseProvider._service_status(dict(base, flagged_items=3)) == "issues"
    assert BaseProvider._service_status(dict(base, incomplete_rules=1)) == "incomplete"
    assert BaseProvider._service_status(dict(base, flagged_items=0,
                                            review_items=0)) == "review_required"
