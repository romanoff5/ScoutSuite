"""An opt-in policy contract for AWS compliance-review findings."""
COMPLIANCE_PROFILE_ID = "aws-compliance-policy"
POLICY_RULE_REQUIREMENTS = {
 "vpc-default-with-igw-and-no-network-interfaces-review.json": "disallow_unused_default_vpc_with_igw",
 "rds-instance-enhanced-monitoring-disabled-review.json": "require_rds_enhanced_monitoring",
 "rds-instance-detailed-query-metrics-disabled-review.json": "require_rds_detailed_query_metrics",
 "rds-instance-iam-database-auth-disabled-review.json": "require_rds_iam_db_auth",
 "rds-instance-monitoring-auth-all-disabled-review.json": "require_rds_observability_and_iam_auth",
 "ssm-document-public-sharing-permitted-review.json": "require_ssm_public_document_sharing_blocked",
 "ec2-running-instance-detailed-monitoring-disabled-review.json": "require_ec2_detailed_monitoring",
 "cloudwatch-log-group-unlimited-retention.json": "require_finite_cloudwatch_retention",
 "cloudwatch-log-group-no-customer-kms.json": "require_cloudwatch_customer_kms",
 "ec2-running-instances-share-ssh-key-name.json": "disallow_shared_ec2_key_name",
 "ec2-security-group-all-egress-to-world.json": "require_restricted_ec2_egress",
 "athena-workgroup-results-kms-not-enforced.json": "require_athena_result_kms",
 "glue-catalog-kms-not-configured.json": "require_glue_catalog_kms",
 "cloudwatch-log-group-retention-exceeds-policy.json": "max_cloudwatch_retention_days",
}
BOOLEAN_REQUIREMENTS = frozenset(v for v in POLICY_RULE_REQUIREMENTS.values()
                                 if v != "max_cloudwatch_retention_days")


def validate_compliance_thresholds(profile):
    """Reject ambiguous or unsupported compliance requirements, never fall back."""
    values = profile.get("policy_thresholds")
    if not isinstance(values, dict) or not values:
        raise ValueError("Missing explicit policy_thresholds")
    if set(values) - (BOOLEAN_REQUIREMENTS | {"max_cloudwatch_retention_days"}):
        raise ValueError("Unknown policy threshold")
    maximum = values.get("max_cloudwatch_retention_days")
    if maximum is not None and (type(maximum) is not int or not 1 <= maximum <= 3650):
        raise ValueError("Retention maximum must be an integer from 1 to 3650")
    selected = profile.get("rules")
    if not isinstance(selected, dict) or not selected:
        raise ValueError("No explicit compliance rules selected")
    if set(selected) - set(POLICY_RULE_REQUIREMENTS):
        raise ValueError("Non-policy rule in compliance profile")
    for filename, entries in selected.items():
        if not isinstance(entries, list) or len(entries) != 1:
            raise ValueError("Exactly one policy rule version required")
        config = entries[0]
        if (not isinstance(config, dict) or config.get("enabled") is not True
                or config.get("level") not in ("warning", "danger")):
            raise ValueError("Enabled rule and explicit severity are required")
        requirement = POLICY_RULE_REQUIREMENTS[filename]
        if requirement == "max_cloudwatch_retention_days":
            if type(maximum) is not int or config.get("args") != [str(maximum)]:
                raise ValueError("Retention threshold and rule argument must match")
        elif values.get(requirement) is not True:
            raise ValueError("Selected policy rule must have an explicit true requirement")


def policy_requirement_for(rule):
    if getattr(rule, "finding_category", None) != "policy_dependent":
        return None
    return getattr(rule, "policy_requirement", None)
