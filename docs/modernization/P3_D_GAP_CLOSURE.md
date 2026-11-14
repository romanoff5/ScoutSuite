# P3-D — ALB target health, EC2 S3 IAM grants, RDS monitoring

## Scope

Adds **seven enabled AWS rules** in three read-only domains. Cross-resource
correlations run in existing `AWSProvider.preprocessing()`, after the
underlying AWS resources and security rules have been collected.

No customer evidence or credentials are committed. No network/host reachability
test, policy simulation, or secret-value read is performed.

## ALB target health (2 rules)

The existing P3-B `DescribeTargetGroups` and `DescribeTargetHealth` collector
now preserves:
- Target-group ARN, name, target type, protocol/version, listener-independent
  target port, VPC ID
- HealthCheckEnabled, HealthCheckProtocol, HealthCheckPort, HealthCheckPath,
  interval, timeout, thresholds and Matcher
- Target ID, port, health State, Reason and Description

The first rule identifies actual AWS `Target.ResponseCodeMismatch` states
and includes the mismatch reason and configured health-check settings. This
proves an observed response-code mismatch, **not** a path misconfiguration:
application authentication, routing and redirects can cause the same symptom.
A second rule flags other unhealthy targets such as
`Target.Timeout`, `Target.FailedHealthChecks` and `Elb.InternalError`.

Transient states, empty target groups, malformed/incomplete inventories and
AccessDenied never produce a clean PASS.

## EC2 instance IAM S3 read candidate (1 rule)

Uses `ec2.instances.IamInstanceProfile.Id` and
`iam.roles.instance_profiles` to establish the real role, not the possibly
different profile name. Reviews inline and managed policy **documents** for
unconditional `Allow` broad `s3:Get*`, `s3:List*`, `s3:*`, `*`
statements with wildcard S3 resources. `s3:ListAllMyBuckets` alone does
not trigger the rule. Names/ARNs/action/resource/Sid are preserved.

Findings are **broad grant candidates**, *not verified effective access*.
SCPs, permission boundaries, session policies, resource policies,
explicit Deny, KMS and conditions may constrain the effective permission
set. Missing policy documents, denied IAM inventory, unsupported NotAction/
NotResource and conditional Allow remain unverified.

## RDS local observability (4 rules)

The RDS facade now reads `DescribeEventSubscriptions` with bounded
pagination, preserving subscription ARN, ID, SourceType, SourceIds, status,
enabled flag, SNS topic and categories. A failed or partial call is never an
empty inventory.

The correlation links complete regional `CloudWatch.MetricAlarms`
(including MetricStat from metric-math queries) to RDS DB instances and
clusters by `AWS/RDS` namespace and `DBInstanceIdentifier` /
`DBClusterIdentifier` dimension. An actionable alarm has
`ActionsEnabled=True` and at least one AlarmAction; an alarm with empty or
disabled actions is not counted as operational notification coverage.

Event subscriptions count when active, Enabled and targeting the database
or having an empty SourceIds list for the appropriate SourceType. Standalone
instances and Aurora clusters are evaluated separately to avoid duplicate
cluster-member findings. An omitted/partial CloudWatch or RDS inventory is
UNKNOWN, not a passed or missing control.

**Limitations:** This is a local-account configuration signal, not proof that
an alert arrives at a person. EventBridge, external SIEM, cross-account
CloudWatch, topic health, actual delivery, all custom metric-math expressions
and agreed alerting policies are not fully validated.

## CI and quality gates

`tests/test_p3d_security_gap_closure.py` covers positive, secure, transient,
unsupported, permission-denied and partial cases at API-to-rule boundaries.
P3-C's anonymized mapping changes three `gap` abstracts to `partial`:
ALB health-check interpretation, S3 privilege candidate, and RDS observability.
The P3-C synthetic triad count grows from 18 to 25.

All tests use isolated synthetic data, not AWS profiles or customer exports.
Run the existing `Offline CI` workflow across Ubuntu and Windows,
Python 3.11/3.14, then separately conduct authorised field validation.
