# RC9: secrets in EC2 user data, Lambda and ECS environments

## Before

- EC2 stored the full decoded `user_data` in the report.
  `user_data_secrets` stored the matched values themselves, including whole
  RSA private-key blocks and 40-character secret access keys.
- Lambda stored every environment value twice: in `env_variables` and in
  `env_variable_values`.
- No rule checked Lambda or ECS environments for secrets.
- The EC2 detector flagged any script containing the bare word "password" or
  "secret", and any 40-character `[0-9a-zA-Z/+]` run, which includes
  repeated characters.

The AGENTS rule "never retrieve or expose secret values ... or raw customer
content not required for the assessment" applies to all of these. A secret
copied into a report becomes a second copy that also has to be rotated and
handled.

## After

All three resources share
`ScoutSuite/providers/aws/resources/secret_detection.py` (detector version
`rc9-secret-detection-v1`). It scans in memory and returns rows of
`{type, location, preview}`:

| Detection | Location | Preview |
|---|---|---|
| AWS access key ID (`AKIA`/`ASIA`) | line / variable | full ID (an identifier, needed to find and deactivate the key) |
| Possible AWS secret access key (40 chars, mixed case + digit or `/`/`+`) | line / variable | `[redacted: 40 chars]` |
| Private key (RSA/EC/DSA/OPENSSH/ENCRYPTED/PKCS8 PEM) | first line | PEM header only |
| Credentials in URL | line / variable | `scheme://user:[redacted: N chars]@host` |
| Secret assignment (`password=`, `token:`, `api_key=`, ...) | line | `[redacted: N chars]` |
| Known token formats (third-party catalog in `providers/utils.py`) | line / variable | `[redacted]` |
| Sensitive variable name with literal value | variable | `[redacted: N chars]` |

Exclusions that reduce false positives:

- Assignments whose value starts with `$`, `` ` ``, `{`, `(` or `<` (variable
  or template references).
- 40-character runs that are SHA-1 hex digests or single-case strings.
- Variable values that reference Secrets Manager, SSM or KMS (an ARN,
  `{{resolve:`, or a `ssm:`/`secretsmanager:` prefix).
- Variable names ending in `_ARN`, `_NAME`, `_ID`, `_PATH`, `_PARAMETER`,
  `_URL`, `_ENABLED` and similar suffixes.
- Placeholder values: `true`, `changeme`, `***`, short integers.
- Bare catalog words ("Generic Password", "Generic Secret") and catalog
  entries the detector already covers.

### EC2 instances (`ec2.regions.*.vpcs.*.instances.*`)

`user_data` is no longer stored. New fields:

- `user_data_status`: `absent`, `present`, `unknown` (DescribeInstanceAttribute
  failed; the failure is recorded as a collection issue) or `undecodable`.
- `user_data_size_bytes`, `user_data_line_count`.
- `user_data_format`: `shell-script`, `cloud-config`, `powershell`,
  `mime-multipart` or `other`.
- `user_data_secrets`: a list of detections. Before RC9 this was a dict of raw
  values.
- `user_data_secret_status`: `detected`, `none`, `no_user_data` or `unknown`.
- `secret_detector_version`.

Decoding no longer runs a second, lenient base64 pass over plain scripts. That
pass silently dropped characters. Strict base64 is still decoded twice.

`ec2-instance-with-user-data-secrets` now flags
`user_data_secret_status == detected`, with evidence policy
`ec2-user-data-secrets-v1`. Unreadable user data is UNKNOWN, which marks the
rule incomplete. The rule ID and `id_suffix` (`potential_secrets`) are
unchanged, so existing exceptions still match.

### Lambda functions (`awslambda.regions.*.functions.*`)

Environment variables are taken from the `ListFunctions` response, so the
per-function `GetFunctionConfiguration` call has been removed.
`env_variable_values` has been removed. `env_variables` now maps each name to
`[redacted: N chars]`, or to the reference itself when the value is a
Secrets Manager, SSM or KMS reference.

New fields:

- `env_variables_status`: `complete` or `unknown`.
- `env_variables_error_code`: copied from `Environment.Error`, for example when
  the scanner cannot use the function's KMS key. This case is recorded as
  `partial/EnvironmentVariablesUnreadable`.
- `env_secret_detections`.
- `env_secret_status`: `detected`, `none`, `no_variables` or `unknown`.

New rule: `awslambda-function-env-secrets` (danger, evidence policy
`lambda-environment-secrets-v1`).

### ECS task definitions (`ecs.regions.*.task_definitions.*`)

Values were already not serialized. Each container now also carries
`environment_secret_detections`, and each task definition carries
`environment_secret_status`: `detected`, `none`, `no_variables` or `unknown`
(malformed `environment` or container definitions). References in
`secrets[]` are never flagged.

New rule: `ecs-task-definition-environment-secrets` (danger, evidence policy
`ecs-environment-secrets-v1`).

## Old reports and rollback

When an old report contains raw `user_data` or `env_variables`, the viewer
shows a note asking for a re-scan instead of the content. Old report files
are not modified. They still hold the raw content and should be handled as
the confidential artifacts they are.

To roll back, revert the RC9 configuration-secrets commit. The two new rules
are new IDs, and the EC2 rule ID is unchanged.
