# M08-D — S3 new-write encryption and bucket-level public exposure

Date reviewed: **2026-11-01**. Base: `4a69b545`. Scope: AWS S3 general-purpose
buckets already collected by ScoutSuite. No AWS writes, object downloads,
live credentials, Azure/GCP changes, or benchmark recertification.

## Encryption — preserve historical rule ID without false findings

Since **2023-01-05**, Amazon S3 automatically applies **SSE-S3** to *new
writes* for every general-purpose bucket. No custom default-encryption
configuration is **not** proof that objects are unencrypted.

- `GetBucketEncryption` with AES256, aws:kms, or aws:kms:dsse:
  `default_encryption_enabled=True`, `encryption_evidence='api'`.
- `ServerSideEncryptionConfigurationNotFoundError`: classify new-write
  SSE-S3 baseline as `True`, `AES256`,
  `encryption_evidence='aws_baseline'`. Do **not** flag missing custom
  configuration as insecure.
- Denied, malformed, unsupported or missing client: leave fields
  `None`, set `encryption_evidence='unverified'`, and record
  `BucketEncryption` in collection issues; this is not compliance success.
- Existing rule **`s3-bucket-no-default-encryption`** remains at the same
  resource path, with original `id_suffix` and default severity. It
  triggers only on explicitly observed disabled encryption; it no longer
  treats historical saved reports lacking evidence provenance as a
  verified violation. New `evaluation_summary` reports secure/insecure/
  unknown distinctly.

**Limit:** this confirms new-write default configuration/baseline, **not
encryption of older existing objects**, object-level encryption overrides,
KMS key access control or customer-managed key mandates. Those require a
separate policy and inventory. There is no supported AWS switch to
disable baseline SSE-S3.

Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption-faq.html

## Public access — separate configuration from effective bucket-level risk

`S3.finalize()` now combines account-level and bucket-level Block Public
Access using tri-state, most-restrictive logic:
**True** if either known True, **False** only if both known False,
otherwise **None**. The raw bucket settings are copied to
`bucket_public_access_block_configuration`; the legacy
`public_access_block_configuration` field contains the effective
account+bucket view. Neither the source dict nor the account config is
mutated. A denied account-level read is never flattened into False.

New bucket-level evidence (additive):
- `public_exposure_status`: `exposed`,
  `no_bucket_level_exposure_detected`, or `unknown`
- `public_exposure_reasons` (e.g. `PublicBucketPolicy`,
  `EffectivePublicBucketACL`)
- `acl_collection_status` / `policy_collection_status` and the
  existing M06 `object_ownership` and `policy_is_public`

A public bucket policy is considered an observed exposure vector when
`RestrictPublicBuckets=False`; `BlockPublicPolicy` is preventive and
does **not** suppress an already present policy.
Public bucket ACL grants to AllUsers/AuthenticatedUsers are effective only
when ACLs are enabled and `IgnorePublicAcls=False`; new ACL prevention
(`BlockPublicAcls`) does not necessarily block preexisting grants.
`BucketOwnerEnforced` disables ACL authorization altogether.
Any unresolved required property leads to `unknown`, unless another
confirmed exposure vector establishes the finding.

The separately **opt-in** `s3-bucket-effective-public-exposure` finding
and `aws-s3-evidence-2026-11.json` profile use those fields. Existing
world-ACL and world-policy statement findings **retain their IDs** and
remain config-oriented: a public policy statement is not necessarily
effective public access. The rule is not a complete IAM authorization
simulation. Access Points, MRAP, object ACLs, VPC endpoint permissions,
IAM, SCP/RCP and access-point aliases remain outside the check.

Sources:
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html

## Encryption in transit

The existing `s3-bucket-allowing-cleartext` rule retains its key,
severity and `id_suffix`. An `Allow` conditioned on HTTPS alone does
not prove that independent HTTP requests are denied. We only mark
`secure_transport_enabled=True` for a broad explicit **Deny**
of `aws:SecureTransport=false`, for all principals and bucket and object
resources, optionally excluding AWS service principals as AWS recommends.
A missing verified bucket policy is False; denied/unknown reads are None.
Unsupported complex policy patterns are **not automatically proven secure**.
This is a conservative *bucket-policy enforcement* check, not an effective
authorization proof across all policy layers.

Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html

## Report and test contracts

The default ruleset is unchanged; the existing two S3 rule keys are
updated in place. The new explicit profile consists of three checks:
default encryption, HTTPS enforcement, effective bucket-level exposure.
All new fields are additive to existing report resources.

Offline tests:
- SDK success, SSE-S3 baseline absence, explicit SSE-KMS/DSSE-KMS,
  AccessDenied, malformed encryption payload
- ACL/policy deny, explicit NoSuchBucketPolicy, positive and negative
  HTTPS policy examples
- BPA None/True/False, no source mutations, preventive vs retroactive
  blocks, BucketOwnerEnforced ACL suppression, unknown states
- Exact rule IDs, checked/flagged items, synthetic stored report
  serialization, profile version and incomplete issue provenance

No new IAM actions are introduced beyond existing M06 reads:
`s3:GetEncryptionConfiguration`, `s3:GetBucketPolicy`,
`s3:GetBucketPolicyStatus`, `s3:GetBucketAcl`,
`s3:GetBucketOwnershipControls`,
`s3:GetBucketPublicAccessBlock`,
`s3:GetAccountPublicAccessBlock`.
Missing permissions must show incomplete coverage.

**Remaining M08:** non-bucket S3 access paths/object encryption inventory,
Classic ELB TLS, IMDSv2/Lambda runtime lifecycle, IAM policy freshness,
current compliance edition mapping, broader Python 3.14 and live AWS
integrations. This M08-D slice does not assert those complete.
