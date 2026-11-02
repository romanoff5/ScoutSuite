# M10-Q — S3 Advanced Security

Default AWS scan includes S3 Access Points (regional), directory-bucket access points,
Multi-Region Access Points (MRAP), S3 Access Grants instances/locations/grants, and
S3 Express directory buckets. Output lives under `services.s3.advanced`; all
checks are read-only and preserve resource IDs, ARNs, grantees and scopes.

## Semantics
- API denied/unsupported/unavailable, malformed pages and repeated pagination tokens
  yield **incomplete/unknown**, not empty/passing. Partial rows remain in evidence.
- Access Point / MRAP `policy_public=True` is a **review candidate**, not proof
  of effective anonymous access: bucket/account access blocks, IAM and organizational
  restrictions may still apply.
- Broad Access Grants `WRITE/READWRITE` with `GrantScope=s3://` are review
  candidates; Access Grants do not directly represent anonymous/public access.
- Directory bucket policies and encryption configuration are preserved, but
  object-level exposure, KMS key access and S3 Express authorization end-to-end
  are **not evaluated**. Do not equate inventory success with a secure bucket.
- MRAP control plane uses `us-west-2` once per scan (AWS commercial partition);
  unsupported partitions are explicitly marked.
- Never request object contents, grant credentials, sample sensitive data or object
  enumeration. API pagination continues to exhaustion without arbitrary truncation.
- SDK operations: `ListAccessPoints`, `GetAccessPoint`,
  `GetAccessPointPolicy[Status]`, `GetAccessPointScope`,
  `ListAccessPointsForDirectoryBuckets`, `ListDirectoryBuckets`,
  `GetBucketPolicy`, `GetBucketEncryption`,
  `List/GetMultiRegionAccessPoint[Policy/Status]`,
  `ListAccessGrantsInstances/Locations`, `ListAccessGrants`,
  `GetAccessGrantsInstance[ResourcePolicy]`.

## AWS permissions
Grant the named list/get actions under the appropriate `s3:` or
`s3express:` IAM action names (some differ from SDK names). Most
`s3control` actions also require `AccountId`. Review SCP, region and
cross-account policy constraints. Access-denied evidence remains visible.
Some S3 Express APIs require `s3express:GetBucketPolicy` or
`s3express:GetEncryptionConfiguration`.

## Validation
`python -m pytest -q tests/test_m10_s3_advanced.py` plus guarded offline CI
on Windows and Ubuntu. No real AWS resources were queried in synthetic tests.

References:
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/MrapOperations.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-points-directory-buckets-list.html
- https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_ListAccessGrantsLocations.html
