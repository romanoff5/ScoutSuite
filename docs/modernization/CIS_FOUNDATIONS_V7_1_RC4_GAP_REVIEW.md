# CIS AWS Foundations v7.1.0 — RC4 staging crosswalk and gap review

**State:** separate branch only; not merged into `master`, not part of RC3.
Reference: owner-provided CIS AWS Foundations v7.1.0 PDF, dated 2026-10-02.
Do not commit, redistribute, or reproduce the licensed source document.

## Control inventory — not a compliance score

The canonical reference index lists **94** recommendations. The machine-readable
implementation inventory is `ScoutSuite/providers/aws/rules/catalogs/cis-foundations-v7.1.0-coverage.json`.

| Development status | Count | Interpretation |
| --- | ---: | --- |
| Candidate evidence mapping | 30 | 32 rule associations; not complete CIS control validation |
| Manual review required | 43 | May use captured evidence, but cannot be called automated PASS |
| Partial existing checks, not mapped | 13 | Evidence lacks required specificity or scope |
| Not implemented | 8 | No suitable rule; must remain unassessed |
| **Total** | **94** | Not a compliance denominator |

The opt-in profile `cis-foundations-7.1.0-partial.json` contains **32**
candidate rule mappings across **30** CIS IDs, expanded from the original
11 mappings. All outputs retain `coverage: candidate` and
`compliance_verified: false`. No automatic compliant percentage is permitted.
The older CIS 1.2.0 profile is unchanged. The regular AWS default and
detailed scans include the four new checks independently of the opt-in profile.

## Newly implemented collector-aligned checks

| Control ID | Rule name | Evidence contract and limitation |
| --- | --- | --- |
| 3.1.4 | `s3-bucket-public-access-block-incomplete` | Four effective account/bucket BPA flags; unknown API responses remain UNKNOWN; not proof of object/AP safety or org-wide policy |
| 3.2.5 | `rds-instance-deletion-protection-disabled` | Existing DescribeDBInstances field; does not assess RDS clusters, backup or IAM |
| 3.3.1 | `efs-filesystem-not-encrypted` | DescribeFileSystems Encrypted boolean; does not assess TLS or KMS key policy |
| 5.16 | `securityhub-region-not-subscribed` | Only explicit DescribeHub ResourceNotFound means NOT_SUBSCRIBED; AccessDenied and invalid responses are UNKNOWN |

Each rule uses an evidence classifier with explicit secure/insecure/unknown
states and synthetic regression tests. Existing resource identifiers and
existing reporting schemas are preserved. No new network calls or write APIs.

## Examples of existing checks now mapped conservatively

- 2.10 IAM console MFA; 2.11 unused credentials with **45-day** threshold
  set only in the CIS profile (the regular default may use 90 days);
  2.12 active access keys with 90-day threshold.
- 2.6 root hardware MFA; 3.1.1 S3 HTTPS-only; 3.1.2 MFA Delete;
  3.1.5 default encryption as *new-write configuration only*.
- 3.2.1–3.2.4 existing RDS encryption/upgrade/publicity/Multi-AZ;
  4.1 regional trail visibility; 4.10 partial ELB/ALB log visibility.
- 6.1.1 EBS volume encryption and regional default encryption;
  7.4.2 Bedrock invocation logging configuration.
- Original 11 candidate mappings remain in the profile with their original
  IDs. No legacy rule condition, finding ID or benchmark label is changed.

## Deliberately excluded from automated PASS

- **2.13/2.15/2.16/2.18:** user-group-only permissions, support principals,
  instance-role runtime use and *all-region* Access Analyzer coverage need
  more than related existing rules; no inference from missing IAM data.
- **3.1.3:** Macie session/jobs != proof every sensitive S3 object has been
  classified and secured. **3.1.4:** result reflects effective bucket flags,
  not organization-wide enforcement or individual Access Points.
- **4.7–4.9:** existing VPC/subnet flow logs and generic CloudTrail data
  selectors do not independently establish all VPCs and separate S3
  object READ/WRITE collection; no unsupported aliases.
- **5.1–5.15:** related legacy CloudWatch metric-filter rules are currently
  disabled in the default profile and cannot demonstrate effective alert
  delivery/deduplicated centralized logging. These remain manual review,
  not 15 fabricated PASS results.
- **6.2–6.4:** generic NACL/security-group checks do not independently prove
  both IPv4 and IPv6 exposures to *all* specified remote administration ports
  under the exact benchmark scope. Separate protocols and CIDR analysis needed.
- **7.1–7.5:** Bedrock models/agents/guardrails, long-term API keys, SCP
  context, data-plane logging, vector stores and VPC isolation remain
  unassessed unless evidence for the exact condition is collected; guardrail
  configuration is not runtime protection proof.
- **AWS Organizations / multi-account:** cross-account SecurityAudit roles
  may have AccessDenied for Organizations and Identity Center. A member-account
  scan is not automatically an organization-wide CIS assessment.

## Validation gates and release handling

1. Syntax and integrity of 94-control catalog, 32 candidate rules and
   benchmark-specific arguments, with no copied licensed source.
2. Real rule-engine regression on synthetic RDS, EFS, S3 and Security Hub
   objects, including missing metadata, denial and unknown classification.
3. Windows/Ubuntu Python 3.11/3.14 guarded offline CI, package parity and
   XSS/SQLite/reporting tests on the final candidate SHA.
4. **Wait for the user's RC3 real scan report.** Reconcile any mismatched
   findings/evidence, API response contracts and collection gaps in this
   staging branch. No merge or RC4 tag before that analysis.
5. After approval of code quality gates and real RC3 evidence review, update
   release version/tag to an immutable RC4, merge validated work to fork
   `master`, run four-way CI on the merged SHA and independently build,
   verify and publish RC4.
