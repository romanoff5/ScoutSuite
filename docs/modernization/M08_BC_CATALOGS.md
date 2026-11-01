# M08-B/C — versioned RDS CA lifecycle and ALB TLS protocol-floor rules

Date: 2026-11-01. Source baseline: `c1d8412b`.

## M08-B RDS certificate authority lifecycle

Existing rule `rds-instance-ca-certificate-deprecated` now identifies
`rds-ca-2019` **in addition** to `rds-ca-2015`, while preserving its
rule key, `id_suffix=CACertificateIdentifier`, path and default severity.
It does **not** assert that every old CA expired at the same time:
AWS's 2024 regional timelines vary and some regions were unaffected
until much later. The finding indicates deprecated/migration-required CA,
not a verified outage. Newer known `rds-ca-rsa2048-g1`,
`rds-ca-rsa4096-g1` and `rds-ca-ecc384-g1` are classified as current.
Missing or unrecognized values are `unknown`, not secure.

Source: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL-certificate-rotation.html
and AWS regional release:
https://aws.amazon.com/blogs/aws/rotate-your-ssl-tls-certificates-now-amazon-rds-and-aurora-expire-in-2024/

Catalog: `ScoutSuite/providers/aws/rules/catalogs/rds-ca-2026-11.json`
(version `2026.11.0`, reviewed 2026-11-01, named maintainer ownership).
This is a static dated list, **not** a runtime assertion that a
specific region supports each new CA or that a specific instance's
server certificate has actually expired. Per-region API validity checks
would require explicit `DescribeCertificates` evidence and new IAM
coverage (future M08 slice).

## M08-C ALB listener TLS minimum version

Existing `elbv2-older-ssl-policy` now checks known policies that
**permit TLS 1.0 or TLS 1.1**. The previous rule called several
TLS 1.0/1.1 policies acceptable, including
`ELBSecurityPolicy-2016-08`. It also treated any unknown future
policy as insecure by comparing against a short allowlist.

The versioned `alb-tls-2026-11.json` contains known ALB policy names
from AWS's current `Protocols by policy` matrix, separated into
minimum TLS 1.2+ and permits-earlier-protocol categories. Unknown or
missing HTTPS/TLS policy names remain incomplete, HTTP listeners are
not applicable. `RuleEvidenceUnknown` propagates through M04
collection_status without creating a synthetic critical/danger finding.
The `elbv2-older-ssl-policy` rule ID, existing report path,
risk level and user exception IDs are unchanged. TLS 1.0/1.1
policies now generate warnings; unknown names do not get a
false secure or false insecure designation.

Source: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html

Important: this control checks **protocol minimum only**, not cipher
suite strength, FS/FIPS/PQ compliance, client TLS negotiation, backend
policies or Classic ELB capabilities. An AWS-policy name outside
the dated catalog is an incomplete evaluation. Classic ELB
`elb-older-ssl-policy` must have a separately sourced profile, and
is **not** upgraded by the ALB rule.

## Explicit compatibility differences

- Findings previously omitted for `rds-ca-2019` now appear.
- ALB policies permitting TLS 1.0/1.1 are now flagged instead of
  treated as acceptable.
- Unknown ALB policy names previously flagged by
  `containNoneOf` become unknown evidence, not a security
  assertion.
- Findings for normal TLS1.2+ and current RDS CA are unchanged.
- New `evaluation_summary` metadata is additive; no legacy
  resource ID, rule key, severity or exception key is renamed.

Each changed rule has offline secure, insecure, missing/unknown
and not-applicable cases where relevant. The default AWS ruleset
continues to be selected unless a profile is explicitly requested.
No benchmark equivalence, CIS edition upgrade or universal
compliance certification is asserted by these catalogs.

Required gates: full offline Windows/Linux Python 3.11,
provider preservation M07, AWS/Azure/GCP report characterization
and packaging. Python 3.14 and live nonproduction AWS integrations
are still unverified.
