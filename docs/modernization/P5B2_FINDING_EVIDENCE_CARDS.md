# P5-B2 — per-resource finding evidence cards (2026-11-15)

P5-B2 extends P5-B on top of P5-A and P5-C. It is additive and does not
change security rules, finding IDs, severity evaluation, API calls or provider
collector permissions. Ordinary confidential client reports keep original
resource paths, names, full ARNs, account IDs, SG IDs, public IPs, target-group
ARNs, and observed configuration. P4-F/F2 exported fixtures remain
synthetic/anonymized, not a replacement for normal client-report details.

## Data contract

- Each versioned classifier's insecure or unknown observation now records
  an allowlisted resource identity and deterministic predicate checks.
- Each finding includes optional finding_cards (schema_version 1), one
  card per insecure or unknown resource, not one aggregate confidence number.
- The card includes severity, confidence, collection, reachability,
  verification status, claim type, required predicate counts, reason codes,
  source paths, supporting evidence, and safe diagnostic attributes.
- CONFIRMED predicates originate from explicitly named normalized AWS facts.
  UNKNOWN, CONTRADICTED and NOT_VERIFIED never silently become positive
  evidence. Unknown resource outcomes remain UNKNOWN, never PASS.
- Confidence is deterministic: no LLM rating, invented probability or
  numeric risk score. All mandatory predicates must be observed before a
  resource can receive non-UNKNOWN confidence. Classifier-only cards
  cannot receive HIGH confidence without independent rule-specific witnesses.
- Candidate IAM/EC2/ALB paths have a MEDIUM confidence ceiling;
  effective authorization, routing, NACL, OS firewall, listener and active
  exploitability are unverified. Backup RPO/RTO and external SIEM delivery
  likewise are not asserted.
- Collection COMPLETE means all mandatory available rule predicates were
  observed and no assessment-wide incomplete signal was present. It is NOT
  proof of AWS pagination completeness, effective authorization or external
  reachability. Unknown/uncollected mandatory predicates yield PARTIAL/UNKNOWN.
- Dashboard renders each card through escaped Handlebars expressions; never
  raw/triple-mustache HTML. Old JSON/SQLite reports without new fields
  remain readable and render the former dashboard.

## Explicit supported predicates

| Family | Mandatory observed proof | Not verified |
| --- | --- | --- |
| EC2 direct HTTPS | Running state, matching public ENI IPv4/IPv6, linked SG world ingress TCP/443 | Route tables, NACL, host firewall, listener, actual reachability |
| ALB/WAF backend bypass | ALB candidate state and exact target instance, target group ARN, SG and port witness | Actual Internet path and end-to-end bypass |
| IAM/PassRole/OIDC | Per-resource correlated candidate state | Policy simulator, SCP, boundary, session effective permissions |
| CloudWatch | Local alerting gap plus complete metric-filter/alarm collection | External SIEM and notification delivery |
| ACM hostname mismatch | Mismatch classification, visible hostname list and mismatching hostname evidence | Production hostname census and active SNI |
| AWS Backup | Versioned observed status | Application recovery, contractual RPO/RTO |
| Other versioned policies | Classifier outcome and approved diagnostic attributes | Independent predicate validation where not implemented |

Cards are observations, not exploit proof or third-party compliance assurance.
For legacy non-versioned rules, confidence is not fabricated.

## Validation and rollback

Synthetic offline regressions cover EC2 SG witnesses and contradictions,
missing SGs, independent resources, incomplete collection, IAM, CloudWatch,
Backup, ALB, real identifiers, no credential leakage, JSON round-trip,
old-report fallback and HTML escaping. Repository CI additionally covers
report/browser/XSS and multi-provider compatibility. No cloud credentials,
customer data or live network tests are used.

Rollback: revert the P5-B2 commits; P5-B v1 schema remains readable.
