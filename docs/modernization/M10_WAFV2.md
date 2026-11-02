# M10-J — AWS WAFv2 Web ACLs (default AWS scan)

This is a bounded, read-only WAFv2 collector included in the ordinary
`scout aws` scan. It does not use application requests, traffic logs, sample
requests or mutable AWS APIs.

## Scope and permissions

Calls: `wafv2:ListWebACLs`, `wafv2:GetWebACL` and
`wafv2:GetLoggingConfiguration` for regional Web ACLs in the selected
Regions. In `us-east-1`, separately collects CloudFront-scope (`CLOUDFRONT`)
Web ACLs using the documented global API endpoint. If `us-east-1` is
excluded from the region selection, CloudFront Web ACLs are not inventoried.
No `ListResourcesForWebACL` association discovery, rule group expansion,
request bodies or vulnerability findings in this slice.

At most 20 pages × 100 Web ACL summaries per scope, at most 2,000
GetWebACL and 2,000 GetLoggingConfiguration calls per scope. Tokens,
duplicates, malformed/foreign resource ARNs, permission errors, incomplete
details, logging configuration errors and limits are explicitly marked
partial/denied/failed rather than silently clean.

The report preserves full ARN/ID/name, region/scope, default action, rule
names/priorities, statement type names, managed-rule-group references, rule
group ARNs, Web ACL capacity/visibility, logging destinations and whether
logging configuration was successfully read. It deliberately does not store
raw WAF rule statements or logged HTTP request contents.

## Finding semantics

`wafv2-web-acl-empty-allow` flags only a positively observed Web ACL with
default `ALLOW`, **zero** rules, explicit `ManagedByFirewallManager=false`,
and no firewall-manager pre/post rules. Existing nonempty rules or an
explicit restrictive default action are secure *only for this narrow test*.
Missing, malformed or FMS-managed state remains unknown, not compliant.
No assumption is made about ACL associations or protection effectiveness.
Logging not found or inaccessible is unknown, not proof that logging is off.

## Test and rollback

Botocore model/Stubber tests on both platforms, pagination and API errors,
CloudFront global scoping, rule evidence positive/negative/unknown,
escaped offline HTML, wheel/sdist and legacy AWS/Azure/GCP gates must pass
before merge. No live AWS account was assessed. Use
`--skip-services wafv2` to exclude it.

## M10-K — actual association inventory

A new bounded read-only association collection now runs for **every** Web ACL
during the standard AWS scan:

- Regional Web ACLs: `wafv2:ListResourcesForWebACL` for **all seven**
  resource families in the pinned AWS SDK: Application Load Balancer
  (`APPLICATION_LOAD_BALANCER`), API Gateway REST API stages
  (`API_GATEWAY`), AppSync, Cognito user pools, App Runner, Verified Access
  and Amplify. This API is **not paginated**. Each returned list is checked
  for type, duplicate ARNs and an explicit high bound (10,000 items per
  resource type per Web ACL). Response limit overflow is marked partial.
- CloudFront-scope Web ACLs: use
  `cloudfront:ListDistributionsByWebACLId(WebACLId=<full Web ACL ARN>)`,
  never regional WAFv2 resource enumeration. Up to 100 pages × 100
  distributions; validates each distribution ID/ARN, account ID, returned
  WAF ARN if supplied, and repeated/invalid continuation markers.
  The CloudFront SDK client uses `us-east-1`; no global check is asserted
  when the caller excluded `us-east-1` from the selected regions.

New fields include `association_status`, `association_scope_complete`,
`associated_resources`, `associated_resource_count`,
`checked_resource_types` and `unknown_resource_types`. Reports retain
the full associated resource ARN and, for CloudFront, the distribution ID,
domain name and status. No distribution configuration, origin credentials,
HTTP traffic, Web ACL rule statements or secret payloads are retained.

Three mutually exclusive outcomes:

- **associated:** at least one AWS-returned association confirmed, even
  if a different resource-type check was denied (that other check remains
  explicitly incomplete);
- **unused_candidate:** all API checks within this collector's known
  resource-type scope completed and returned no association;
- **unknown:** no association confirmed, but any necessary API call,
  response, continuation token or size bound was incomplete.

`wafv2-web-acl-unassociated` is an **unused candidate** warning, not proof
that the Web ACL is globally unused. Newly added AWS WAF resource families
not yet in the pinned SDK, Firewall Manager/cross-account deployment,
eventual consistency and association races can limit coverage. An unused
candidate requires manual review before deletion. No inference is made
about whether an associated Web ACL effectively protects its application.

Additional IAM/resource permissions are required for the respective
resource types to use `wafv2:ListResourcesForWebACL`, and
`cloudfront:ListDistributionsByWebACLId` for CloudFront. Missing
permissions are explicit partial evidence, not zero associations.

Synthetic SDK calls and pagination, denied/malformed/duplicate/limit
cases are tested in `tests/test_m10_wafv2_associations.py`; the complete
offline Windows/Ubuntu and installed package gates are required before
merging. No live AWS validation has been performed.
