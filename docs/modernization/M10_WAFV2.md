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
