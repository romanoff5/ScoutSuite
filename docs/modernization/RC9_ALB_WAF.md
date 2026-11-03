# RC9: internet-facing ALB WAF protection

## Before

Nothing in the scanner checked whether an internet-facing Application Load
Balancer was protected by a WAF. The WAFv2 service listed web ACLs and their
associations, but no rule combined that information with load balancers.
Security-group normalization also dropped `PrefixListIds`, so an origin that
accepts only CloudFront's managed prefix list looked as if it had no ingress
at all.

## API/permission contract

These calls are all read-only. Each is made only for application load
balancers whose scheme is `internet-facing`:

- `wafv2:GetWebACLForResource` per ALB. It returns the associated web ACL, or
  nothing when none is associated.
- `ec2:DescribeManagedPrefixLists`, filtered to the catalogued prefix-list
  names, once per Region. It maps prefix-list IDs to names.
- At scanner start, an unauthenticated HTTPS GET to each CDN/WAF provider's
  published range list (see below). It contacts no AWS or customer endpoint.

A denied or failed call is recorded as an `elbv2` collection issue, and the
evidence it was meant to produce stays `unknown`.

## Fields

Security groups gain `prefix_lists` (`PrefixListId`, `Description`) under
each protocol/port grant. The legacy `rules.ingress.count` is unchanged.

Load balancers keep all existing fields and gain these additive ones:

| Field | Values |
|---|---|
| `waf_web_acl_status` | `associated`, `none`, `unknown` |
| `waf_web_acl` | `{arn, name, id}` of the associated web ACL |
| `cdn_prefix_lists` | `{prefix-list-id: name}`; `null` if unreadable |
| `origin_exposure` | `open_to_internet`, `cdn_restricted`, `restricted_sources`, `no_ingress`, `unknown`, `not_internet_facing`, `not_applicable` |
| `origin_sources` | one row per TCP/ALL ingress grant reaching a listener port: `group_id`, `ports`, `source`, `cdn_provider` |
| `origin_cdn_providers` | proxies recognised in those sources |
| `waf_protection_status` | `aws_waf`, `external_waf_likely`, `restricted_origin`, `open_without_waf`, `not_internet_facing`, `not_applicable`, `unknown` |
| `cdn_catalog_version`, `cdn_catalog_sources` | catalog version, and for each provider whether its ranges were `live`, `bundled` or `unavailable` |

`elbv2.cdn_catalog` records the run's catalog summary: version, review date,
and for each provider its source, count, fetch time or failure reason.

## Rule

`elbv2-internet-facing-alb-without-waf` (warning, evidence policy
`alb-waf-protection-v1`) flags `waf_protection_status == open_without_waf`.
That status requires three conditions together:

- the ALB is internet-facing;
- AWS WAF is verified as not associated;
- a listener port is reachable from `0.0.0.0/0` or `::/0`.

Such an origin is unprotected even if an external WAF sits in front of it,
because a client can connect to the ALB directly. The other statuses map as
follows:

- `external_waf_likely`: listener ports accept only CloudFront's prefix list or
  catalogued proxy ranges. Secure, reported as "likely" because the WAF policy
  itself is not visible.
- `restricted_origin`: any other non-world source set. Secure.
- `not_internet_facing` and `not_applicable`: not applicable.
- `unknown`: UNKNOWN, which marks the rule incomplete.

## CDN/WAF origin range catalog

The bundled catalog is
`ScoutSuite/providers/aws/rules/catalogs/cdn-origin-ranges-2026-11.json`,
version `2026.11.1`, reviewed 2026-11-03.

| Provider | Official source | Bundled |
|---|---|---|
| CloudFront | AWS managed prefix list `com.amazonaws.global.cloudfront.origin-facing` (resolved from the AWS API) | n/a |
| Cloudflare | `https://www.cloudflare.com/ips-v4`, `ips-v6` | yes |
| Fastly | `https://api.fastly.com/public-ip-list` | yes |
| Akamai | Origin IP ACL: `techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_CIDRs.txt`, `..._ipv6_CIDRs.txt` (ranges retired on 2025-07-01 excluded) | yes |
| Imperva | `https://my.imperva.com/api/integration/v1/ips` | yes |
| Gcore | `https://api.gcore.com/cdn/public-ip-list` (several hundred host addresses) | live only |

Some providers are not included. Akamai Site Shield maps and Azure Front Door
service tags are per customer or per week. Sucuri had no verifiable official
list on the review date. Their origins are classified as `restricted_origin`,
never as open.

### Start-of-run refresh

For AWS scans that include `elbv2`, the scanner downloads each provider's
current list before collection. The download:

- uses HTTPS only, with a 5-second timeout and a 1 MiB limit per source;
- requires every entry to parse as a CIDR no broader than /8 (IPv4) or /20
  (IPv6);
- requires the entry count to be between 1 and 20,000.

Any failure, such as no internet access, a timeout, a changed format, a
too-broad entry or an oversized response, keeps that provider's bundled
ranges. The scanner prints a warning and continues the scan. A live-only
provider is not recognised in that run. Use `--no-cdn-range-update` for
air-gapped runs. The refreshed catalog lives on the run's `RunContext` and is
never shared between runs.

A tampered list cannot turn an open origin into a pass, because world-open
ingress is evaluated first. At worst it changes a `restricted_origin` into
`external_waf_likely`; both are non-findings.

## Compatibility and rollback

All fields are additive, and the rule ID is new. Old reports render without
the WAF section. To roll back, revert the RC9 ALB WAF commit. Without it the
scan stops making the start-of-run requests and the two AWS read calls.
