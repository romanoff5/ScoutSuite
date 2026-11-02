# M10-M — AWS Network Firewall

The `networkfirewall` service runs in a standard AWS scan; no dedicated flag
or separate scanning mode is required.

## Read-only API coverage

`ListFirewalls`, `DescribeFirewall`, `DescribeLoggingConfiguration`,
`ListFirewallPolicies`, `DescribeFirewallPolicy`, `ListRuleGroups`,
`DescribeRuleGroup`, EC2 `DescribeRouteTables`. Bounded paginated
collection rejects malformed pages and repeated tokens and retains identifiable
ARNs, rule configuration, policy group references, subnet mappings and routes.
Each inventory has an independent completeness flag. AccessDenied is never PASS.

## Findings

Enabled by default: disabled logging; stateless PASS default; fragmented packet
PASS default; conservative universal PASS rule; complete VPC route inventory
with no endpoint routes; and inactive/unready endpoint routes.

A `routing_status` of `endpoint_referenced` means only that an ACTIVE
route references a READY firewall endpoint. It does **not** prove that intended
traffic is inspected. `traffic_inspection_verified=false` and
`bidirectional_flow_verified=false` are unconditional; a configured firewall
must never be reported as automatically protecting the VPC.

## Limitations

Cross-account and centralized inspection, Transit Gateway route-table
associations, new VPC endpoint associations, proxy mode, asymmetric traffic,
and end-to-end packet inspection need additional checks/evidence. The route
inventory covers only EC2 route tables belonging to the scanned account and
VPC. Unknown/denied/partial routing yields `routing_status=unknown`, not a
finding of absence and not compliance.

Ensure the audit role can call the enumerated `network-firewall:List*` and
`network-firewall:Describe*` APIs plus `ec2:DescribeRouteTables`.

AWS-managed groups are not directly enumerated in this slice. Policies retain
unresolved rule-group ARNs, and `rule_group_references_resolved=false` records
incomplete policy-to-rule-group coverage rather than claiming all rules inspected.
