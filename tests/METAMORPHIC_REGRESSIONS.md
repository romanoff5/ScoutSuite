# Metamorphic and adversarial AWS rule regressions

These tests use **only synthetic AWS inventory and mocked read-only API
responses**. They are not field-validation evidence for client infrastructure.

## Contract

For every case:

1. Construct one baseline inventory with a known rule outcome.
2. Deep-copy it and mutate exactly one raw input field (or replace one
   resource collection as a single structural mutation).
3. Recompute the *production* classifier/correlator and run the *published*
   JSON finding through Scout Suite's recursive rule traversal and
   `evaluate_rule_evidence`.
4. Check both the finding count and the evidence-state classification.
5. Ensure that missing or denied API data produces `UNKNOWN`, not
   `secure`/PASS, and that inapplicable resources produce
   `not_applicable`, not PASS.
6. Re-process the same object where annotations may otherwise leave stale
   evidence.

## Current mutation families

| Source | One input change | Required result |
|---|---|---|
| EC2 | Running -> stopped | N/A for live HTTPS exposure |
| EC2 | SG missing or lifecycle unknown | UNKNOWN, not PASS |
| EC2 | Public IP removed or world ingress restricted | Secure for this scoped rule only |
| ALB/WAF backend | Registered targets removed | N/A for bypass (not clean network evidence) |
| ALB/WAF backend | Target-group listing partial | UNKNOWN, not PASS |
| ALB health | Unhealthy target disappears | N/A; **stale evidence cleared** |
| ALB health | Target-health listing partial | UNKNOWN, not PASS |
| ACM/SNI | SAN no longer covers public Route53 alias | Finding emitted |
| ACM/SNI | Listener cert census or SAN incomplete | UNKNOWN, not PASS |
| RDS Proxy | Healthy target list becomes empty | Missing-target finding emitted |
| RDS Proxy | Target enumeration becomes partial | UNKNOWN, not PASS |
| CloudWatch | Successful inventory becomes AccessDenied | UNKNOWN, not PASS |

The suite uses the standard pytest discovery path; no separate AWS account,
credentials or live network access are required. Run directly with:

```bash
python -m pytest -q tests/test_metamorphic_adversarial.py
```

Extend it using a new independent raw fixture and a single mutation path;
avoid changing multiple AWS inputs to make a failing detector pass.
