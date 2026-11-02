"""M10-Q consolidation contract: default AWS scan, rulesets and fail-closed joins.

This is an offline regression gate, not a claim that AWS operational controls
have been exercised in a customer account.
"""
import ast
import inspect
import json
import textwrap
from pathlib import Path

from ScoutSuite.providers.aws.resources.coverage_reconciliation import (
    reconcile_m10q_coverage,
)
from ScoutSuite.providers.aws.services import AWSServicesConfig


ROOT = Path(__file__).resolve().parents[1]
M10_SERVICES = frozenset({
    "accessanalyzer", "guardduty", "securityhub", "organizations",
    "inspector2", "ecr", "ecs", "eks", "wafv2", "backup",
    "identitycenter", "networkfirewall", "macie", "ssm", "bedrock",
})
# M10-Q and M10-S are postprocessors, not standalone AWS services.
RULE_PREFIXES = M10_SERVICES | frozenset({"m10q", "m10s"})


def _json(relative_path):
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


def _m10_default_rules():
    rules = _json("ScoutSuite/providers/aws/rules/rulesets/default.json")["rules"]
    return {
        name: entries for name, entries in rules.items()
        if name.split("-", 1)[0] in RULE_PREFIXES
    }


def test_all_m10_services_have_unconditional_production_registration():
    # Unlike synthetic service-list fixtures, this inspects the actual class
    # used by AWSServicesConfig in a normal AWS scan.
    source = textwrap.dedent(inspect.getsource(AWSServicesConfig.__init__))
    method = ast.parse(source).body[0]
    direct_assignments = {
        target.attr
        for statement in method.body
        if isinstance(statement, ast.Assign)
        for target in statement.targets
        if isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id == "self"
    }
    assert M10_SERVICES <= direct_assignments


def test_all_m10_services_are_in_catalog_and_have_report_navigation():
    catalog = _json("tests/data/provider-catalogs.json")["aws"]
    assert M10_SERVICES <= set(catalog["core_services"])
    metadata = _json("ScoutSuite/providers/aws/metadata.json")
    for service in M10_SERVICES:
        candidates = [
            section[service] for section in metadata.values()
            if service in section
        ]
        assert len(candidates) == 1, service
        entries = candidates[0].get("resources")
        assert isinstance(entries, dict) and entries, service
        for entry in entries.values():
            assert entry["path"].startswith("services." + service + "."), (
                service, entry
            )


def test_detailed_ruleset_preserves_every_default_m10_rule_and_severity():
    default = _m10_default_rules()
    detailed = _json("ScoutSuite/providers/aws/rules/rulesets/detailed.json")["rules"]
    assert default
    assert not (default.keys() - detailed.keys()), sorted(
        default.keys() - detailed.keys()
    )
    for filename, config in default.items():
        assert (ROOT / "ScoutSuite/providers/aws/rules/findings" / filename).is_file()
        assert detailed[filename] == config, filename


def test_m10q_and_m10s_rules_remain_enabled_by_default():
    rules = _m10_default_rules()
    required = {
        "m10q-ec2-not-reported-by-inspector2.json",
        "m10q-ecr-image-scanning-gap.json",
        "m10q-s3-backup-evidence-gap.json",
        "m10q-s3-access-point-bucket-unresolved.json",
        "m10q-s3-directory-access-point-target-unresolved.json",
        "m10s-org-cloudtrail-config-gap.json",
    }
    assert required <= rules.keys()
    assert all(any(item.get("enabled") is True for item in rules[name])
               for name in required)


def test_postprocessing_occurs_once_after_inspector_without_sdk_collection():
    from ScoutSuite.providers.aws.provider import AWSProvider

    source = inspect.getsource(AWSProvider.preprocessing)
    inspector = source.index("reconcile_inspector_inventory(")
    m10q = source.index("reconcile_m10q_coverage(")
    cloudtrail = source.index("reconcile_cloudtrail_organization_coverage(")
    assert inspector < m10q < cloudtrail
    assert source.count("reconcile_m10q_coverage(") == 1


def test_partial_or_unselected_inspector_never_becomes_a_negative_finding():
    instance = {"id": "i-00000000000000001", "State": {"Name": "running"}}
    services = {
        "ec2": {"regions": {
            "eu-central-1": {"vpcs": {
                "vpc-123": {"instances": {instance["id"]: instance}}
            }}
        }}
    }
    summary = reconcile_m10q_coverage(
        services, ["ec2"], "123456789012"
    )
    assert summary["version"] == 2
    assert summary["api_calls"] == 0
    assert summary["resource_counts"]["ec2_inspector"] == 1
    assert instance["m10q_inspector"]["state"] == "unknown"
    assert not instance["m10q_inspector_not_reported"]
    assert "inspector2" not in services
    assert "m10q_image_scanning" not in instance
