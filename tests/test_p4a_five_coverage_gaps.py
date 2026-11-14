"""P4-A: collector API outcomes, resource states, and real rule JSON traversal."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from botocore.exceptions import ClientError

from ScoutSuite.core.rule_evidence import evaluate_rule_evidence
from ScoutSuite.core.utils import recurse
from ScoutSuite.providers.aws.facade.ec2 import EC2Facade
from ScoutSuite.providers.aws.facade.iam import IAMFacade
from ScoutSuite.providers.aws.facade.ssm_public import SSMPublicFacade
from ScoutSuite.providers.aws.facade.utils import AWSFacadeUtils
from ScoutSuite.providers.aws.resources.ec2.p4a_monitoring import classify_detailed_monitoring
from ScoutSuite.providers.aws.resources.rds.instances import RDSInstances
from ScoutSuite.providers.aws.resources.rds.p4a_controls import classify_rds_instance_controls
from ScoutSuite.providers.aws.resources.vpc.p4a_default_vpc import classify_default_vpc_gateway


RULES = Path(__file__).resolve().parents[1] / "ScoutSuite/providers/aws/rules/findings"
REGION = "eu-central-1"
P4A = (
    "vpc-default-with-igw-and-no-network-interfaces-review.json",
    "iam-security-alternate-contact-missing.json",
    "rds-instance-enhanced-monitoring-disabled-review.json",
    "rds-instance-detailed-query-metrics-disabled-review.json",
    "rds-instance-iam-database-auth-disabled-review.json",
    "rds-instance-monitoring-auth-all-disabled-review.json",
    "ssm-document-public-sharing-permitted-review.json",
    "ec2-running-instance-detailed-monitoring-disabled-review.json",
)


def check(name, resources):
    rule = json.loads((RULES / name).read_text(encoding="utf-8"))
    cfg = SimpleNamespace(filename=name, path=rule["path"],
                          conditions=rule["conditions"],
                          evidence_policy=rule["evidence_policy"],
                          id_suffix=rule.get("id_suffix"), checked_items=0)
    hits = recurse(resources, resources, cfg.path.split("."), [], cfg, True)
    evidence = evaluate_rule_evidence(cfg, resources)
    return hits, evidence


def test_all_p4a_rule_contracts_enabled_and_policy_reviews_are_neutral():
    base = RULES.parent / "rulesets"
    for profile in ("default.json", "detailed.json"):
        rules = json.loads((base / profile).read_text(encoding="utf-8"))["rules"]
        for name in P4A:
            assert rules[name][0]["enabled"] is True
            assert rules[name][0]["level"] == (
                "warning" if name.startswith("iam-security-") else "review")


class Pages:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kwargs):
        return iter(self.pages)


class DefaultVpcClient:
    def __init__(self, igw_count=1, eni_count=0, fail_at=None):
        self.igw_count = igw_count
        self.eni_count = eni_count
        self.fail_at = fail_at
        self.operations = []

    def get_paginator(self, operation):
        self.operations.append(operation)
        if operation == self.fail_at:
            raise PermissionError("denied")
        field, count = (
            ("InternetGateways", self.igw_count)
            if operation == "describe_internet_gateways"
            else ("NetworkInterfaces", self.eni_count))
        return Pages([{field: [{} for _ in range(count)]}])


def _vpc_data(status):
    return {"vpc": {"regions": {REGION: {"vpcs": {
        "vpc-synthetic": {"default_vpc_gateway_status": status}}}}}}


def test_default_vpc_igw_without_eni_is_candidate_only():
    facade = EC2Facade(object(), "synthetic-owner")
    client = DefaultVpcClient(igw_count=1, eni_count=0)
    with patch.object(AWSFacadeUtils, "get_client", return_value=client):
        census = asyncio.run(facade.get_default_vpc_usage(REGION, "vpc-synthetic"))
    assert census == {"status": "complete", "igw_count": 1, "eni_count": 0}
    assert client.operations == ["describe_internet_gateways", "describe_network_interfaces"]
    state = classify_default_vpc_gateway(True, census)
    assert state == "unused_candidate"
    hit, ev = check(P4A[0], _vpc_data(state))
    assert len(hit) == 1 and ev["counts"]["insecure"] == 1
    assert classify_default_vpc_gateway(False, census) == "not_applicable"


def test_default_vpc_eni_or_no_gateway_not_flagged():
    facade = EC2Facade(object(), "synthetic-owner")
    for igw, eni, state in ((1, 2, "in_use"), (0, 0, "not_applicable")):
        with patch.object(AWSFacadeUtils, "get_client",
                          return_value=DefaultVpcClient(igw, eni)):
            value = asyncio.run(facade.get_default_vpc_usage(REGION, "vpc-synthetic"))
        assert classify_default_vpc_gateway(True, value) == state
        hits, ev = check(P4A[0], _vpc_data(state))
        assert not hits
        assert ev["counts"]["secure" if state == "in_use" else "not_applicable"] == 1


def test_default_vpc_denied_second_api_never_claims_unused_or_clean():
    facade = EC2Facade(object(), "synthetic-owner")
    with patch.object(AWSFacadeUtils, "get_client", return_value=DefaultVpcClient(
            fail_at="describe_network_interfaces")):
        partial = asyncio.run(facade.get_default_vpc_usage(REGION, "vpc-synthetic"))
    assert partial == {"status": "unknown"}
    assert classify_default_vpc_gateway(True, partial) == "unknown"
    hits, ev = check(P4A[0], _vpc_data("unknown"))
    assert not hits and ev["counts"]["unknown"] == 1


def test_security_contact_absent_configured_and_denied_without_pii():
    facade = IAMFacade(object())
    missing = ClientError({"Error": {"Code": "ResourceNotFoundException", "Message": "absent"}},
                          "GetAlternateContact")
    for fn, status in (
        (lambda **kw: (_ for _ in ()).throw(missing), "missing"),
        (lambda **kw: {"AlternateContact": {"EmailAddress": "synthetic.example.invalid"}}, "configured"),
        (lambda **kw: (_ for _ in ()).throw(PermissionError("denied")), "unknown"),
    ):
        client = SimpleNamespace(get_alternate_contact=fn)
        with patch.object(AWSFacadeUtils, "get_client", return_value=client):
            result = asyncio.run(facade.get_security_alternate_contact_status())
        assert result == status
        hits, ev = check(P4A[1], {"iam": {"security_contacts": {
            "security": {"security_contact_status": status}}}})
        assert len(hits) == (1 if status == "missing" else 0)
        assert ev["counts"][
            {"missing": "insecure", "configured": "secure", "unknown": "unknown"}[status]] == 1
    assert not hasattr(facade, "contact")


def _rds_instance(**overrides):
    raw = {
        "DBInstanceIdentifier": "synthetic-db", "DBInstanceStatus": "available",
        "Engine": "postgres", "MonitoringInterval": 0,
        "DatabaseInsightsMode": "standard", "PerformanceInsightsEnabled": False,
        "IAMDatabaseAuthenticationEnabled": False,
    }
    raw.update(overrides)
    return raw


def _rds_data(fields):
    return {"rds": {"regions": {REGION: {"vpcs": {"vpc": {
        "instances": {"db": fields}}}}}}}


def test_rds_three_independent_controls_and_composite_flag_actual_json():
    parser = RDSInstances.__new__(RDSInstances)
    _, item = parser._parse_instance(_rds_instance())
    for filename in P4A[2:6]:
        hits, ev = check(filename, _rds_data(item))
        assert len(hits) == 1 and ev["counts"]["insecure"] == 1
    assert item["monitoring_auth_baseline_status"] == "all_disabled"
    assert item["DatabaseInsightsMode"] == "standard"


def test_rds_partial_settings_and_unknown_never_false_positive():
    missing = classify_rds_instance_controls(_rds_instance(
        IAMDatabaseAuthenticationEnabled=None))
    assert missing["monitoring_auth_baseline_status"] == "unknown"
    hits, ev = check(P4A[5], _rds_data(missing))
    assert not hits and ev["counts"]["unknown"] == 1
    improved = classify_rds_instance_controls(_rds_instance(MonitoringInterval=60))
    assert improved["monitoring_auth_baseline_status"] == "not_all_disabled"
    hits, ev = check(P4A[5], _rds_data(improved))
    assert not hits and ev["counts"]["secure"] == 1
    unsupported = classify_rds_instance_controls(_rds_instance(Engine="sqlserver-ee"))
    assert unsupported["iam_db_auth_status"] == "not_applicable"
    cluster = classify_rds_instance_controls(_rds_instance(DBClusterIdentifier="cluster"))
    assert all(value == "not_applicable" for value in cluster.values())


def _ssm_data(status):
    return {"ssm": {"regions": {REGION: {
        "document_public_sharing_setting_status": status}}}}


def test_ssm_public_sharing_setting_distinct_from_public_document_inventory():
    facade = SSMPublicFacade(object())
    for aws_value, status in (("Enable", "enabled"), ("Disable", "blocked"),
                              ("Other", "unknown")):
        client = SimpleNamespace(get_service_setting=lambda **kw: {
            "ServiceSetting": {"SettingValue": aws_value}})
        with patch.object(AWSFacadeUtils, "get_client", return_value=client):
            observed = asyncio.run(facade.get_public_document_sharing_setting(REGION))
        assert observed == status
        hits, ev = check(P4A[6], _ssm_data(status))
        assert len(hits) == (1 if status == "enabled" else 0)
        assert ev["counts"][
            {"enabled": "insecure", "blocked": "secure", "unknown": "unknown"}[status]] == 1


def test_ssm_setting_access_denied_remains_unknown():
    client = SimpleNamespace(get_service_setting=lambda **kw: (
        _ for _ in ()).throw(PermissionError("denied")))
    facade = SSMPublicFacade(object())
    with patch.object(AWSFacadeUtils, "get_client", return_value=client):
        assert asyncio.run(facade.get_public_document_sharing_setting(REGION)) == "unknown"


def _ec2_data(status):
    return {"ec2": {"regions": {REGION: {"vpcs": {"vpc": {
        "instances": {"i1": {"detailed_monitoring_status": status}}}}}}}}


def test_ec2_detailed_monitoring_basic_detailed_stopped_and_incomplete():
    rows = [
        ({"State": {"Name": "running"}, "Monitoring": {"State": "disabled"}}, "basic"),
        ({"State": {"Name": "running"}, "Monitoring": {"State": "enabled"}}, "detailed"),
        ({"State": {"Name": "stopped"}, "Monitoring": {"State": "disabled"}}, "not_applicable"),
        ({"State": {"Name": "pending"}, "Monitoring": {"State": "disabled"}}, "unknown"),
        ({"State": {"Name": "running"}}, "unknown"),
    ]
    for raw, expected in rows:
        status = classify_detailed_monitoring(raw)
        assert status == expected
        hits, ev = check(P4A[7], _ec2_data(status))
        assert len(hits) == (1 if expected == "basic" else 0)
        assert ev["counts"][
            {"basic": "insecure", "detailed": "secure", "not_applicable": "not_applicable",
             "unknown": "unknown"}[expected]] == 1
