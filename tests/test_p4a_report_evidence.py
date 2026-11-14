"""P4-A: every new evidence field remains visible in escaped HTML details."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "ScoutSuite/output/data/html/partials/aws"
TEMPLATES = {
    "services.iam.security_contacts.html": ("security_contact_status",),
    "services.ssm.regions.html": ("document_public_sharing_setting_status",),
    "services.vpc.regions.id.vpcs.html": ("default_vpc_gateway_status",
                                           "default_vpc_igw_count", "default_vpc_eni_count"),
    "services.ec2.regions.id.vpcs.id.instances.html": ("detailed_monitoring_status",),
    "services.rds.regions.id.vpcs.id.instances.html": (
        "enhanced_monitoring_status", "detailed_query_metrics_status",
        "iam_db_auth_status", "monitoring_auth_baseline_status"),
}


def test_p4a_resource_details_show_status_and_do_not_use_raw_handlebars():
    for filename, fields in TEMPLATES.items():
        html = (ROOT / filename).read_text(encoding="utf-8")
        assert "{{{" not in html, filename
        for field in fields:
            assert "{{" + field + "}}" in html, (filename, field)


def test_contact_template_does_not_embed_contact_pii():
    html = (ROOT / "services.iam.security_contacts.html").read_text(encoding="utf-8")
    for sensitive in ("EmailAddress", "PhoneNumber", "Title", "{{EmailAddress}}"):
        assert sensitive not in html
