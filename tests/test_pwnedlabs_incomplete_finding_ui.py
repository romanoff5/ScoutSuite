"""PwnedLabs regression: UNKNOWN/incomplete findings must never render as verified danger.

Uses synthetic rule objects only; no AWS credentials, identifiers or lab reports.
"""
from pathlib import Path

# Actual JS helper execution is gated by tools/verify_report_xss.py in its
# dedicated offline sandbox; pytest's M01 guard prohibits subprocess creation.

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT / "ScoutSuite/output/data/inc-scoutsuite/helpers.js"
JS = ROOT / "ScoutSuite/output/data/inc-scoutsuite/scoutsuite.js"
DASHBOARD = ROOT / "ScoutSuite/output/data/html/partials/dashboard.html"
CSS = ROOT / "ScoutSuite/output/data/inc-scoutsuite/css/scoutsuite.css"


def test_finding_header_exposes_unverified_state_without_hiding_details():
    html = DASHBOARD.read_text(encoding="utf-8")
    assert 'finding-title-{{dashboard_color level checked_items flagged_items assessment_status}}' in html
    assert 'finding-badge-{{dashboard_color level checked_items flagged_items assessment_status}}' in html
    assert '{{#ifEqual assessment_status "incomplete"}}' in html
    assert 'INCOMPLETE · UNVERIFIED' in html
    assert '{{confidence_assessment.confidence}}' in html
    assert '{{confidence_assessment.evidence_quality}}' in html
    assert '<li>Assessment status: {{assessment_status}}</li>' in html
    assert 'href="#services.{{../service_name}}.findings.{{key}}.items"' in html
    assert '.finding-title-incomplete' in CSS.read_text(encoding="utf-8")


def test_resource_highlighting_fails_closed_but_keeps_original_severity():
    code = JS.read_text(encoding="utf-8")
    start = code.index("function showFindings(")
    end = code.index("\n}", start)
    function = code[start:end]
    assert "let level = getValueAt(path.replace('items', 'level'))" in function
    assert "getValueAt(path.replace('items', 'assessment_status'))" in function
    assert "if (assessment === 'incomplete') level = 'incomplete'" in function
    assert "addClass('finding-' + level)" in function
    assert "removeClass('finding-incomplete')" in code
