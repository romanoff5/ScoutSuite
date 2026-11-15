"""PwnedLabs regression: UNKNOWN/incomplete findings must never render as verified danger.

Uses synthetic rule objects only; no AWS credentials, identifiers or lab reports.
"""
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT / "ScoutSuite/output/data/inc-scoutsuite/helpers.js"
JS = ROOT / "ScoutSuite/output/data/inc-scoutsuite/scoutsuite.js"
DASHBOARD = ROOT / "ScoutSuite/output/data/html/partials/dashboard.html"
CSS = ROOT / "ScoutSuite/output/data/inc-scoutsuite/css/scoutsuite.css"


def test_dashboard_color_runs_with_denied_and_verified_findings():
    """Execute the *real* JS classifier on the synthetic states from the lab."""
    source = HELPERS.read_text(encoding="utf-8")
    start = source.index("function dashboardColor (")
    end = source.index("Handlebars.registerHelper('dashboard_color'", start)
    function = source[start:end]
    cases = [
        [["danger", 3, 3, "incomplete"], "incomplete"],  # denied CloudTrail
        [["warning", 3, 3, "incomplete"], "incomplete"],  # denied Config
        [["danger", 1, 1, "incomplete"], "incomplete"],  # denied IAM policy
        [["danger", 0, 1, "incomplete"], "incomplete"],  # legacy bad counts
        [["warning", 1, 0, "incomplete"], "incomplete disabled-link"],
        [["danger", 3, 3, None], "danger"],  # genuine observed finding
        [["warning", 3, 3, None], "warning"],
        [["danger", 0, 0, None], "unknown disabled-link"],
        [["danger", 3, 0, None], "good disabled-link"],
        [["danger", 3, 0, 4], "incomplete disabled-link"],
        [["review", 3, 0, "review"], "review disabled-link"],
    ]
    # Node ships with GitHub Actions and is already used to run repository JS;
    # failure to execute the contract should fail CI, not silently skip.
    node = shutil.which("node")
    assert node, "Node.js is required to verify the actual UI helper"
    program = ("'use strict';\nconst assert = require('node:assert/strict');\n"
               + function + "\nconst cases = " + json.dumps(cases) + ";\n"
               + "for (const [args, expected] of cases) "
               + "assert.equal(dashboardColor(...args), expected);\n")
    proc = subprocess.run([node, "-e", program], cwd=ROOT,
                          capture_output=True, text=True, timeout=15, check=False)
    assert proc.returncode == 0, proc.stderr


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
