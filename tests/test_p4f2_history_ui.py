"""P4-F2 UI contract: real reports unchanged; locally imported scans stay local."""
import json
from pathlib import Path

from ScoutSuite.core.semantic_replay import ADAPTERS

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "ScoutSuite/output/data/inc-scoutsuite/scan_history.js"
HTML = ROOT / "ScoutSuite/output/data/html/report.html"
RULES = ROOT / "ScoutSuite/providers/aws/rules/findings"


def test_report_bundles_history_ui_without_altering_result_serialization():
    markup = HTML.read_text(encoding="utf-8")
    code = UI.read_text(encoding="utf-8")
    assert '<script src="inc-scoutsuite/scan_history.js"></script>' in markup
    for part in ('scout-history-toggle', 'scout-history-files', 'scout-history-rows',
                 'scout-history-semantic', 'scout-history-warning'):
        assert part in markup
    assert "file.text()" in code
    assert "textContent" in code
    assert "localStorage" not in code and "sessionStorage" not in code
    assert "fetch(" not in code and "eval(" not in code
    assert "innerHTML" not in code
    assert "scoutsuite_results" in code
    assert "HMAC" in code
    assert "runResults" in code


def test_ui_semantic_adapters_match_current_python_p4f2_rule_contract():
    source = UI.read_text(encoding="utf-8")
    assert len(ADAPTERS) == 5
    for key, adapter in ADAPTERS.items():
        definition = json.loads((RULES / (key + ".json")).read_text(encoding="utf-8"))
        assert definition["path"] == adapter.path
        condition = definition["conditions"]
        assert condition[0] == "and" and len(condition) == 2
        field, operator, expected = condition[1]
        assert operator == "equal" and field == adapter.field
        assert expected in adapter.allowed
        # UI has the same bounded rule/field/expected value.
        assert "'" + key + "'" in source
        assert "path: '" + adapter.path + "'" in source or "'" + adapter.path + "'," in source
        assert "target: '" + expected + "'" in source
