"""Task 14 fork release safety contracts, no network or real AWS scan."""
import ast
from pathlib import Path

from ScoutSuite import __version__


ROOT = Path(__file__).resolve().parents[1]
TAG = "fork-v5.14.0-m10-rc5"
VERSION = "5.14.0+romanoff5.m10rc5"


def test_unique_fork_version_and_manifest_generator_syntax():
    assert __version__ == VERSION
    path = ROOT / "tools/fork_release.py"
    ast.parse(path.read_text(encoding="utf-8"))
    source = path.read_text(encoding="utf-8")
    assert "romanoff5/ScoutSuite" in source
    assert "botocore" in source
    assert "SHA256SUMS" in source
    assert "CycloneDX" in source
    assert "git_sha" in source
    assert "partitions_validated_live" in source


def test_release_is_fork_scoped_and_ci_gated_not_automatic_client_scan():
    flow = (ROOT / ".github/workflows/fork-rc-release.yml").read_text(encoding="utf-8")
    for phrase in ("workflow_run", "conclusion == 'success'",
                   "head_branch == 'master'", "github.repository == 'romanoff5/ScoutSuite'",
                   "gh release create", "--prerelease", "--verify-tag",
                   "tools/verify_distribution.py", "python -m twine check"):
        assert phrase in flow
    for forbidden in ("pypi.org", "twine upload", "docker push",
                      "aws sts", "aws configure", "scout aws --profile"):
        assert forbidden not in flow.lower()
    assert "contents: write" in flow


def test_stable_venv_and_external_client_toolkit_are_never_mutated_by_install():
    install = (ROOT / "scripts/install-fork.ps1").read_text(encoding="utf-8")
    select = (ROOT / "scripts/select-scanner.ps1").read_text(encoding="utf-8")
    wrapper = (ROOT / "scripts/invoke-selected-scout.ps1").read_text(encoding="utf-8")
    assert ".venv-scout-fork" in install
    assert "SHA256SUMS" in install and "ExpectedSha256" in install
    assert "pip check" in install
    assert "scout.exe" in install
    assert "aws --help" in install
    assert "venv-scout-fork" in select and ".venv-scout" in select
    assert "Move-Item" in select
    assert "mode = 'stable'" in wrapper
    assert "Invalid scanner selection config" in wrapper
    for script in (install, select, wrapper):
        assert "C:\\Users\\Dzmitry" not in script
        assert "111789566859" not in script
    assert "if ($createdVenv -and -not $verifiedInstall)" in install
    assert "Remove-Item -LiteralPath $venv -Recurse -Force" in install
    assert "runtime-py311.constraints.txt" in install
    assert ".venv-scout-fork-rc5" in install
    assert "scout_exe_sha256" in install + wrapper
    assert "Get-FileHash" in wrapper
    assert "ForkRc1" in select and "ForkRc2" in select and "ForkRc3" in select and "ForkRc4" in select
    assert ".venv-scout-fork-rc5" in select + wrapper
    assert ".venv-scout-fork-rc4" in select + wrapper
    assert ".venv-scout-fork-rc3" in select + wrapper
    assert ".venv-scout-fork-rc2" in select + wrapper
    assert "5.14.0+romanoff5.m10rc5" in wrapper
    assert "5.14.0+romanoff5.m10rc4" in wrapper
    assert "5.14.0+romanoff5.m10rc3" in wrapper
    assert "5.14.0+romanoff5.m10rc2" in wrapper


def test_release_notes_explicitly_disclaim_unverified_controls_and_containers():
    note = (ROOT / "docs/releases" / (TAG + ".md")).read_text(encoding="utf-8")
    assert "No real client AWS scanning" in note
    assert "No container image" in note
    assert "Azure/GCP SDK modernization remains" in note
    assert "Stable .venv-scout untouched" in note
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    for entry in ("recursive-include scripts *.ps1",
                  "recursive-include docs/releases *.md",
                  "include tools/fork_release.py", "include tools/audit_scan_evidence.py"):
        assert entry in manifest


def test_rc5_release_pins_installable_dependency_closure_and_runtime_hotfix():
    flow = (ROOT / ".github/workflows/fork-rc-release.yml").read_text(encoding="utf-8")
    generator = (ROOT / "tools/fork_release.py").read_text(encoding="utf-8")
    assert "runtime-py311.constraints.txt" in flow
    assert "runtime_constraints_sha256" in generator
    assert "70cf29d5579864543b6363e7a271a84216bb6837" in flow
    assert "merge-base --is-ancestor" in flow
    assert "fork-v5.14.0-m10-rc5" in flow
    assert "fork-v5.14.0-m10-rc1" not in flow
    assert "No real client AWS scanning" in (ROOT / "docs/releases" / (TAG + ".md")).read_text(encoding="utf-8")


def test_ridgepay_has_explicit_non_mutating_preflight_and_rollback_instructions():
    note = (ROOT / "docs/releases/TASK14_INSTALL.md").read_text(encoding="utf-8")
    assert "aws sts get-caller-identity" in note
    assert "ForkRc1" in note and "ForkRc4" in note and "Stable" in note
    assert "PowerShell 7" in note
    assert "no-browser" in note
    assert "authorized" in note
