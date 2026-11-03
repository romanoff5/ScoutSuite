"""Fork install safety contracts: install from verified origin/master, no release candidates, no network or AWS scan."""
from pathlib import Path

from ScoutSuite import __version__


ROOT = Path(__file__).resolve().parents[1]
VERSION = "5.14.0+romanoff5.main"
LEGACY_MODES = ("ForkRc1", "ForkRc2", "ForkRc3", "ForkRc4", "ForkRc5", "ForkRc6", "ForkRc7", "ForkRc8", "ForkRc9")


def scripts():
    return [(ROOT / "scripts" / name).read_text(encoding="utf-8")
            for name in ("install-fork.ps1", "select-scanner.ps1", "invoke-selected-scout.ps1")]


def test_fork_version_names_the_main_channel_not_a_release_candidate():
    assert __version__ == VERSION
    install, select, wrapper = scripts()
    assert VERSION in install and VERSION in select and VERSION in wrapper


def test_release_candidate_publication_is_removed():
    assert not (ROOT / ".github/workflows/fork-rc-release.yml").exists()
    assert not (ROOT / "tools/fork_release.py").exists()
    for flow in (ROOT / ".github/workflows").glob("*.yml"):
        text = flow.read_text(encoding="utf-8").lower()
        assert "contents: write" not in text
        for forbidden in ("gh release", "pypi.org", "twine upload", "docker push",
                          "aws sts", "aws configure", "scout aws --profile"):
            assert forbidden not in text, (flow.name, forbidden)


def test_installer_builds_only_the_verified_remote_master_commit():
    install, _, _ = scripts()
    assert "romanoff5/ScoutSuite" in install
    assert "fetch --quiet origin master" in install
    assert "ls-remote origin refs/heads/master" in install
    assert "origin/master moved during install" in install
    assert "archive --format=zip" in install  # Tracked files of that commit, never the working tree.
    assert "constraints\\build-py311.txt" in install and "build --no-isolation --wheel" in install
    assert "constraints\\combined-py311.txt" in install
    assert "Invoke-WebRequest" not in install
    assert "pip check" in install and "aws --help" in install
    assert "'.venv-scout-fork-main-' + $CommitSha.Substring(0, 12)" in install
    assert "Refusing overwrite" in install
    assert "if ($createdVenv -and -not $verifiedInstall)" in install
    assert "Remove-Item -LiteralPath $venv -Recurse -Force" in install
    assert "channel = 'origin/master'" in install and "scout_exe_sha256" in install


def test_selection_keeps_stable_and_every_rc_environment_for_rollback():
    install, select, wrapper = scripts()
    assert "select-scanner.ps1') -Mode Fork -GitSha" in install and "[switch]$NoSelect" in install
    assert all(mode in select for mode in LEGACY_MODES)
    for venv in (".venv-scout'", ".venv-scout-fork'", *(".venv-scout-fork-rc%d" % n for n in range(2, 10))):
        assert venv in select and venv in wrapper
    assert "'^\\.venv-scout-fork-main-([0-9a-f]{12})$'" in select
    assert "Sort-Object InstalledAt -Descending" in select
    assert "schema = 2" in select and "Move-Item" in select
    assert "'5.14.0+romanoff5.m10rc' + $mode.Substring(6)" in wrapper
    assert "mode = 'stable'" in wrapper and "Invalid scanner selection config" in wrapper
    assert "$record.git_sha -cne $expectedSha" in wrapper
    assert "Get-FileHash" in wrapper and "Fork executable changed after verification" in wrapper
    # Selections written while RC9 was current keep launching RC9.
    assert "if ($configuration.mode -eq 'fork') { 'forkrc9' }" in wrapper
    for script in (install, select, wrapper):
        assert "C:\\Users\\Dzmitry" not in script
        assert "111789566859" not in script and "640012953110" not in script


def test_ci_exercises_the_installer_and_fail_closed_selection_on_windows():
    flow = (ROOT / ".github/workflows/offline.yml").read_text(encoding="utf-8")
    assert "./scripts/install-fork.ps1 -WheelPath" in flow
    assert "'*romanoff5.main*.whl'" in flow
    assert "Selector did not pick the newest origin/master install" in flow
    assert "Modified fork executable was not rejected" in flow
    assert "Stable rollback selection failed" in flow


def test_packaging_ships_scripts_and_install_notes():
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    for entry in ("recursive-include scripts *.ps1", "recursive-include docs/releases *.md",
                  "include tools/audit_scan_evidence.py"):
        assert entry in manifest
    assert "fork_release" not in manifest


def test_install_notes_cover_preflight_rollback_and_authorization():
    note = (ROOT / "docs/releases/TASK14_INSTALL.md").read_text(encoding="utf-8")
    assert "origin/master" in note and "install-fork.ps1" in note
    assert "aws sts get-caller-identity" in note
    assert all(mode in note for mode in LEGACY_MODES) and "Stable" in note and "-GitSha" in note
    assert "PowerShell 7" in note
    assert "no-browser" in note
    assert "authorized" in note
    assert "Stable .venv-scout untouched" in note
