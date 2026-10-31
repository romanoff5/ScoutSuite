# OpenCode handoff — 2026-10-31

Owner paused new implementation after Task 00 and integration. **M03/Task 03 is
not started.** Continue it only when the owner resumes development in OpenCode.

All accumulated work is integrated into `origin/master`; fork PRs #1, #2 and #3
are marked merged by GitHub. Task 00 implementation/integration snapshot is
`1a91b6811332a8c5b264341c0ff9b9189d4c7997`; the later documentation receipt
advances the final handoff head without changing implementation. Original topic
branches remain available for provenance/rollback. Working checkout is left on
`master`; the local GitHub CLI default is also `romanoff5/ScoutSuite`.

- Repository: `romanoff5/ScoutSuite`; default branch: `master`. `upstream`
  (`nccgroup/ScoutSuite`) is read-only. No upstream PR/push.
- Workflow: local changes, offline checks, commit/push to origin, integrate
  passing slices into default, verify remote SHAs. No mandatory PR, human review
  or per-task sign-off. Respect actual GitHub rules; no force-push/admin bypass.
- Read `AGENTS.md`, `MODERNIZATION_PROGRESS.md`, `docs/modernization/ROADMAP.md`
  and the local ignored `ScoutSuite_AWS_Codex_Tasks_Fork.md` before continuing.
- M01, M02-A and M02-B are implemented; reuse them. M02-B has verified Windows
  3.11.9 / Ubuntu 3.11.18 CI: 146 tests + 22 subtests, 161 visible warnings per
  OS, six CLI bodies, 31 fixtures, six dependency environments per OS, clean
  wheel/sdist smoke. Exact versions/logs are in `evidence/M02_B_RESULTS.json`.
- M02A-D01: Docker engine/build execution remains unverified. Previous engine
  start/registry-auth action was rejected by automatic approval review; do not
  circumvent it. This does not invalidate tested AWS/core packaging.
- Current limitations: 128 AWS / 80 Azure / 118 GCP rule keys untested; Python
  beyond 3.11, full browser coverage and real-cloud behavior not certified.
- Azure/GCP SDKs, collectors and security rules are frozen; shared changes need
  preservation smoke. Never use cloud credentials, customer data, cloud CLIs or
  live APIs in tests. Default pytest installs the M01 isolation guard.
- Stable scanner installations and unrelated workspaces were not changed.
  Do not install this fork over the stable scanner or run a real assessment.
- Both owner task markdown files are ignored by exact root names; keep them
  local. They are not included in commits or distributions.

Offline validation from an existing private environment (Windows example):

```powershell
& "$env:TEMP\scoutsuite-m02b\pipeline\test\Scripts\python.exe" -B -m pytest -q -p no:cacheprovider --tb=short --show-capture=no
```

If absent, acquire a fresh external environment following `tests/README.md` and
the M02-A constraints. Dependency acquisition is separate from guarded tests.
CI's `tools/ci.py` also builds/installs outside the checkout and enforces OS
network isolation on hosted runners. Never weaken the guard for a green run.

Local commit, pushed/default-branch snapshots and integration receipts are in
`MODERNIZATION_PROGRESS.md`; use `git ls-remote origin refs/heads/master` for the
current default SHA. Roll back with targeted reverts, preserving evidence and
stable installations; do not reset/force-push published history.
