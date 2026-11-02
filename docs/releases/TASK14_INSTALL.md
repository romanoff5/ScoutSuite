# Task 14: isolated install and rollback

Stable: <ToolkitRoot>\.venv-scout\Scripts\scout.exe (5.14.0)
Fork: <ToolkitRoot>\.venv-scout-fork\Scripts\scout.exe
Example root: $HOME\Documents\Security Tools\aws-audit-newclient-starter
Requires PowerShell 7+ and py -3.11 with venv/pip.
The fork CI also tests Python 3.14, but the helper defaults to 3.11.

## Install verified fork release

~~~powershell
$toolkit = Join-Path $HOME 'Documents\Security Tools\aws-audit-newclient-starter'
pwsh -File .\scripts\install-fork.ps1 -FromRelease -ReleaseTag fork-v5.14.0-m10-rc1 -ToolkitRoot $toolkit
~~~

Exact fork release and wheel pinned. Hashes of wheel and manifest verified
against SHA256SUMS, metadata repo/version/SHA checked, pip check and
scout --help / scout aws --help performed. Compare SHA256SUMS through an
independent trusted channel; hashes published with an asset are not signatures.

## Install locally built wheel

~~~powershell
$wheel = (Get-ChildItem .\dist\scoutsuite-5.14.0+romanoff5.m10rc1-*.whl | Select-Object -First 1).FullName
$hash = (Get-FileHash -LiteralPath $wheel -Algorithm SHA256).Hash
$commit = (git rev-parse HEAD)
pwsh -File .\scripts\install-fork.ps1 -WheelPath $wheel -CommitSha $commit -ExpectedSha256 $hash -ToolkitRoot $toolkit
~~~

The helper will not overwrite any preexisting fork venv; it records version,
git commit SHA, wheel SHA256 and origin in .venv-scout-fork\fork-install.json.
Stable .venv-scout is never upgraded/deleted.

## Explicit toolkit choice and one-change rollback

~~~powershell
pwsh -File .\scripts\select-scanner.ps1 -Mode Fork -ToolkitRoot $toolkit
pwsh -File .\scripts\select-scanner.ps1 -Mode Stable -ToolkitRoot $toolkit
~~~

Only .scout-scanner-selection.json changes (schema 1, mode fork/stable);
missing config defaults stable, invalid config refuses to execute.
Installation/selection executes NO client scan.

To make the current AWS Audit Toolkit honor this file, its owner must
consciously replace the existing hardcoded scout invocation ONCE with
scripts/invoke-selected-scout.ps1 and forward explicit ScoutArgs.
This external integration is NOT performed automatically by these scripts.
Until changed, the Toolkit continues to use its stable scanner regardless
of the config, as a deliberate safety boundary.

Manual safe smoke:

~~~powershell
& "$toolkit\.venv-scout\Scripts\scout.exe" --help
& "$toolkit\.venv-scout-fork\Scripts\scout.exe" aws --help
~~~

No client credentials or account details appear in committed scripts.
