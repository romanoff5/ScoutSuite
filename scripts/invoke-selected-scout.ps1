#requires -Version 7.0
[CmdletBinding()]
param(
    [string]$ToolkitRoot = (Join-Path $HOME 'Documents\Security Tools\aws-audit-newclient-starter'),
    [Parameter(ValueFromRemainingArguments)][string[]]$ScoutArgs
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$selection = Join-Path $ToolkitRoot '.scout-scanner-selection.json'
$mode = 'stable'
if (Test-Path -LiteralPath $selection -PathType Leaf) {
    $configuration = Get-Content -LiteralPath $selection -Raw | ConvertFrom-Json
    if ($configuration.schema -ne 1 -or $configuration.mode -notin @('stable', 'fork')) {
        throw 'Invalid scanner selection config; refusing implicit fallback'
    }
    $mode = $configuration.mode
}
$venvName = if ($mode -eq 'fork') { '.venv-scout-fork' } else { '.venv-scout' }
$exe = Join-Path $ToolkitRoot (Join-Path $venvName 'Scripts\scout.exe')
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Scanner missing: $exe" }
if ($mode -eq 'fork' -and -not (Test-Path -LiteralPath (Join-Path $ToolkitRoot '.venv-scout-fork\fork-install.json'))) {
    throw 'Fork provenance missing; refusing launch'
}
# This wrapper is never invoked automatically; all arguments must be supplied explicitly.
& $exe @ScoutArgs
exit $LASTEXITCODE
