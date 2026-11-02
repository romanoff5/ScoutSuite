#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Stable', 'Fork')][string]$Mode,
    [string]$ToolkitRoot = (Join-Path $HOME 'Documents\Security Tools\aws-audit-newclient-starter')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ToolkitRoot -PathType Container)) { throw "Missing toolkit root: $ToolkitRoot" }
$venvName = if ($Mode -eq 'Fork') { '.venv-scout-fork' } else { '.venv-scout' }
$exe = Join-Path $ToolkitRoot (Join-Path $venvName 'Scripts\scout.exe')
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Scanner not installed: $exe" }
if ($Mode -eq 'Fork') {
    $record = Join-Path $ToolkitRoot '.venv-scout-fork\fork-install.json'
    if (-not (Test-Path -LiteralPath $record)) { throw 'Fork provenance record missing' }
}
$target = Join-Path $ToolkitRoot '.scout-scanner-selection.json'
$temp = Join-Path $ToolkitRoot ('.scout-selection-' + [guid]::NewGuid().ToString('N') + '.tmp')
try {
    ([ordered]@{ schema = 1; mode = $Mode.ToLowerInvariant() } | ConvertTo-Json) |
        Set-Content -LiteralPath $temp -Encoding utf8
    Move-Item -LiteralPath $temp -Destination $target -Force
} finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
}
Write-Host "Selected $Mode at $target (no scan executed)."
