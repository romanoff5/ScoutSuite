#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Stable', 'Fork', 'ForkRc8', 'ForkRc7', 'ForkRc6', 'ForkRc5', 'ForkRc4', 'ForkRc3', 'ForkRc2', 'ForkRc1')][string]$Mode,
    [string]$ToolkitRoot = (Join-Path $HOME 'Documents\Security Tools\aws-audit-newclient-starter')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ToolkitRoot -PathType Container)) { throw "Missing toolkit root: $ToolkitRoot" }
$venvName = switch ($Mode) {
    'Stable' { '.venv-scout' }
    'Fork' { '.venv-scout-fork-rc9' }
    'ForkRc8' { '.venv-scout-fork-rc8' }
    'ForkRc7' { '.venv-scout-fork-rc7' }
    'ForkRc6' { '.venv-scout-fork-rc6' }
    'ForkRc5' { '.venv-scout-fork-rc5' }
    'ForkRc4' { '.venv-scout-fork-rc4' }
    'ForkRc3' { '.venv-scout-fork-rc3' }
    'ForkRc2' { '.venv-scout-fork-rc2' }
    'ForkRc1' { '.venv-scout-fork' }
}
$exe = Join-Path $ToolkitRoot (Join-Path $venvName 'Scripts\scout.exe')
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Scanner not installed: $exe" }
if ($Mode -ne 'Stable') {
    $recordPath = Join-Path $ToolkitRoot (Join-Path $venvName 'fork-install.json')
    if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) { throw 'Fork provenance record missing' }
    $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
    if ($record.repository -cne 'romanoff5/ScoutSuite' -or
        $record.version -cne $(switch ($Mode) {
            'Fork' { '5.14.0+romanoff5.m10rc9' }
            'ForkRc8' { '5.14.0+romanoff5.m10rc8' }
            'ForkRc7' { '5.14.0+romanoff5.m10rc7' }
            'ForkRc6' { '5.14.0+romanoff5.m10rc6' }
            'ForkRc5' { '5.14.0+romanoff5.m10rc5' }
            'ForkRc4' { '5.14.0+romanoff5.m10rc4' }
            'ForkRc3' { '5.14.0+romanoff5.m10rc3' }
            'ForkRc2' { '5.14.0+romanoff5.m10rc2' }
            'ForkRc1' { '5.14.0+romanoff5.m10rc1' }
        })) {
        throw 'Fork provenance identity mismatch'
    }
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
