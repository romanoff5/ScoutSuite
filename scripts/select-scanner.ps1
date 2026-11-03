#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Stable', 'Fork', 'ForkRc9', 'ForkRc8', 'ForkRc7', 'ForkRc6', 'ForkRc5', 'ForkRc4', 'ForkRc3', 'ForkRc2', 'ForkRc1')][string]$Mode,
    # Fork only: a commit (prefix) of an installed origin/master build; the newest install when omitted.
    [ValidatePattern('^[0-9a-fA-F]{7,40}$')][string]$GitSha,
    [string]$ToolkitRoot = (Join-Path $HOME 'Documents\Security Tools\aws-audit-newclient-starter')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ToolkitRoot -PathType Container)) { throw "Missing toolkit root: $ToolkitRoot" }
if ($GitSha -and $Mode -ne 'Fork') { throw '-GitSha applies only to -Mode Fork' }
$selection = [ordered]@{ schema = 1; mode = $Mode.ToLowerInvariant() }
if ($Mode -eq 'Fork') {
    $candidates = foreach ($dir in Get-ChildItem -LiteralPath $ToolkitRoot -Directory -Force) {
        if ($dir.Name -cnotmatch '^\.venv-scout-fork-main-([0-9a-f]{12})$') { continue }
        $prefix = $Matches[1]
        $recordPath = Join-Path $dir.FullName 'fork-install.json'
        if (-not (Test-Path -LiteralPath (Join-Path $dir.FullName 'Scripts\scout.exe') -PathType Leaf) -or
            -not (Test-Path -LiteralPath $recordPath -PathType Leaf)) { continue }
        $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
        if ($record.repository -cne 'romanoff5/ScoutSuite' -or $record.version -cne '5.14.0+romanoff5.main' -or
            $record.git_sha -cnotmatch '^[0-9a-f]{40}$' -or -not $record.git_sha.StartsWith($prefix)) { continue }
        if ($GitSha -and -not $record.git_sha.StartsWith($GitSha.ToLowerInvariant())) { continue }
        [pscustomobject]@{ Venv = $dir.Name; GitSha = $record.git_sha; InstalledAt = [string]$record.installed_at_utc }
    }
    $chosen = @($candidates | Sort-Object InstalledAt -Descending)
    if (-not $chosen) { throw 'No verified origin/master install found; run install-fork.ps1' }
    $selection = [ordered]@{ schema = 2; mode = 'fork'; venv = $chosen[0].Venv; git_sha = $chosen[0].GitSha }
} else {
    $venvName = switch ($Mode) {
        'Stable' { '.venv-scout' }
        'ForkRc9' { '.venv-scout-fork-rc9' }
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
            $record.version -cne ('5.14.0+romanoff5.m10rc' + $Mode.Substring(6))) {
            throw 'Fork provenance identity mismatch'
        }
    }
}
$target = Join-Path $ToolkitRoot '.scout-scanner-selection.json'
$temp = Join-Path $ToolkitRoot ('.scout-selection-' + [guid]::NewGuid().ToString('N') + '.tmp')
try {
    ($selection | ConvertTo-Json) | Set-Content -LiteralPath $temp -Encoding utf8
    Move-Item -LiteralPath $temp -Destination $target -Force
} finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
}
$detail = if ($Mode -eq 'Fork') { " $($selection.git_sha) ($($selection.venv))" } else { '' }
Write-Host "Selected $Mode$detail at $target (no scan executed)."
