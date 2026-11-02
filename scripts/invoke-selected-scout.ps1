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
    if ($configuration.schema -ne 1 -or $configuration.mode -notin @('stable', 'fork', 'forkrc6', 'forkrc5', 'forkrc4', 'forkrc3', 'forkrc2', 'forkrc1')) {
        throw 'Invalid scanner selection config; refusing implicit fallback'
    }
    $mode = $configuration.mode
}
$venvName = switch ($mode) {
    'stable' { '.venv-scout' }
    'fork' { '.venv-scout-fork-rc7' }
    'forkrc6' { '.venv-scout-fork-rc6' }
    'forkrc5' { '.venv-scout-fork-rc5' }
    'forkrc4' { '.venv-scout-fork-rc4' }
    'forkrc3' { '.venv-scout-fork-rc3' }
    'forkrc2' { '.venv-scout-fork-rc2' }
    'forkrc1' { '.venv-scout-fork' }
}
$exe = Join-Path $ToolkitRoot (Join-Path $venvName 'Scripts\scout.exe')
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Scanner missing: $exe" }
if ($mode -ne 'stable') {
    $provenance = Join-Path $ToolkitRoot (Join-Path $venvName 'fork-install.json')
    if (-not (Test-Path -LiteralPath $provenance -PathType Leaf)) {
        throw 'Fork provenance missing; refusing launch'
    }
    $record = Get-Content -LiteralPath $provenance -Raw | ConvertFrom-Json
    $expectedVersion = switch ($mode) {
        'fork' { '5.14.0+romanoff5.m10rc7' }
        'forkrc6' { '5.14.0+romanoff5.m10rc6' }
        'forkrc5' { '5.14.0+romanoff5.m10rc5' }
        'forkrc4' { '5.14.0+romanoff5.m10rc4' }
        'forkrc3' { '5.14.0+romanoff5.m10rc3' }
        'forkrc2' { '5.14.0+romanoff5.m10rc2' }
        'forkrc1' { '5.14.0+romanoff5.m10rc1' }
    }
    if ($record.repository -cne 'romanoff5/ScoutSuite' -or $record.version -cne $expectedVersion -or
        $record.git_sha -notmatch '^[0-9a-f]{40}$' -or
        $record.wheel_sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Untrusted fork provenance; refusing launch'
    }
    if ($mode -in @('fork', 'forkrc6', 'forkrc5', 'forkrc4', 'forkrc3', 'forkrc2')) {
        if ($record.scout_exe_sha256 -notmatch '^[0-9a-f]{64}$' -or
            $record.constraints_sha256 -notmatch '^[0-9a-f]{64}$') {
            throw 'Fork integrity evidence missing'
        }
        $hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -cne $record.scout_exe_sha256) { throw 'Fork executable changed after verification' }
    }
    $python = Join-Path $ToolkitRoot (Join-Path $venvName 'Scripts\python.exe')
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Fork interpreter missing' }
    $actualVersion = (& $python -I -c 'import importlib.metadata as m; print(m.version("ScoutSuite"))').Trim()
    if ($LASTEXITCODE -ne 0 -or $actualVersion -cne $expectedVersion) {
        throw 'Fork installed version disagrees with provenance'
    }
}
# Credentials and targets are passed through only on an explicit invocation.
& $exe @ScoutArgs
exit $LASTEXITCODE
