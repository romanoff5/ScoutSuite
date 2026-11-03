#requires -Version 7.0
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$ToolkitRoot = (Join-Path $HOME 'Documents\Security Tools\aws-audit-newclient-starter'),
    [Parameter(ValueFromRemainingArguments)][string[]]$ScoutArgs
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$selection = Join-Path $ToolkitRoot '.scout-scanner-selection.json'
$mode = 'stable'
$expectedSha = $null
if (Test-Path -LiteralPath $selection -PathType Leaf) {
    $configuration = Get-Content -LiteralPath $selection -Raw | ConvertFrom-Json
    if ($configuration.schema -eq 2 -and $configuration.mode -ceq 'fork' -and
        $configuration.venv -cmatch '^\.venv-scout-fork-main-[0-9a-f]{12}$' -and
        $configuration.git_sha -cmatch '^[0-9a-f]{40}$' -and $configuration.git_sha.StartsWith($configuration.venv.Substring(22))) {
        $mode = 'fork'
        $expectedSha = $configuration.git_sha
    } elseif ($configuration.schema -eq 1 -and $configuration.mode -in @('stable', 'fork', 'forkrc9', 'forkrc8', 'forkrc7', 'forkrc6', 'forkrc5', 'forkrc4', 'forkrc3', 'forkrc2', 'forkrc1')) {
        # Schema 1 'fork' was written while RC9 was the latest candidate.
        $mode = if ($configuration.mode -eq 'fork') { 'forkrc9' } else { $configuration.mode }
    } else {
        throw 'Invalid scanner selection config; refusing implicit fallback'
    }
}
$venvName = switch ($mode) {
    'stable' { '.venv-scout' }
    'fork' { $configuration.venv }
    'forkrc9' { '.venv-scout-fork-rc9' }
    'forkrc8' { '.venv-scout-fork-rc8' }
    'forkrc7' { '.venv-scout-fork-rc7' }
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
    $expectedVersion = if ($mode -eq 'fork') { '5.14.0+romanoff5.main' } else { '5.14.0+romanoff5.m10rc' + $mode.Substring(6) }
    if ($record.repository -cne 'romanoff5/ScoutSuite' -or $record.version -cne $expectedVersion -or
        $record.git_sha -notmatch '^[0-9a-f]{40}$' -or
        $record.wheel_sha256 -notmatch '^[0-9a-f]{64}$' -or
        ($expectedSha -and $record.git_sha -cne $expectedSha)) {
        throw 'Untrusted fork provenance; refusing launch'
    }
    if ($mode -ne 'forkrc1') {
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
