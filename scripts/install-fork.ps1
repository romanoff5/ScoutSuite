#requires -Version 7.0
[CmdletBinding(DefaultParameterSetName = 'Local')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Local')][string]$WheelPath,
    [Parameter(Mandatory, ParameterSetName = 'Local')][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$CommitSha,
    [Parameter(Mandatory, ParameterSetName = 'Release')][switch]$FromRelease,
    [string]$ReleaseTag = 'fork-v5.14.0-m10-rc9',
    [string]$ToolkitRoot = (Join-Path $HOME 'Documents\Security Tools\aws-audit-newclient-starter'),
    [string]$ExpectedSha256,
    [string]$ConstraintsPath,
    [string]$WheelhousePath,
    [string]$PythonCommand = 'py'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = 'romanoff5/ScoutSuite'
$version = '5.14.0+romanoff5.m10rc9'
$venv = Join-Path $ToolkitRoot '.venv-scout-fork-rc9'
$scout = Join-Path $venv 'Scripts\scout.exe'
$venvPython = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $ToolkitRoot -PathType Container)) {
    throw "Toolkit root not found: $ToolkitRoot"
}
# Side-by-side RC9 installation cannot change the RC1/hotfix or stable scanner.
if (Test-Path -LiteralPath $venv) {
    throw "RC9 environment already exists: $venv. Refusing overwrite; inspect or select the existing install."
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ("scout-fork-rc9-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
$createdVenv = $false
$verifiedInstall = $false
try {
    $origin = 'local-wheel'
    if ($FromRelease) {
        if ($ReleaseTag -cne 'fork-v5.14.0-m10-rc9') { throw 'Only the pinned RC9 release is permitted.' }
        $base = "https://github.com/$repo/releases/download/$ReleaseTag"
        $sums = Join-Path $temp 'SHA256SUMS'
        Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sums
        $entries = @{}
        foreach ($line in (Get-Content -LiteralPath $sums)) {
            if ($line -notmatch '^([0-9a-fA-F]{64})  ([A-Za-z0-9._+~-]+)$') { throw 'Malformed SHA256SUMS' }
            if ($entries.ContainsKey($Matches[2])) { throw 'Duplicate checksum entry' }
            $entries[$Matches[2]] = $Matches[1].ToLowerInvariant()
        }
        $wheelName = 'scoutsuite-5.14.0+romanoff5.m10rc9-py3-none-any.whl'
        $constraintsName = 'runtime-py311.constraints.txt'
        foreach ($name in @($wheelName, 'manifest.json', $constraintsName)) {
            if (-not $entries.ContainsKey($name)) { throw "Missing release asset: $name" }
            Invoke-WebRequest -Uri ("$base/" + [uri]::EscapeDataString($name)) -OutFile (Join-Path $temp $name)
            $assetSha = (Get-FileHash -LiteralPath (Join-Path $temp $name) -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($assetSha -ne $entries[$name]) { throw "Release checksum mismatch: $name" }
        }
        $manifest = Get-Content -LiteralPath (Join-Path $temp 'manifest.json') -Raw | ConvertFrom-Json
        if ($manifest.repository -cne $repo -or $manifest.version -cne $version -or
            $manifest.tag -cne $ReleaseTag -or $manifest.wheel -cne $wheelName -or
            $manifest.wheel_sha256 -cne $entries[$wheelName] -or
            $manifest.runtime_constraints -cne $constraintsName -or
            $manifest.runtime_constraints_sha256 -cne $entries[$constraintsName] -or
            $manifest.git_sha -notmatch '^[0-9a-f]{40}$') {
            throw 'Release manifest/provenance mismatch'
        }
        $CommitSha = $manifest.git_sha
        $WheelPath = Join-Path $temp $wheelName
        $ConstraintsPath = Join-Path $temp $constraintsName
        $ExpectedSha256 = $entries[$wheelName]
        $origin = "https://github.com/$repo/releases/tag/$ReleaseTag"
    } else {
        if (-not $ExpectedSha256 -or $ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') {
            throw 'Local wheel requires an independently computed -ExpectedSha256.'
        }
        $WheelPath = (Resolve-Path -LiteralPath $WheelPath -ErrorAction Stop).Path
        if (-not $ConstraintsPath) {
            $ConstraintsPath = Join-Path $PSScriptRoot '..\constraints\combined-py311.txt'
        }
    }
    $ConstraintsPath = (Resolve-Path -LiteralPath $ConstraintsPath -ErrorAction Stop).Path
    $actualHash = (Get-FileHash -LiteralPath $WheelPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne $ExpectedSha256.ToLowerInvariant()) { throw 'Wheel SHA256 mismatch' }
    if ((Split-Path -Leaf $WheelPath) -cne 'scoutsuite-5.14.0+romanoff5.m10rc9-py3-none-any.whl') {
        throw 'Unexpected wheel filename'
    }
    $constraintsHash = (Get-FileHash -LiteralPath $ConstraintsPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($PythonCommand -eq 'py') {
        & py -3.11 -m venv $venv
    } else {
        & $PythonCommand -m venv $venv
    }
    $createdVenv = Test-Path -LiteralPath $venv -PathType Container
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
        throw 'Failed to create isolated RC9 environment'
    }
    if ($WheelhousePath) {
        $WheelhousePath = (Resolve-Path -LiteralPath $WheelhousePath -ErrorAction Stop).Path
        & $venvPython -m pip install --disable-pip-version-check --no-index --find-links $WheelhousePath -c $ConstraintsPath $WheelPath
    } else {
        & $venvPython -m pip install --disable-pip-version-check -c $ConstraintsPath $WheelPath
    }
    if ($LASTEXITCODE -ne 0) { throw 'Pinned RC9 wheel installation failed' }
    & $venvPython -m pip check
    if ($LASTEXITCODE -ne 0) { throw 'RC9 dependency consistency check failed' }
    $actualVersion = (& $venvPython -I -c 'import importlib.metadata as m; print(m.version("ScoutSuite"))').Trim()
    if ($LASTEXITCODE -ne 0 -or $actualVersion -cne $version) { throw "Unexpected version: $actualVersion" }
    & $scout --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'scout --help failed' }
    & $scout aws --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'scout aws --help failed' }
    $exeHash = (Get-FileHash -LiteralPath $scout -Algorithm SHA256).Hash.ToLowerInvariant()
    $record = [ordered]@{
        repository = $repo; version = $version; git_sha = $CommitSha.ToLowerInvariant()
        wheel_sha256 = $actualHash; constraints_sha256 = $constraintsHash
        scout_exe_sha256 = $exeHash; origin = $origin
        installed_at_utc = [DateTime]::UtcNow.ToString('o'); executable = $scout
    }
    $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $venv 'fork-install.json') -Encoding utf8
    $verifiedInstall = $true
    Write-Host "Verified RC9 installed at: $scout"
    Write-Host 'Scanner selection unchanged; no AWS calls performed.'
} finally {
    if ($createdVenv -and -not $verifiedInstall) {
        # This path was nonexistent before this invocation. Never remove RC1 or stable environments.
        Remove-Item -LiteralPath $venv -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
