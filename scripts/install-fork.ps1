#requires -Version 7.0
[CmdletBinding(DefaultParameterSetName = 'Local')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Local')][string]$WheelPath,
    [Parameter(Mandatory, ParameterSetName = 'Local')][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$CommitSha,
    [Parameter(Mandatory, ParameterSetName = 'Release')][switch]$FromRelease,
    [string]$ReleaseTag = 'fork-v5.14.0-m10-rc1',
    [string]$ToolkitRoot = (Join-Path $HOME 'Documents\Security Tools\aws-audit-newclient-starter'),
    [string]$ExpectedSha256,
    [string]$PythonCommand = 'py'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = 'romanoff5/ScoutSuite'
$version = '5.14.0+romanoff5.m10rc1'
$venv = Join-Path $ToolkitRoot '.venv-scout-fork'
$scout = Join-Path $venv 'Scripts\scout.exe'
$venvPython = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $ToolkitRoot -PathType Container)) {
    throw "Toolkit root not found: $ToolkitRoot. Create or select it explicitly; stable installation is untouched."
}
if (Test-Path -LiteralPath $venv) {
    throw "Fork venv already exists: $venv. Refusing to overwrite. The stable .venv-scout is never modified."
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ("scout-fork-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $origin = 'local-wheel'
    if ($FromRelease) {
        if ($ReleaseTag -ne 'fork-v5.14.0-m10-rc1') { throw 'This helper is pinned to its audited fork RC tag.' }
        $base = "https://github.com/$repo/releases/download/$ReleaseTag"
        $sums = Join-Path $temp 'SHA256SUMS'
        Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sums
        $entries = @{}
        foreach ($line in (Get-Content -LiteralPath $sums)) {
            if ($line -notmatch '^([0-9a-fA-F]{64})  ([A-Za-z0-9._+~-]+)$') { throw 'Malformed SHA256SUMS' }
            if ($entries.ContainsKey($Matches[2])) { throw 'Duplicate SHA256SUMS entry' }
            $entries[$Matches[2]] = $Matches[1].ToLowerInvariant()
        }
        $wheelNames = @($entries.Keys | Where-Object {
            $_ -match '^scoutsuite-5\.14\.0\+romanoff5\.m10rc1-py3-none-any\.whl$'
        })
        if ($wheelNames.Count -ne 1 -or -not $entries.ContainsKey('manifest.json')) {
            throw 'Expected wheel or manifest absent from release SHA256SUMS'
        }
        $wheelName = $wheelNames[0]
        $WheelPath = Join-Path $temp $wheelName
        $manifestPath = Join-Path $temp 'manifest.json'
        Invoke-WebRequest -Uri "$base/$wheelName" -OutFile $WheelPath
        Invoke-WebRequest -Uri "$base/manifest.json" -OutFile $manifestPath
        $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($manifestHash -ne $entries['manifest.json']) { throw 'Release manifest hash mismatch' }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ($manifest.repository -ne $repo -or $manifest.version -ne $version -or
            $manifest.tag -ne $ReleaseTag -or
            $manifest.git_sha -notmatch '^[0-9a-f]{40}$') { throw 'Invalid release provenance metadata' }
        $CommitSha = $manifest.git_sha
        $ExpectedSha256 = $entries[$wheelName]
        $origin = "https://github.com/$repo/releases/tag/$ReleaseTag"
    } else {
        $WheelPath = (Resolve-Path -LiteralPath $WheelPath).Path
    }
    $actualHash = (Get-FileHash -LiteralPath $WheelPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ExpectedSha256 -and ($actualHash -ne $ExpectedSha256.ToLowerInvariant())) {
        throw 'Wheel SHA256 mismatch; refusing installation'
    }
    if ((Split-Path -Leaf $WheelPath) -notmatch '^scoutsuite-5\.14\.0\+romanoff5\.m10rc1-py3-none-any\.whl$') {
        throw 'Wheel filename is not the pinned fork candidate'
    }
    if ($PythonCommand -eq 'py') {
        & py -3.11 -m venv $venv
    } else {
        & $PythonCommand -m venv $venv
    }
    if ($LASTEXITCODE -ne 0) { throw 'Failed to create isolated fork venv' }
    if (-not (Test-Path -LiteralPath $venvPython)) { throw 'Fork python missing' }
    & $venvPython -m pip install --disable-pip-version-check $WheelPath
    if ($LASTEXITCODE -ne 0) { throw 'Wheel installation failed' }
    & $venvPython -m pip check
    if ($LASTEXITCODE -ne 0) { throw 'Fork dependency consistency check failed' }
    $actualVersion = (& $venvPython -c 'import importlib.metadata as m; print(m.version("ScoutSuite"))').Trim()
    if ($LASTEXITCODE -ne 0 -or $actualVersion -ne $version) { throw "Unexpected installed version: $actualVersion" }
    & $scout --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'scout --help failed' }
    & $scout aws --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'scout aws --help failed' }
    $record = [ordered]@{
        repository = $repo; version = $version; git_sha = $CommitSha.ToLowerInvariant()
        wheel_sha256 = $actualHash; origin = $origin
        installed_at_utc = [DateTime]::UtcNow.ToString('o')
        executable = $scout
    }
    $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $venv 'fork-install.json') -Encoding utf8
    Write-Host "Fork installed only at: $scout"
    Write-Host 'Toolkit scanner selection remains unchanged (stable by default).'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
