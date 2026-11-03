#requires -Version 7.0
# Installs the fork scanner straight from verified origin/master; there are no release candidates.
[CmdletBinding(DefaultParameterSetName = 'Main')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Wheel')][string]$WheelPath,
    [Parameter(Mandatory, ParameterSetName = 'Wheel')][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$CommitSha,
    [Parameter(Mandatory, ParameterSetName = 'Wheel')][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
    [string]$RepoPath = (Split-Path -Parent $PSScriptRoot),
    [string]$ToolkitRoot = (Join-Path $HOME 'Documents\Security Tools\aws-audit-newclient-starter'),
    [string]$WheelhousePath,
    [string]$PythonCommand = 'py',
    [switch]$NoSelect
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = 'romanoff5/ScoutSuite'
$version = '5.14.0+romanoff5.main'
if (-not (Test-Path -LiteralPath $ToolkitRoot -PathType Container)) {
    throw "Toolkit root not found: $ToolkitRoot"
}

function New-Venv([string]$Path) {
    if ($PythonCommand -eq 'py') { & py -3.11 -m venv $Path } else { & $PythonCommand -m venv $Path }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $Path 'Scripts\python.exe') -PathType Leaf)) {
        throw "Failed to create isolated environment: $Path"
    }
}

function Select-Install([string]$Sha) {
    if (-not $NoSelect) { & (Join-Path $PSScriptRoot 'select-scanner.ps1') -Mode Fork -GitSha $Sha -ToolkitRoot $ToolkitRoot }
}

$temp = Join-Path ([IO.Path]::GetTempPath()) ('scout-fork-main-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
$venv = $null
$createdVenv = $false
$verifiedInstall = $false
try {
    if ($PSCmdlet.ParameterSetName -eq 'Main') {
        $remote = (git -C $RepoPath remote get-url origin).Trim()
        if ($LASTEXITCODE -ne 0 -or $remote -notmatch '^(https://github\.com/|git@github\.com:)romanoff5/ScoutSuite(\.git)?/?$') {
            throw "origin does not resolve to ${repo}: $remote"
        }
        git -C $RepoPath fetch --quiet origin master
        if ($LASTEXITCODE -ne 0) { throw 'git fetch origin master failed' }
        $CommitSha = (git -C $RepoPath rev-parse 'refs/remotes/origin/master^{commit}').Trim()
        $remoteSha = ((git -C $RepoPath ls-remote origin refs/heads/master) -split "`t")[0].Trim()
        if ($LASTEXITCODE -ne 0 -or $remoteSha -cne $CommitSha) { throw 'origin/master moved during install; retry' }
    }
    $CommitSha = $CommitSha.ToLowerInvariant()
    $venvName = '.venv-scout-fork-main-' + $CommitSha.Substring(0, 12)
    $venv = Join-Path $ToolkitRoot $venvName
    $scout = Join-Path $venv 'Scripts\scout.exe'
    $venvPython = Join-Path $venv 'Scripts\python.exe'
    if (Test-Path -LiteralPath $venv) {
        $existing = Join-Path $venv 'fork-install.json'
        if ((Test-Path -LiteralPath $existing -PathType Leaf) -and
            (Get-Content -LiteralPath $existing -Raw | ConvertFrom-Json).git_sha -ceq $CommitSha) {
            Write-Host "origin/master $CommitSha is already installed at: $venv"
            $venv = $null
            Select-Install $CommitSha
            return
        }
        throw "Environment exists without matching provenance: $venv. Refusing overwrite."
    }

    if ($PSCmdlet.ParameterSetName -eq 'Main') {
        # Only tracked files of the exact remote commit are built, never the working tree.
        $source = Join-Path $temp 'source'
        git -C $RepoPath archive --format=zip --output (Join-Path $temp 'source.zip') $CommitSha
        if ($LASTEXITCODE -ne 0) { throw 'git archive failed' }
        Expand-Archive -LiteralPath (Join-Path $temp 'source.zip') -DestinationPath $source
        $builder = Join-Path $temp 'build-venv'
        New-Venv $builder
        $builderPython = Join-Path $builder 'Scripts\python.exe'
        & $builderPython -m pip install --disable-pip-version-check -r (Join-Path $source 'constraints\build-py311.txt')
        if ($LASTEXITCODE -ne 0) { throw 'Pinned build frontend installation failed' }
        & $builderPython -m build --no-isolation --wheel --outdir (Join-Path $temp 'dist') $source
        if ($LASTEXITCODE -ne 0) { throw 'Wheel build failed' }
        $wheels = @(Get-ChildItem -LiteralPath (Join-Path $temp 'dist') -Filter '*.whl')
        if ($wheels.Count -ne 1) { throw 'Expected exactly one built wheel' }
        $WheelPath = $wheels[0].FullName
        $ExpectedSha256 = (Get-FileHash -LiteralPath $WheelPath -Algorithm SHA256).Hash
        $constraintsPath = Join-Path $source 'constraints\combined-py311.txt'
        $origin = "https://github.com/$repo/commit/$CommitSha"
    } else {
        $WheelPath = (Resolve-Path -LiteralPath $WheelPath -ErrorAction Stop).Path
        $constraintsPath = Join-Path $RepoPath 'constraints\combined-py311.txt'
        $origin = 'local-wheel'
    }
    $actualHash = (Get-FileHash -LiteralPath $WheelPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne $ExpectedSha256.ToLowerInvariant()) { throw 'Wheel SHA256 mismatch' }
    if ((Split-Path -Leaf $WheelPath) -ine "scoutsuite-$version-py3-none-any.whl") { throw 'Unexpected wheel filename' }
    $constraintsHash = (Get-FileHash -LiteralPath $constraintsPath -Algorithm SHA256).Hash.ToLowerInvariant()

    New-Venv $venv
    $createdVenv = $true
    if ($WheelhousePath) {
        $WheelhousePath = (Resolve-Path -LiteralPath $WheelhousePath -ErrorAction Stop).Path
        & $venvPython -m pip install --disable-pip-version-check --no-index --find-links $WheelhousePath -c $constraintsPath $WheelPath
    } else {
        & $venvPython -m pip install --disable-pip-version-check -c $constraintsPath $WheelPath
    }
    if ($LASTEXITCODE -ne 0) { throw 'Pinned wheel installation failed' }
    & $venvPython -m pip check
    if ($LASTEXITCODE -ne 0) { throw 'Dependency consistency check failed' }
    $actualVersion = (& $venvPython -I -c 'import importlib.metadata as m; print(m.version("ScoutSuite"))').Trim()
    if ($LASTEXITCODE -ne 0 -or $actualVersion -cne $version) { throw "Unexpected version: $actualVersion" }
    & $scout --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'scout --help failed' }
    & $scout aws --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'scout aws --help failed' }
    $exeHash = (Get-FileHash -LiteralPath $scout -Algorithm SHA256).Hash.ToLowerInvariant()
    $record = [ordered]@{
        repository = $repo; version = $version; channel = 'origin/master'; git_sha = $CommitSha
        wheel_sha256 = $actualHash; constraints_sha256 = $constraintsHash
        scout_exe_sha256 = $exeHash; origin = $origin
        installed_at_utc = [DateTime]::UtcNow.ToString('o'); executable = $scout
    }
    $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $venv 'fork-install.json') -Encoding utf8
    $verifiedInstall = $true
    Write-Host "Verified origin/master $CommitSha installed at: $scout (no AWS calls performed)"
    Select-Install $CommitSha
} finally {
    if ($createdVenv -and -not $verifiedInstall) {
        # This path was nonexistent before this invocation. Never remove earlier fork or stable environments.
        Remove-Item -LiteralPath $venv -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
