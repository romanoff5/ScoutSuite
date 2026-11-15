$ErrorActionPreference = 'Stop'
# Skip only eager .pyc generation: imports and installed CLI are still executed.
# pip honors PIP_NO_COMPILE, and dependency installation stays --no-index.
$env:PIP_NO_COMPILE = '1'
$root = Join-Path $env:RUNNER_TEMP ('scout-main-real-install-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
try {
  $wheel = @(Get-ChildItem -LiteralPath (Join-Path $env:SCOUT_CI_ROOT 'dist') -Filter '*romanoff5.main*.whl')
  if ($wheel.Count -ne 1) { throw 'Fork wheel missing from independently built CI dist' }
  $sha = (Get-FileHash -LiteralPath $wheel[0].FullName -Algorithm SHA256).Hash
  $commit = (git rev-parse HEAD).Trim()
  & ./scripts/install-fork.ps1 -WheelPath $wheel[0].FullName -CommitSha $commit `
    -ExpectedSha256 $sha -ToolkitRoot $root `
    -WheelhousePath (Join-Path $env:SCOUT_CI_ROOT 'wheelhouse') `
    -PythonCommand (Get-Command python).Source
  $venv = '.venv-scout-fork-main-' + $commit.Substring(0, 12)
  if (-not (Test-Path -LiteralPath (Join-Path $root "$venv/fork-install.json"))) {
    throw 'Verified installation provenance missing'
  }
  $config = Get-Content -LiteralPath (Join-Path $root '.scout-scanner-selection.json') -Raw | ConvertFrom-Json
  if ($config.venv -ne $venv) { throw 'Installer did not select the verified install' }
  & pwsh -NoProfile -File ./scripts/invoke-selected-scout.ps1 -ToolkitRoot $root --help | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Verified selected launcher help failed' }
  & pwsh -NoProfile -File ./scripts/invoke-selected-scout.ps1 -ToolkitRoot $root aws --help | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Verified AWS CLI help failed' }
} finally {
  Remove-Item -LiteralPath $root -Force -Recurse -ErrorAction SilentlyContinue
}
