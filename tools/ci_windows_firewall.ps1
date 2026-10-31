param([Parameter(Mandatory = $true)][ValidateSet('Install', 'Remove')][string]$Mode)
$ErrorActionPreference = 'Stop'
$scoutRuleGroup = 'ScoutSuite offline CI'
if ($Mode -eq 'Remove') {
    Get-NetFirewallRule -Group $scoutRuleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $scoutState = Join-Path $env:SCOUT_CI_ROOT 'firewall-profiles.json'
    if (Test-Path -LiteralPath $scoutState) {
        foreach ($scoutProfile in (Get-Content -LiteralPath $scoutState -Raw | ConvertFrom-Json)) {
            Set-NetFirewallProfile -Name $scoutProfile.Name -Enabled $scoutProfile.Enabled
        }
    }
    exit 0
}
if (-not $env:GITHUB_ACTIONS -or -not $env:SCOUT_CI_ROOT) {
    throw 'Firewall setup is restricted to this disposable hosted CI job.'
}
Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json |
    Set-Content -LiteralPath (Join-Path $env:SCOUT_CI_ROOT 'firewall-profiles.json')
Set-NetFirewallProfile -All -Enabled True
if (@(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count -ne 0) {
    throw 'All firewall profiles must be enabled before offline CI.'
}
$scoutPrograms = @((Get-Command python).Source)
foreach ($scoutName in @('build', 'core', 'aws', 'test', 'wheel', 'sdist')) {
    $scoutPrograms += Join-Path $env:SCOUT_CI_ROOT "$scoutName/Scripts/python.exe"
}
foreach ($scoutProgram in $scoutPrograms) {
    New-NetFirewallRule -DisplayName "ScoutSuite offline $scoutProgram" -Group $scoutRuleGroup `
        -Direction Outbound -Action Block -Profile Any -Program $scoutProgram | Out-Null
}
$scoutRules = @(Get-NetFirewallRule -Group $scoutRuleGroup)
if ($scoutRules.Count -ne $scoutPrograms.Count -or
    @($scoutRules | Where-Object { $_.Enabled -ne 'True' -or $_.Action -ne 'Block' }).Count -ne 0) {
    throw 'Interpreter outbound-denial rules were not installed.'
}
Write-Output "Installed $($scoutRules.Count) interpreter outbound-denial rules."
