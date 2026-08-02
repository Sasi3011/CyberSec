# Internal worker - Windows Firewall bouncer (spawned by run.ps1 start)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))
$bouncerConfig = Join-Path $RepoRoot ".local\bouncer\bouncer.yaml"

function Read-BouncerConfig {
    param([string]$Path)
    $cfg = @{}
    Get-Content $Path | ForEach-Object {
        if ($_ -match '^\s*([^#:]+):\s*(.+)$') {
            $cfg[$Matches[1].Trim()] = $Matches[2].Trim()
        }
    }
    return $cfg
}

function Get-RuleName {
    param([string]$Prefix, [string]$Ip)
    $safe = $Ip -replace '[:./]', '-'
    return "$Prefix-$safe"
}

function Add-BlockedIp {
    param([string]$Ip, [string]$RulePrefix, [string[]]$Profiles)
    $name = Get-RuleName -Prefix $RulePrefix -Ip $Ip
    if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) { return }
    New-NetFirewallRule `
        -DisplayName $name `
        -Description "SasikiranSec ban for $Ip" `
        -Direction Inbound `
        -Action Block `
        -RemoteAddress $Ip `
        -Profile ($Profiles -join ',') `
        -Enabled True | Out-Null
}

function Remove-BlockedIp {
    param([string]$Ip, [string]$RulePrefix)
    $name = Get-RuleName -Prefix $RulePrefix -Ip $Ip
    if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $name
    }
}

function Get-DecisionStream {
    param([string]$Endpoint, [string]$ApiKey, [bool]$Startup)
    $uri = "$Endpoint/v1/decisions/stream?startup=$($Startup.ToString().ToLower())"
    return Invoke-RestMethod -Uri $uri -Headers @{ "X-Api-Key" = $ApiKey } -Method Get
}

function Test-BanDecision {
    param($Decision)
    if ($null -eq $Decision) { return $false }
    $scope = "$($Decision.scope)".ToLower()
    $type = "$($Decision.type)".ToLower()
    return ($scope -eq "ip" -and $type -eq "ban" -and $Decision.value)
}

$cfg = Read-BouncerConfig -Path $bouncerConfig
$apiKey = $cfg["api_key"]
$endpoint = $cfg["api_endpoint"].TrimEnd('/')
$interval = [int]$cfg["update_frequency"]
if ($interval -lt 5) { $interval = 10 }
$rulePrefix = if ($cfg["rule_prefix"]) { $cfg["rule_prefix"] } else { "SasikiranSec-Block" }
$profiles = @("domain", "private", "public")

$active = @{}
$startup = $true

while ($true) {
    try {
        $stream = Get-DecisionStream -Endpoint $endpoint -ApiKey $apiKey -Startup $startup
    }
    catch {
        Start-Sleep -Seconds $interval
        continue
    }

    if ($stream.new) {
        foreach ($d in $stream.new) {
            if (-not (Test-BanDecision $d)) { continue }
            $ip = "$($d.value)".Trim()
            if (-not $active.ContainsKey($ip)) { $active[$ip] = 0 }
            $active[$ip]++
            if ($active[$ip] -eq 1) {
                Add-BlockedIp -Ip $ip -RulePrefix $rulePrefix -Profiles $profiles
            }
        }
    }

    if ($stream.deleted) {
        foreach ($d in $stream.deleted) {
            if (-not (Test-BanDecision $d)) { continue }
            $ip = "$($d.value)".Trim()
            if (-not $active.ContainsKey($ip)) { continue }
            $active[$ip]--
            if ($active[$ip] -le 0) {
                $active.Remove($ip)
                Remove-BlockedIp -Ip $ip -RulePrefix $rulePrefix
            }
        }
    }

    $startup = $false
    Start-Sleep -Seconds $interval
}
