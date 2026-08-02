#Requires -RunAsAdministrator
# CyberSec Agent — Windows Service installer
param(
    [string]$ManagerUrl = "http://localhost:8443",
    [string]$OrgApiKey = "cybersec_dev_org_key",
    [string]$LapiUrl = "http://127.0.0.1:8080",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$AgentDir = Join-Path $env:ProgramData "CyberSec\agent"
$null = New-Item -ItemType Directory -Force -Path $AgentDir

$exeSrc = Join-Path $RepoRoot "bin\cybersec-agent.exe"
if (-not (Test-Path $exeSrc)) {
    Push-Location (Join-Path $RepoRoot "enterprise\agent")
    go build -o $exeSrc ./cmd/agent
    Pop-Location
}

$exeDst = Join-Path $AgentDir "cybersec-agent.exe"
Copy-Item $exeSrc $exeDst -Force

$configPath = Join-Path $AgentDir "config.yaml"
$hostname = $env:COMPUTERNAME
$body = @{
    organization_api_key = $OrgApiKey
    hostname             = $hostname
    agent_version        = "1.0.0"
    department           = "Engineering"
    tags                 = @("windows", "demo")
} | ConvertTo-Json

$agentId = ""
$agentToken = ""
try {
    $reg = Invoke-RestMethod -Uri "$ManagerUrl/api/v1/agents/register" -Method Post -Body $body -ContentType "application/json"
    $agentId = $reg.agent_id
    $agentToken = $reg.agent_token
    Write-Host "Registered agent $agentId"
} catch {
    Write-Warning "Manager registration failed (start manager first): $($_.Exception.Message)"
}

@(
    "manager_url: $ManagerUrl",
    "org_api_key: $OrgApiKey",
    "agent_id: $agentId",
    "agent_token: $agentToken",
    "local_lapi_url: $LapiUrl",
    "lapi_key: local-dev",
    "lapi_password: devpassword",
    "heartbeat_interval_sec: 30",
    "queue_path: $(Join-Path $AgentDir 'queue.db')",
    "department: Engineering",
    "tags: [windows, demo]"
) | Set-Content $configPath -Encoding UTF8

if ($Uninstall) {
    & $exeDst stop 2>$null
    & $exeDst uninstall 2>$null
    Write-Host "CyberSec Agent service removed."
    exit 0
}

& $exeDst install
& $exeDst start

Write-Host @"

CyberSec Enterprise Agent installed.
  Directory: $AgentDir
  Config:    $configPath
  Service:   CyberSecAgent (running)

Local engine unchanged — scripts\run.ps1 start still works.

"@
