#Requires -Version 5.1
<#
.SYNOPSIS
  Enroll a Windows endpoint into the CyberSec org fleet.

.EXAMPLE
  .\enroll-org.ps1 -ManagerUrl http://localhost:8443 -OrgKey cybersec_dev_org_key -Department Chennai
#>
param(
    [string]$ManagerUrl = "http://localhost:8443",
    [Parameter(Mandatory = $true)]
    [string]$OrgKey,
    [string]$Department = "Default",
    [switch]$InstallService
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentDir = Split-Path -Parent $ScriptDir
$RepoRoot = Split-Path -Parent (Split-Path -Parent $AgentDir)
$AgentExe = Join-Path $RepoRoot "bin\cybersec-agent.exe"

Write-Host "=== CyberSec Fleet Enroll ===" -ForegroundColor Cyan
Write-Host "Manager:    $ManagerUrl"
Write-Host "Department: $Department"
Write-Host ""

Push-Location $AgentDir
go build -o $AgentExe ./cmd/agent
Pop-Location

$configDir = Join-Path $env:ProgramData "CyberSec\agent"
$configPath = Join-Path $configDir "config.yaml"
$null = New-Item -ItemType Directory -Force -Path $configDir

@{
    manager_url = $ManagerUrl
    org_api_key = $OrgKey
    department  = $Department
    local_lapi_url = "http://127.0.0.1:8080"
} | ConvertTo-Json | Set-Content $configPath -Encoding UTF8

$env:CS_AGENT_CONFIG = $configPath
$env:CS_AGENT_ORG_API_KEY = $OrgKey
$env:CS_AGENT_MANAGER_URL = $ManagerUrl
$env:CS_AGENT_DEPARTMENT = $Department

if ($InstallService) {
    $install = Join-Path $AgentDir "install.ps1"
    & $install -ManagerUrl $ManagerUrl -OrgKey $OrgKey -Department $Department
    Write-Host "Agent service installed. Check Fleet on http://127.0.0.1:3001" -ForegroundColor Green
} else {
    Write-Host "Running agent in foreground (Ctrl+C to stop)..." -ForegroundColor Yellow
    Write-Host "Ensure local engine is running: .\scripts\run.ps1 start" -ForegroundColor Yellow
    & $AgentExe -foreground
}
