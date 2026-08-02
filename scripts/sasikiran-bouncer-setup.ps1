# SasikiranSec - Register Windows Firewall bouncer with Local API
# Creates API key and saves config to .local/bouncer/

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$configFile = Join-Path $RepoRoot ".local\sasikiran-local.yaml"
$cli = Join-Path $RepoRoot "bin\sscli.exe"
$bouncerDir = Join-Path $RepoRoot ".local\bouncer"
$bouncerConfig = Join-Path $bouncerDir "bouncer.yaml"
$bouncerName = "sasikiran-firewall-bouncer"

if (-not (Test-Path $cli)) {
    Write-Host "Build first: .\scripts\sasikiran-build.ps1"
    exit 1
}

if (-not (Test-Path $configFile)) {
    Write-Host "Setup first: .\scripts\sasikiran-setup.ps1"
    exit 1
}

$null = New-Item -ItemType Directory -Force -Path $bouncerDir

if (Test-Path $bouncerConfig) {
    Write-Host "Bouncer already configured: $bouncerConfig"
    Write-Host "Run: .\scripts\sasikiran-bouncer-run.ps1"
    exit 0
}

Write-Host "Registering firewall bouncer '$bouncerName' with Local API..."
$apiKey = (& $cli -c $configFile bouncers add $bouncerName -o raw).Trim()
if (-not $apiKey) {
    Write-Host "Failed to create bouncer API key."
    exit 1
}

$yaml = @"
# SasikiranSec Windows Firewall Bouncer
bouncer_name: $bouncerName
api_key: $apiKey
api_endpoint: http://127.0.0.1:8080
update_frequency: 10
rule_prefix: SasikiranSec-Block
fw_profiles:
  - domain
  - private
  - public
"@

Set-Content -Path $bouncerConfig -Value $yaml -Encoding UTF8

Write-Host ""
Write-Host "Firewall bouncer configured!"
Write-Host "  Config: $bouncerConfig"
Write-Host ""
Write-Host "Next (run PowerShell as Administrator):"
Write-Host "  .\scripts\sasikiran-bouncer-run.ps1"
Write-Host ""
