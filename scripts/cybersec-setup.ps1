# CyberSec - Local environment setup
# Creates .local/ config tree and installs hub collections

$ErrorActionPreference = "Continue"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RepoRoot

$base = Join-Path $RepoRoot ".local"
$dataDir = Join-Path $base "data"
$configDir = Join-Path $base "config"
$hubDir = Join-Path $configDir "hub"
$logDir = Join-Path $base "logs"
$pluginsDir = Join-Path $base "plugins"
$notifDir = Join-Path $configDir "notifications"
$configFile = Join-Path $base "cybersec-local.yaml"

$engine = Join-Path $RepoRoot "bin\cybersec.exe"
$cli = Join-Path $RepoRoot "bin\cybercli.exe"

if (-not (Test-Path $engine)) {
    Write-Host "Binaries not found. Running build first..."
    & "$RepoRoot\scripts\cybersec-build.ps1"
}

Write-Host "Creating local directories in $base..."
@($dataDir, $configDir, $hubDir, $logDir, $pluginsDir, $notifDir) | ForEach-Object {
    $null = New-Item -ItemType Directory -Force -Path $_
}

$sampleLog = Join-Path $logDir "sample.log"
$attackLog = Join-Path $logDir "attack.log"
New-Item -ItemType File -Path $attackLog -Force | Out-Null
if (Test-Path $sampleLog) { Set-Content -Path $sampleLog -Value "" -Encoding UTF8 }

Copy-Item "$RepoRoot\config\profiles.yaml" $configDir -Force
Copy-Item "$RepoRoot\config\simulation.yaml" $configDir -Force
Copy-Item "$RepoRoot\config\console.yaml" $configDir -Force
Copy-Item "$RepoRoot\config\acquis_local_dev.yaml" (Join-Path $configDir "acquis.yaml") -Force
$env:ATTACK_LOG = (Join-Path $logDir "attack.log").Replace('\', '/')
$acquisRaw = (Get-Content (Join-Path $configDir "acquis.yaml") -Raw)
$acquisRaw = $acquisRaw.Replace('%ATTACK_LOG%', $env:ATTACK_LOG)
$utf8 = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText((Join-Path $configDir "acquis.yaml"), $acquisRaw, $utf8)
Copy-Item -Recurse "$RepoRoot\config\patterns" $configDir -Force

if (-not (Test-Path "$configDir\local_api_credentials.yaml")) {
    New-Item -ItemType File "$configDir\local_api_credentials.yaml" | Out-Null
}
if (-not (Test-Path "$configDir\online_api_credentials.yaml")) {
    New-Item -ItemType File "$configDir\online_api_credentials.yaml" | Out-Null
}

$env:CONFIG_DIR = $configDir
$env:DATA_DIR = $dataDir
$env:PLUGINS_DIR = $pluginsDir
$env:USERNAME = $env:USERNAME

$raw = Get-Content "$RepoRoot\config\cybersec-local.yaml" -Raw
$expanded = [Environment]::ExpandEnvironmentVariables($raw)
# YAML treats backslash as escape; use forward slashes for Windows paths
$expanded = $expanded -replace '\\', '/'
$expanded | Set-Content $configFile -Encoding UTF8

Write-Host "Generating local API credentials..."
& $cli -c $configFile machines add local-dev -p devpassword -f "$configDir\local_api_credentials.yaml" --force 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Machine may already exist, continuing..."
}

Write-Host "Updating hub index (requires internet)..."
& $cli -c $configFile hub update
if ($LASTEXITCODE -ne 0) {
    Write-Host "Warning: hub update failed. Check your internet connection."
}

Write-Host "Installing base detection collection..."
& $cli -c $configFile collections install crowdsecurity/sshd --force 2>$null
& $cli -c $configFile parsers install crowdsecurity/syslog-logs --force 2>$null

Write-Host "Installing network attack demo detection..."
$demoDir = Join-Path $RepoRoot "config\demo"
Copy-Item (Join-Path $demoDir "cybersec-net-logs.yaml") (Join-Path $configDir "parsers\s01-parse\cybersec-net-logs.yaml") -Force
Copy-Item (Join-Path $demoDir "cybersec-net-flood.yaml") (Join-Path $configDir "scenarios\cybersec-net-flood.yaml") -Force

Write-Host ""
Write-Host "Setup complete!"
Write-Host "  Config: $configFile"
Write-Host "  Data:   $dataDir"
Write-Host ""
Write-Host "Run: .\scripts\run.ps1 start"
