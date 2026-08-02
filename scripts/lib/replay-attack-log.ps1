# Re-append attack.log lines so the engine tail picks them up after a late start
param([string]$LogPath)

if (-not $LogPath) {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))
    $LogPath = Join-Path $RepoRoot ".local\logs\attack.log"
}
if (-not (Test-Path $LogPath)) { Write-Host "No attack.log"; exit 0 }

$lines = Get-Content $LogPath | Where-Object { $_.Trim() }
if (-not $lines.Count) { Write-Host "attack.log empty"; exit 0 }

Add-Content -Path $LogPath -Value $lines -Encoding UTF8
Write-Host "Replayed $($lines.Count) attack log lines for engine ingestion"
