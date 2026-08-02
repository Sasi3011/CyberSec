$RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))
$attackPath = (Join-Path $RepoRoot ".local\logs\attack.log").Replace('\', '/')
$content = @"
# Real-time acquisition only - honeypot attack.log (no static sample data)
filenames:
  - $attackPath
labels:
  type: syslog
"@
$path = Join-Path $RepoRoot ".local\config\acquis.yaml"
$utf8 = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($path, $content, $utf8)
Write-Host "Wrote acquis.yaml without BOM"
