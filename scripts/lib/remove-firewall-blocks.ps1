$count = 0
while ($true) {
    $batch = @(Get-NetFirewallRule -DisplayName "SasikiranSec-Block-*" -ErrorAction SilentlyContinue | Select-Object -First 100)
    if (-not $batch.Count) { break }
    $batch | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    $count += $batch.Count
    Write-Host "Removed $count..."
}
$left = (Get-NetFirewallRule -DisplayName "SasikiranSec-Block-*" -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Host "Total removed: $count | Remaining: $left"
