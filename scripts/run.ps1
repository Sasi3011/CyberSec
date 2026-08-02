# CyberSec - Single script for host and other device
#
# HOST (project folder):
#   .\scripts\run.ps1 setup
#   .\scripts\run.ps1 start
#   .\scripts\run.ps1 info
#   .\scripts\run.ps1 block 192.168.1.50
#   .\scripts\run.ps1 status
#   .\scripts\run.ps1 export
#   .\scripts\run.ps1 stop
#
# OTHER DEVICE (copy run.ps1 only):
#   .\run.ps1 attack -HostIp 172.17.11.200
#
# HOST (optional local test without second device):
#   .\scripts\run.ps1 simulate 203.0.113.99

param(
    [Parameter(Position = 0)]
    [ValidateSet("setup", "start", "stop", "clean", "info", "extern", "block", "status", "export", "attack", "simulate", "help")]
    [string]$Action = "help",

    [string]$HostIp,
    [Parameter(Position = 1)]
    [string]$Ip,
    [int]$TestPort = 9999,
    [int]$FloodCount = 20
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptName = Split-Path -Leaf $MyInvocation.MyCommand.Path
if (Test-Path (Join-Path (Split-Path $ScriptDir -Parent) "bin\cybersec.exe")) {
    $RepoRoot = Split-Path $ScriptDir -Parent
} elseif (Test-Path (Join-Path $ScriptDir "bin\cybersec.exe")) {
    $RepoRoot = $ScriptDir
} else {
    $RepoRoot = $null
}

$IsHost = ($null -ne $RepoRoot) -and (Test-Path (Join-Path $RepoRoot "bin\cybersec.exe"))

$LapiPort = 8080
$UiPort = 3000
$MetricsPort = 6060

if ($IsHost) {
    Set-Location $RepoRoot
    $configFile = Join-Path $RepoRoot ".local\cybersec-local.yaml"
    $engine = Join-Path $RepoRoot "bin\cybersec.exe"
    $cli = Join-Path $RepoRoot "bin\cybercli.exe"
    $bouncerConfig = Join-Path $RepoRoot ".local\bouncer\bouncer.yaml"
    $runDir = Join-Path $RepoRoot ".local\run"
    $pidFile = Join-Path $runDir "processes.json"
    $libDir = Join-Path $RepoRoot "scripts\lib"
    $attackLog = Join-Path $RepoRoot ".local\logs\attack.log"
}

$script:engineProc = $null
$script:bouncerProc = $null
$script:uiProc = $null
$script:testProc = $null

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-MyLanIp {
    param([string]$PreferSameSubnetAs)

    $virtualPatterns = 'vEthernet|Docker|WSL|Hyper-V|VirtualBox|VMware|Loopback|Teredo|isatap|Bluetooth|Npcap'

    $candidates = @()
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -notmatch '^127\.' -and
            $_.IPAddress -notmatch '^169\.254\.' -and
            $_.PrefixOrigin -ne 'WellKnown'
        } |
        ForEach-Object {
            $adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
            $desc = if ($adapter) { "$($adapter.Name) $($adapter.InterfaceDescription)" } else { "" }
            $isVirtual = $desc -match $virtualPatterns
            $candidates += [PSCustomObject]@{
                IP         = $_.IPAddress
                Virtual    = $isVirtual
                IsWifi     = $desc -match 'Wi-Fi|Wireless|802\.11|WLAN'
                IsEthernet = ($desc -match 'Ethernet' -and $desc -notmatch 'Virtual|vEthernet')
            }
        }

    if ($PreferSameSubnetAs -match '^(\d+\.\d+\.\d+)\.\d+$') {
        $subnet = $Matches[1]
        $sameSubnet = @($candidates | Where-Object { -not $_.Virtual -and $_.IP -like "$subnet.*" })
        if ($sameSubnet.Count -gt 0) {
            $pick = $sameSubnet | Where-Object IsWifi | Select-Object -First 1
            if (-not $pick) { $pick = $sameSubnet | Select-Object -First 1 }
            return $pick.IP
        }
    }

    $nonVirtual = @($candidates | Where-Object { -not $_.Virtual })
    if ($nonVirtual.Count -gt 0) {
        $pick = $nonVirtual | Where-Object IsWifi | Select-Object -First 1
        if (-not $pick) { $pick = $nonVirtual | Where-Object IsEthernet | Select-Object -First 1 }
        if (-not $pick) { $pick = $nonVirtual | Select-Object -First 1 }
        return $pick.IP
    }
    if ($candidates.Count -gt 0) { return $candidates[0].IP }
    return $null
}

function Get-PublicIp {
    $urls = @(
        "https://api.ipify.org",
        "https://ifconfig.me/ip"
    )
    foreach ($url in $urls) {
        try {
            $ip = (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 8).Content.Trim()
            if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') { return $ip }
        }
        catch { }
    }
    return $null
}

function Write-CrossNetworkFiles {
    param([string]$PublicIp, [string]$LanIp)
    $desktop = [Environment]::GetFolderPath("Desktop")
    $pub = if ($PublicIp) { $PublicIp } else { "YOUR_PUBLIC_IP" }
    $lan = if ($LanIp) { $LanIp } else { "YOUR_LAN_IP" }

    $guide = @"
CyberSec - Attack from MOBILE DATA (different network)
==========================================================

HOST must be running: .\scripts\run.ps1 start  (Admin, keep open)

STEP 1 - Router port forward (one time)
  External port:  $TestPort (TCP)
  Internal IP:    $lan
  Internal port:  $TestPort

STEP 2 - Your public IP (give to phone)
  $pub
  Refresh anytime: .\scripts\run.ps1 extern

STEP 3 - Phone on MOBILE DATA (turn OFF Wi-Fi)

  Option A - Termux (Android):
    pkg install netcat-openbsd
    for i in `$(seq 1 25); do nc -w2 $pub $TestPort </dev/null; done

  Option B - Copy mobile-flood.sh to phone (from repo scripts/):
    bash mobile-flood.sh $pub $TestPort 25

  Option C - Windows PC on another network:
    .\run.ps1 attack -HostIp $pub

Detection uses the phone's real carrier IP on the dashboard map.
"@
    $guidePath = Join-Path $desktop "CyberSec-CROSS-NETWORK.txt"
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($guidePath, $guide, $utf8)

    $mobileScript = Join-Path $RepoRoot "scripts\mobile-flood.sh"
    if (Test-Path $mobileScript) {
        Copy-Item $mobileScript (Join-Path $desktop "mobile-flood.sh") -Force
    }
    return $guidePath
}

function Show-Extern {
    if (-not $IsHost) {
        Write-Host "Run 'extern' on the host PC (inside the project folder)."
        exit 1
    }
    Write-Host ""
    Write-Host "=== Cross-Network Attack Setup ===" -ForegroundColor Cyan
    Write-Host ""
    $lanIp = Get-MyLanIp
    Write-Host "  Step 1: Port forward on your router" -ForegroundColor Yellow
    Write-Host "    External TCP port:  $TestPort"
    Write-Host "    Forward to laptop:  $(if ($lanIp) { "$lanIp`:$TestPort" } else { 'LAN_IP:9999' })"
    Write-Host ""
    Write-Host "  Step 2: Fetching public IP..." -ForegroundColor Yellow
    $publicIp = Get-PublicIp
    if ($publicIp) {
        Write-Host "    Public IP:  $publicIp" -ForegroundColor Green
    }
    else {
        Write-Host "    Public IP:  (offline - open https://ifconfig.me on laptop)" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "  Step 3: Phone attack (MOBILE DATA, Wi-Fi OFF)" -ForegroundColor Yellow
    if ($publicIp) {
        Write-Host "    Termux:  for i in `$(seq 1 25); do nc -w2 $publicIp $TestPort </dev/null; done"
        Write-Host "    Or:      .\run.ps1 attack -HostIp $publicIp  (from PC on other network)"
    }
    Write-Host ""
    Write-Host "  Honeypot listens on 0.0.0.0:$TestPort - any network works if port forward is set."
    Write-Host ""
    $path = Write-CrossNetworkFiles -PublicIp $publicIp -LanIp $lanIp
    Write-Host "  Saved guide: $path" -ForegroundColor Green
    Write-Host "  Saved script: $(Join-Path ([Environment]::GetFolderPath('Desktop')) 'mobile-flood.sh')"
    Write-Host ""
}

function Test-LooksLikeVirtualIp {
    param([string]$Ip)
    if (-not $Ip) { return $false }
    # Common Docker Desktop / WSL / Hyper-V default gateway-style addresses
    return $Ip -match '^172\.(1[7-9]|2[0-9]|3[0-1])\.0\.1$' -or $Ip -match '^172\.28\.'
}

function Test-PortOpen {
    param([int]$Port, [string]$Target = "127.0.0.1", [int]$TimeoutMs = 3000)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $ar = $client.BeginConnect($Target, $Port, $null, $null)
        $ok = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $ok) { $client.Close(); return $false }
        $client.EndConnect($ar)
        $client.Close()
        return $true
    }
    catch { return $false }
}

function Test-TcpConnect {
    param([string]$Target, [int]$Port, [int]$TimeoutMs = 3000)
    Test-PortOpen -Port $Port -Target $Target -TimeoutMs $TimeoutMs
}

function Test-TcpScan {
    param([string]$Target, [int]$Port)
    Test-PortOpen -Port $Port -Target $Target -TimeoutMs 500
}

function Get-ListenerPids {
    param([int]$Port)
    $pids = [System.Collections.Generic.HashSet[int]]::new()
    netstat -ano | ForEach-Object {
        $line = $_.ToString()
        if ($line -notmatch ":$Port\s") { return }
        if ($line -notmatch 'LISTENING\s+(\d+)\s*$') { return }
        $procId = [int]$Matches[1]
        if ($procId -gt 0) { [void]$pids.Add($procId) }
    }
    return @($pids)
}

function Stop-PortListeners {
    param([int]$Port, [string]$Label = "service")
    foreach ($procId in (Get-ListenerPids -Port $Port)) {
        try {
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
            Write-Host "  Stopped $Label (PID $procId, port $Port)"
        }
        catch { }
    }
    Start-Sleep -Milliseconds 300
}

$script:SimUsers = @("root","admin","administrator","user","test","guest","ubuntu","pi","oracle","deploy","attacker","scanner","bot","probe")

function Add-AttackLogLines {
    param(
        [string]$Path,
        [string]$SourceIp,
        [int]$Count = 8
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) {
        $null = New-Item -ItemType Directory -Force -Path $dir
    }
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    try {
        $sw = New-Object System.IO.StreamWriter($fs)
        for ($i = 1; $i -le $Count; $i++) {
            $user = $script:SimUsers[$i % $script:SimUsers.Count]
            $srcPort = Get-Random -Minimum 40000 -Maximum 65535
            $ts = (Get-Date).ToString("MMM dd HH':'mm':'ss", [System.Globalization.CultureInfo]::InvariantCulture)
            $sw.WriteLine("$ts localhost sshd[9999]: Failed password for invalid user $user from $SourceIp port $srcPort ssh2")
        }
        $sw.Flush()
    }
    finally {
        $fs.Close()
    }
}

function Do-RemoteAttack {
    if (-not $HostIp) {
        Write-Host "ERROR: -HostIp required"
        Write-Host "  Same Wi-Fi:       .\run.ps1 attack -HostIp 172.17.11.200"
        Write-Host "  Different network: .\run.ps1 attack -HostIp PUBLIC_IP  (host: run.ps1 extern)"
        exit 1
    }
    if ($HostIp -eq "127.0.0.1") {
        Write-Host "ERROR: Use host LAN IP, not 127.0.0.1"
        exit 1
    }

    $myIp = Get-MyLanIp -PreferSameSubnetAs $HostIp
    Clear-Host
    Write-Host ""
    Write-Host "  ===== CyberSec Remote ATTACK =====" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Your IP:   $(if ($myIp) { $myIp } else { 'unknown - run ipconfig' })" -ForegroundColor Yellow
    Write-Host "  Target:    $HostIp" -ForegroundColor Yellow
    if (Test-LooksLikeVirtualIp $myIp) {
        Write-Host "  WARNING: IP may be virtual (Docker/WSL). Use Wi-Fi IP from ipconfig if ban fails." -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  Simulating malicious activity (port scan + TCP flood)..." -ForegroundColor DarkYellow
    Write-Host ""

    $scanPorts = @(22, 80, 443, 3389, 8080, 9999)
    Write-Host "  [1/2] Port scan ($($scanPorts.Count) ports, 500ms timeout each)..." -ForegroundColor Cyan
    $openPorts = @()
    foreach ($p in $scanPorts) {
        Write-Host "        Probing port $p ..." -NoNewline
        if (Test-TcpScan -Target $HostIp -Port $p) {
            $openPorts += $p
            Write-Host " OPEN" -ForegroundColor Red
        } else {
            Write-Host " closed" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
    if ($openPorts.Count -gt 0) {
        Write-Host "  Open ports found: $($openPorts -join ', ')" -ForegroundColor Red
    }
    elseif ($openPorts.Count -eq 0) {
        Write-Host "  No open ports detected." -ForegroundColor DarkYellow
        Write-Host "  Same Wi-Fi? Use LAN IP from host: .\scripts\run.ps1 info" -ForegroundColor DarkYellow
        Write-Host "  Mobile data? Set router port forward TCP $TestPort, then use PUBLIC IP from: .\scripts\run.ps1 extern" -ForegroundColor DarkYellow
        Write-Host "  Continuing with flood anyway..." -ForegroundColor DarkYellow
    }

    Write-Host ""
    $FloodTotal = [Math]::Max($FloodCount, 30)
    Write-Host "  [2/2] TCP flood - $FloodTotal rapid connections to port $TestPort ..." -ForegroundColor Cyan
    $ok = 0
    for ($i = 1; $i -le $FloodTotal; $i++) {
        $hit = Test-TcpConnect -Target $HostIp -Port $TestPort -TimeoutMs 1500
        if ($hit) { $ok++ }
        if ($i % 5 -eq 0 -or $i -eq $FloodTotal) {
            $color = if ($hit) { "Green" } else { "Red" }
            Write-Host "        $i / $FloodTotal   reached=$ok" -ForegroundColor $color
        }
        Start-Sleep -Milliseconds 80
    }
    Write-Host ""
    if ($ok -eq 0) {
        Write-Host "  FLOOD FAILED - host down or already banned." -ForegroundColor Red
    } else {
        Write-Host "  $ok / $FloodTotal connections reached the honeypot." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "  ATTACK COMPLETE" -ForegroundColor Red
    Write-Host ""
    Write-Host "  On the HOST PC:" -ForegroundColor Green
    Write-Host "    1. Watch dashboard http://127.0.0.1:3000 (alert + ban appear in ~10-20 sec)"
    Write-Host "    2. Run: .\scripts\run.ps1 status"
    Write-Host "    3. Firewall bouncer blocks your IP automatically"
    Write-Host ""
    Write-Host "  Try connecting again - it should FAIL once banned."
    Write-Host ""
    exit 0
}

function Do-Simulate {
    Require-ValidIp -TargetIp $Ip
    if (-not (Test-Path $attackLog)) {
        $null = New-Item -ItemType File -Path $attackLog -Force
    }
    Write-Host ""
    Write-Host "Injecting SSH brute-force logs for $Ip - 8 events ..."
    Add-AttackLogLines -Path $attackLog -SourceIp $Ip -Count 8
    Write-Host "Injected. Engine should detect and ban within ~5-15 seconds."
    Write-Host ""
    Write-Host "  Dashboard: http://127.0.0.1:3000"
    Write-Host "  Metrics:   http://127.0.0.1:6060/metrics"
    Write-Host ""
    Write-Host "Waiting 10 seconds then showing status..."
    Start-Sleep -Seconds 10
    Do-Status
}

if (-not $IsHost) {
    if ($Action -eq "attack") { Do-RemoteAttack }
    Write-Host ""
    Write-Host "Remote attacker mode: copy run.ps1 from host (run export on host PC)."
    Write-Host ""
    Write-Host "  .\run.ps1 attack -HostIp HOST_LAN_IP"
    Write-Host ""
    Write-Host "  Full guide: ATTACK-DEMO.md"
    Write-Host ""
    exit 0
}

function Show-Help {
    Write-Host ""
    Write-Host "  CyberSec - run.ps1" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  .\scripts\run.ps1 setup              First-time build and config"
    Write-Host "  .\scripts\run.ps1 start              Start all (Admin, keep open)"
    Write-Host "  .\scripts\run.ps1 info               LAN IP (same Wi-Fi attack)"
    Write-Host "  .\scripts\run.ps1 extern             Public IP + phone attack setup"
    Write-Host "  .\scripts\run.ps1 block 1.2.3.4      Block attacker IP"
    Write-Host "  .\scripts\run.ps1 status             Bans and firewall rules"
    Write-Host "  .\scripts\run.ps1 simulate 1.2.3.4   Inject test attack (no 2nd device)"
    Write-Host "  .\scripts\run.ps1 export             Copy run.ps1 to Desktop"
    Write-Host "  .\scripts\run.ps1 stop               Stop all services"
    Write-Host "  .\scripts\run.ps1 clean              Unblock all, wipe DB, fresh start"
    Write-Host ""
    Write-Host "  Same Wi-Fi:    .\run.ps1 attack -HostIp LAN_IP"
    Write-Host "  Other network: .\run.ps1 attack -HostIp PUBLIC_IP  (see: run.ps1 extern)"
    Write-Host "  Metrics:       http://127.0.0.1:6060/metrics"
    Write-Host "  Full guide:    ATTACK-DEMO.md"
    Write-Host ""
}

function Show-Info {
    Write-Host ""
    Write-Host "  Same Wi-Fi (LAN IP for other device on your network):" -ForegroundColor Yellow
    $ip = Get-MyLanIp
    if ($ip) { Write-Host "    $ip" -ForegroundColor Green }
    else { Write-Host "    (not found)" -ForegroundColor Red }
    Write-Host ""
    Write-Host "  Different network (mobile data / other Wi-Fi):" -ForegroundColor Yellow
    Write-Host "    Run: .\scripts\run.ps1 extern"
    Write-Host "    (needs router port forward TCP $TestPort -> laptop)"
    Write-Host ""
    Write-Host "  Dashboard:  http://127.0.0.1:$UiPort"
    Write-Host "  Metrics:    http://127.0.0.1:$MetricsPort/metrics"
    Write-Host "  Test port:  $TestPort (honeypot)"
    Write-Host ""
}

function Do-Setup {
    Write-Host "=== CyberSec Setup ==="
    & (Join-Path $RepoRoot "scripts\cybersec-build.ps1")
    & (Join-Path $RepoRoot "scripts\cybersec-setup.ps1")
    if (-not (Test-Path $bouncerConfig)) {
        & (Join-Path $RepoRoot "scripts\cybersec-bouncer-setup.ps1")
    }
    Write-Host ""
    Write-Host "Setup complete. Run: .\scripts\run.ps1 start"
}

function Require-ValidIp {
    param([string]$TargetIp)
    if (-not $TargetIp) {
        Write-Host "ERROR: IP required. Example: .\scripts\run.ps1 block 192.168.1.50"
        exit 1
    }
    if ($TargetIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        Write-Host "ERROR: Invalid IP '$TargetIp'. Use real IP from other device BEFORE test."
        exit 1
    }
}

function Do-Block {
    Require-ValidIp -TargetIp $Ip
    Write-Host "Blocking $Ip ..."
    & $cli -c $configFile decisions add --ip $Ip -d 4h -R "cybersec/demo" -t ban
    if ($LASTEXITCODE -ne 0) { exit 1 }
    Write-Host "Ban added. Wait 15 seconds, then AFTER test on other device."
    Start-Sleep -Seconds 2
    Do-Status
}

function Do-Status {
    Show-Info
    Write-Host "  --- Ban decisions ---" -ForegroundColor Cyan
    & $cli -c $configFile decisions list 2>$null
    Write-Host ""
    Write-Host "  --- Firewall rules ---" -ForegroundColor Cyan
    $rules = Get-NetFirewallRule -DisplayName "CyberSec-Block-*" -ErrorAction SilentlyContinue
    if ($rules) {
        foreach ($r in $rules) {
            $a = (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue).RemoteAddress
            Write-Host ("    " + $r.DisplayName + " -> " + ($a -join ", "))
        }
    } else {
        Write-Host "    (none - is run.ps1 start running as Admin?)"
    }
    Write-Host ""
}

function Do-Export {
    $dest = Join-Path ([Environment]::GetFolderPath("Desktop")) "run.ps1"
    Copy-Item $PSCommandPath $dest -Force
    Write-Host ""
    Write-Host "Copied to: $dest"
    Write-Host "Send this ONE file to the other device."
    Write-Host ""
    $ip = Get-MyLanIp
    if ($ip) {
        Write-Host "Same Wi-Fi attack:"
        Write-Host "  .\run.ps1 attack -HostIp $ip"
    }
    Write-Host ""
    Write-Host "Different network (mobile data): run on HOST first:"
    Write-Host "  .\scripts\run.ps1 extern"
    Write-Host ""
}

function Wait-PortReady {
    param([int]$Port, [int]$TimeoutSec = 45, [string]$Name)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-PortOpen -Port $Port) { return }
        Start-Sleep -Milliseconds 400
    }
    throw "$Name did not start on port $Port"
}

function Test-LapiHealthy {
    if (-not (Test-Path $cli)) { return $false }
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $cli -c $configFile metrics 2>&1 | Out-Null
    $ok = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $prevEap
    return $ok
}

function Start-EngineProcess {
    param([string[]]$ExtraArgs = @())
    $null = New-Item -ItemType Directory -Force -Path $runDir
    $engineLog = Join-Path $runDir "engine.log"
    $engineErr = Join-Path $runDir "engine.err.log"
    $argList = @("-c", $configFile, "-no-capi", "-info") + $ExtraArgs
    return Start-Process `
        -FilePath $engine `
        -ArgumentList $argList `
        -WorkingDirectory $RepoRoot `
        -RedirectStandardOutput $engineLog `
        -RedirectStandardError $engineErr `
        -PassThru -WindowStyle Hidden
}

function Test-NeedsBootstrap {
    $db = Join-Path $RepoRoot ".local\data\cybersec.db"
    return -not (Test-Path $db)
}

function Invoke-SscliQuiet {
    param([string[]]$CmdArgs)
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $cli -c $configFile @CmdArgs 2>&1 | Out-Null
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    return $code
}

function Bootstrap-LapiMachine {
    Write-Host "  Fresh database - bootstrapping local-dev credentials..."
    Stop-PortListeners -Port $LapiPort -Label "bootstrap"
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $RepoRoot ".local\data")
    $bootstrapProc = Start-EngineProcess -ExtraArgs @("-no-cs")
    try {
        Wait-PortReady -Port $LapiPort -Name "Bootstrap LAPI" -TimeoutSec 60
        Start-Sleep -Seconds 2
        $configDir = Join-Path $RepoRoot ".local\config"
        $credFile = Join-Path $configDir "local_api_credentials.yaml"
        $exitCode = Invoke-SscliQuiet -CmdArgs @("machines", "add", "local-dev", "-p", "devpassword", "-f", $credFile, "--force")
        if ($exitCode -ne 0) { throw "Failed to register local-dev machine (exit $exitCode)" }
        Write-Host "  Registered local-dev machine"
    }
    finally {
        if ($bootstrapProc -and -not $bootstrapProc.HasExited) {
            Stop-Process -Id $bootstrapProc.Id -Force -ErrorAction SilentlyContinue
        }
        Stop-PortListeners -Port $LapiPort -Label "bootstrap"
        Start-Sleep -Milliseconds 800
    }
}

function Ensure-EngineRunning {
    if ($script:engineProc -and -not $script:engineProc.HasExited -and (Test-PortOpen $LapiPort) -and (Test-LapiHealthy)) {
        return
    }
    Write-Host "  (Re)starting backend..."
    if ($script:engineProc -and -not $script:engineProc.HasExited) {
        Stop-Process -Id $script:engineProc.Id -Force -ErrorAction SilentlyContinue
    }
    Stop-PortListeners -Port $LapiPort -Label "backend"
    & (Join-Path $libDir "fix-acquis.ps1") | Out-Null
    if (Test-NeedsBootstrap) {
        Bootstrap-LapiMachine
    }
    $script:engineProc = Start-EngineProcess
    Wait-PortReady -Port $LapiPort -Name "Backend"
    if ($script:engineProc.HasExited) {
        $errLog = Join-Path $runDir "engine.err.log"
        if (Test-Path $errLog) { Get-Content $errLog -Tail 12 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red } }
        throw "Engine exited. See .local\run\engine.err.log"
    }
    $deadline = (Get-Date).AddSeconds(45)
    while ((Get-Date) -lt $deadline) {
        if ($script:engineProc.HasExited) {
            $errLog = Join-Path $runDir "engine.err.log"
            if (Test-Path $errLog) { Get-Content $errLog -Tail 12 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red } }
            throw "Engine crashed (machine not found?). Run: .\scripts\run.ps1 clean then start"
        }
        if (Test-LapiHealthy) {
            & (Join-Path $libDir "replay-attack-log.ps1") | Out-Null
            return
        }
        Start-Sleep -Milliseconds 500
    }
    throw "API not responding on port $LapiPort"
}

function Save-ProcessIds {
    $data = @{
        engine  = if ($script:engineProc) { $script:engineProc.Id } else { 0 }
        bouncer = if ($script:bouncerProc) { $script:bouncerProc.Id } else { 0 }
        ui      = if ($script:uiProc) { $script:uiProc.Id } else { 0 }
        test    = if ($script:testProc) { $script:testProc.Id } else { 0 }
        started = (Get-Date).ToString("o")
    }
    $null = New-Item -ItemType Directory -Force -Path $runDir
    $data | ConvertTo-Json | Set-Content $pidFile -Encoding UTF8
}

function Stop-AllServices {
    Write-Host "Stopping CyberSec..."

    if (Test-Path $pidFile) {
        try {
            $saved = Get-Content $pidFile -Raw | ConvertFrom-Json
            foreach ($name in @("test", "ui", "bouncer", "engine")) {
                $id = [int]$saved.$name
                if ($id -gt 0) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }
            }
        }
        catch { }
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    }

    foreach ($proc in @($script:testProc, $script:uiProc, $script:bouncerProc, $script:engineProc)) {
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }

    Get-Process -Name "cybersec" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    foreach ($port in @($TestPort, $UiPort, $LapiPort, $MetricsPort)) {
        Stop-PortListeners -Port $port
    }
    Write-Host "Stopped."
}

function Ensure-Prerequisites {
    if (-not (Test-Path $engine)) {
        & (Join-Path $RepoRoot "scripts\cybersec-build.ps1")
    }
    if (-not (Test-Path $configFile)) {
        & (Join-Path $RepoRoot "scripts\cybersec-setup.ps1")
    }
    if (-not (Test-Path $bouncerConfig)) {
        & (Join-Path $RepoRoot "scripts\cybersec-bouncer-setup.ps1")
    }
}

function Remove-AllFirewallBlocks {
    if (-not (Test-IsAdmin)) {
        Write-Host "  Skipping firewall cleanup (not Admin)"
        return 0
    }
    $count = 0
    while ($true) {
        $batch = @(Get-NetFirewallRule -DisplayName "CyberSec-Block-*" -ErrorAction SilentlyContinue | Select-Object -First 100)
        if (-not $batch.Count) { break }
        $batch | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        $count += $batch.Count
        if ($count % 100 -eq 0) { Write-Host "  Removed $count firewall rules..." }
    }
    return $count
}

function Update-AcquisRealtimeOnly {
    & (Join-Path $libDir "fix-acquis.ps1") | Out-Null
}

function Do-Clean {
    if (-not (Test-IsAdmin)) {
        Write-Host "Administrator required (removes firewall block rules)."
        Start-Process powershell -Verb RunAs `
            -ArgumentList "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" clean" `
            -WorkingDirectory $RepoRoot
        exit 0
    }

    Write-Host ""
    Write-Host "=== CyberSec CLEAN RESET ===" -ForegroundColor Yellow
    Write-Host ""

    Stop-AllServices

    $dataDir = Join-Path $RepoRoot ".local\data"
    $logDir = Join-Path $RepoRoot ".local\logs"
    $uiDataDir = Join-Path $RepoRoot ".local\cybersec-web-ui\data"

    if (Test-Path $dataDir) {
        Remove-Item $dataDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    $null = New-Item -ItemType Directory -Force -Path $dataDir
    Write-Host "  Wiped engine database (fresh folder)"

    if (Test-Path $uiDataDir) {
        Get-ChildItem $uiDataDir -Filter "*.db*" -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            Write-Host "  Deleted UI $($_.Name)"
        }
    }

    $null = New-Item -ItemType Directory -Force -Path $logDir
    Set-Content -Path $attackLog -Value "" -Encoding UTF8
    Write-Host "  Cleared attack.log (real-time honeypot only)"

    $sampleLog = Join-Path $logDir "sample.log"
    if (Test-Path $sampleLog) {
        Set-Content -Path $sampleLog -Value "" -Encoding UTF8
        Write-Host "  Cleared sample.log (removed from engine ingestion)"
    }

    Update-AcquisRealtimeOnly
    Write-Host "  Acquisition: attack.log only (no static demo logs)"

    if (Test-NeedsBootstrap) {
        Write-Host "  Database empty - credentials will be registered on next start"
    }

    $removed = Remove-AllFirewallBlocks
    Write-Host "  Removed $removed firewall block rule(s)"

    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host "  CLEAN COMPLETE - fresh empty database" -ForegroundColor Green
    Write-Host "=========================================="
    Write-Host "  All IPs unblocked | All alerts/bans cleared"
    Write-Host "  Only real attacks (honeypot port $TestPort) will appear"
    Write-Host ""
    Write-Host "  Next: .\scripts\run.ps1 start"
    Write-Host "=========================================="
    Write-Host ""
}

function Do-Start {
    if (-not (Test-IsAdmin)) {
        Write-Host "Administrator required. Opening elevated window..."
        Write-Host "Keep that window OPEN during the demo."
        Start-Process powershell -Verb RunAs `
            -ArgumentList "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" start" `
            -WorkingDirectory $RepoRoot
        exit 0
    }

    try {
        Write-Host ""
        Write-Host "=== CyberSec Starting ==="
        Write-Host ""

        Stop-AllServices
        Ensure-Prerequisites

        Write-Host "Starting backend..."
        Ensure-EngineRunning
        Write-Host "  Backend ready (PID $($script:engineProc.Id))"

        $bouncerScript = Join-Path $libDir "bouncer-worker.ps1"
        Write-Host "Starting firewall bouncer..."
        $script:bouncerProc = Start-Process powershell.exe `
            -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", $bouncerScript) `
            -WorkingDirectory $RepoRoot -PassThru -WindowStyle Hidden
        Write-Host "  Bouncer ready (PID $($script:bouncerProc.Id))"

        $uiScript = Join-Path $libDir "ui-server.ps1"
        Write-Host "Starting dashboard..."
        $uiErrLog = Join-Path $runDir "ui.err.log"
        $script:uiProc = Start-Process powershell.exe `
            -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", $uiScript, "-Port", $UiPort) `
            -WorkingDirectory $RepoRoot -RedirectStandardError $uiErrLog -PassThru -WindowStyle Hidden
        Wait-PortReady -Port $UiPort -Name "Dashboard"
        if ($script:uiProc.HasExited) {
            if (Test-Path $uiErrLog) { Get-Content $uiErrLog -Tail 15 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red } }
            throw "Dashboard crashed on startup. See .local\run\ui.err.log"
        }
        Write-Host "  Dashboard ready (PID $($script:uiProc.Id))"

        $allowName = "CyberSec-TestPort-$TestPort"
        if (-not (Get-NetFirewallRule -DisplayName $allowName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $allowName -Direction Inbound -Action Allow `
                -Protocol TCP -LocalPort $TestPort -Profile Domain,Private,Public | Out-Null
        }

        $testScript = Join-Path $libDir "test-server.ps1"
        Write-Host "Starting attack honeypot (port $TestPort)..."
        $script:testProc = Start-Process powershell.exe `
            -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", $testScript, "-Port", $TestPort, "-LogPath", $attackLog) `
            -WorkingDirectory $RepoRoot -PassThru -WindowStyle Hidden
        Wait-PortReady -Port $TestPort -Name "Attack honeypot"
        Write-Host "  Honeypot ready (PID $($script:testProc.Id), logs to attack.log)"

        Save-ProcessIds
        Start-Process "http://127.0.0.1:$UiPort"

        $lanIp = Get-MyLanIp
        Write-Host ""
        Write-Host "==========================================" -ForegroundColor Green
        Write-Host "  CyberSec RUNNING" -ForegroundColor Green
        Write-Host "=========================================="
        Write-Host "  Dashboard:   http://127.0.0.1:$UiPort"
        Write-Host "  Your LAN IP: $(if ($lanIp) { $lanIp } else { 'unknown' })  (same Wi-Fi)"
        Write-Host "  Test port:   $TestPort"
        Write-Host ""
        Write-Host "  Same Wi-Fi:       .\run.ps1 attack -HostIp $(if ($lanIp) { $lanIp } else { 'LAN_IP' })"
        Write-Host "  Mobile/other net: .\scripts\run.ps1 extern  (port forward + public IP)"
        Write-Host "  Demo: see ATTACK-DEMO.md"
        Write-Host ""
        Write-Host "  DO NOT CLOSE THIS WINDOW - it keeps everything running"
        Write-Host "  Press Ctrl+C to stop everything"
        Write-Host "=========================================="
        Write-Host ""

        while ($true) {
            if ($script:engineProc.HasExited -or -not (Test-PortOpen $LapiPort) -or -not (Test-LapiHealthy)) {
                Write-Host "WARN: Backend stopped - restarting..."
                Ensure-EngineRunning
                Save-ProcessIds
            }
            if ($script:uiProc.HasExited -and (Test-LapiHealthy)) {
                Write-Host "WARN: Dashboard stopped - restarting..."
                Stop-PortListeners -Port $UiPort -Label "dashboard"
                $uiErrLog = Join-Path $runDir "ui.err.log"
                $script:uiProc = Start-Process powershell.exe `
                    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", $uiScript, "-Port", $UiPort) `
                    -WorkingDirectory $RepoRoot -RedirectStandardError $uiErrLog -PassThru -WindowStyle Hidden
                Wait-PortReady -Port $UiPort -Name "Dashboard"
                Save-ProcessIds
            }
            if ($script:testProc.HasExited) {
                Write-Host "WARN: Test server stopped - restarting..."
                $script:testProc = Start-Process powershell.exe `
                    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", $testScript, "-Port", $TestPort, "-LogPath", $attackLog) `
                    -WorkingDirectory $RepoRoot -PassThru -WindowStyle Hidden
                Save-ProcessIds
            }
            Start-Sleep -Seconds 3
        }
    }
    catch {
        Write-Host ""
        Write-Host "START FAILED: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Stop-AllServices
        Read-Host "Press Enter to close"
        exit 1
    }
}

switch ($Action) {
    "help"   { Show-Help }
    "setup"  { Do-Setup }
    "start"  { Do-Start }
    "stop"   { Stop-AllServices }
    "clean"  { Do-Clean }
    "info"   { Show-Info }
    "extern" { Show-Extern }
    "block"  { Do-Block }
    "status" { Do-Status }
    "export"   { Do-Export }
    "attack" { Do-RemoteAttack }
    "simulate" { Do-Simulate }
    default  { Show-Help }
}
