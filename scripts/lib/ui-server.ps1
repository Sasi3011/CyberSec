# Internal worker - dashboard server (spawned by run.ps1 start)

param([int]$Port = 3000)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))
$Cli = Join-Path $RepoRoot "bin\sscli.exe"
$Config = Join-Path $RepoRoot ".local\sasikiran-local.yaml"
$LapiPort = 8080
$MetricsPort = 6060

function Test-LapiUp {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect("127.0.0.1", $LapiPort)
        $client.Close()
        return $true
    }
    catch { return $false }
}

function Wait-ForBackend {
    param([int]$TimeoutSec = 90)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-LapiUp) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Get-SscliJson {
    param([string[]]$CmdArgs)
    if (-not (Test-LapiUp)) { throw "Backend offline (127.0.0.1:$LapiPort)" }
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $raw = ""
    for ($try = 0; $try -lt 4; $try++) {
        $raw = (& $Cli -c $Config @CmdArgs -o json 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -eq 0) { break }
        if ($raw -notmatch "SQLITE_BUSY|database is locked") { break }
        Start-Sleep -Milliseconds (300 * ($try + 1))
    }
    $ErrorActionPreference = $prevEap
    if ($LASTEXITCODE -ne 0) { throw $raw }
    if (-not $raw) { return @() }
    return ($raw | ConvertFrom-Json)
}

function Invoke-Sscli {
    param([string[]]$CmdArgs)
    if (-not (Test-LapiUp)) { throw "Backend offline (127.0.0.1:$LapiPort)" }
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $out = (& $Cli -c $Config @CmdArgs 2>&1 | Out-String).Trim()
    $ErrorActionPreference = $prevEap
    if ($LASTEXITCODE -ne 0) { throw $out }
    return $out
}

function Read-JsonBody {
    param($Request)
    $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
    $raw = $reader.ReadToEnd()
    if (-not $raw) { return @{} }
    return ($raw | ConvertFrom-Json)
}

$RulePrefix = "SasikiranSec-Block"

function Get-FirewallRuleName {
    param([string]$Ip)
    $safe = $Ip -replace '[:./]', '-'
    return "$RulePrefix-$safe"
}

function Test-FirewallBlocked {
    param([string]$Ip)
    $name = Get-FirewallRuleName -Ip $Ip
    return $null -ne (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)
}

function Remove-FirewallBlock {
    param([string]$Ip)
    $name = Get-FirewallRuleName -Ip $Ip
    if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $name -ErrorAction Stop
        return $true
    }
    return $false
}

function ConvertTo-JsonArray {
    param($Items, [int]$Depth = 10)
    $arr = @($Items)
    if ($arr.Count -eq 0) { return "[]" }
    if ($arr.Count -eq 1) {
        return "[" + ($arr[0] | ConvertTo-Json -Depth $Depth -Compress) + "]"
    }
    return ($arr | ConvertTo-Json -Depth $Depth -Compress)
}

function Test-PrivateIp {
    param([string]$Ip)
    return $Ip -match '^(192\.168\.|10\.|172\.(1[6-9]|2|3[01])\.|127\.)'
}

function Get-HostPublicGeo {
    try {
        $g = Invoke-RestMethod "http://ip-api.com/json/?fields=status,lat,lon,city,regionName,country,countryCode,timezone" -TimeoutSec 5
        if ($g.status -eq "success") { return $g }
    }
    catch { }
    return @{ lat = 11.0102; lon = 76.9701; city = "Coimbatore"; regionName = "Tamil Nadu"; country = "India"; countryCode = "IN" }
}

function Get-ReverseGeo {
    param([double]$Lat, [double]$Lon)
    try {
        $headers = @{ "User-Agent" = "SasikiranSec-Dashboard/1.0 (local security demo)" }
        $uri = "https://nominatim.openstreetmap.org/reverse?lat=$Lat&lon=$Lon&format=json&zoom=18&addressdetails=1"
        $r = Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec 8
        $a = $r.address
        $city = if ($a.city) { $a.city } elseif ($a.town) { $a.town } elseif ($a.village) { $a.village } elseif ($a.suburb) { $a.suburb } else { "" }
        $road = if ($a.road) { $a.road } elseif ($a.neighbourhood) { $a.neighbourhood } else { "" }
        return @{
            city    = $city
            region  = $a.state
            country = $a.country
            road    = $road
            suburb  = $a.suburb
            postcode = $a.postcode
            display = if ($road) { "$road, $city" } else { "$city, $($a.state)" }
        }
    }
    catch { }
    return @{ city = ""; region = ""; country = ""; road = ""; suburb = ""; postcode = ""; display = "" }
}

function Get-PublicIpGeo {
    param([string]$Ip)
    $fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    try {
        $d = Invoke-RestMethod "http://ip-api.com/json/$Ip?fields=$fields" -TimeoutSec 6
        if ($d.status -eq "success") {
            return @{
                lat = [double]$d.lat; lon = [double]$d.lon; city = $d.city; region = $d.regionName
                country = $d.country; countryCode = $d.countryCode; zip = $d.zip
                isp = $d.isp; org = $d.org; timezone = $d.timezone
                isPrivate = $false; subnet = ""; source = "ip-api"
                accuracy = "City-level IP geolocation (~1-5 km)"
                label = "$($d.city), $($d.regionName), $($d.country)" + $(if ($d.zip) { " $($d.zip)" } else { "" })
            }
        }
    }
    catch { }
    try {
        $w = Invoke-RestMethod "https://ipwho.is/$Ip" -TimeoutSec 6
        if ($w.success) {
            return @{
                lat = [double]$w.latitude; lon = [double]$w.longitude; city = $w.city; region = $w.region
                country = $w.country; countryCode = $w.country_code; zip = [string]$w.postal
                isp = if ($w.connection) { $w.connection.isp } else { "" }
                org = if ($w.connection) { $w.connection.org } else { "" }
                timezone = if ($w.timezone) { $w.timezone.id } else { "" }
                isPrivate = $false; subnet = ""; source = "ipwho"
                accuracy = "City-level IP geolocation (~1-5 km)"
                label = "$($w.city), $($w.region), $($w.country)" + $(if ($w.postal) { " $($w.postal)" } else { "" })
            }
        }
    }
    catch { }
    return $null
}

function Get-PrivateIpOffset {
    param([string]$Ip, [switch]$GpsAnchored)
    $parts = $Ip.Split('.')
    if ($parts.Count -ne 4) { return @{ lat = 0; lon = 0 } }
    $o2 = [int]$parts[1]
    $o3 = [int]$parts[2]
    $o4 = [int]$parts[3]
    # GPS mode: ~20 m spread; ISP mode: ~500 m spread
    $scale = if ($GpsAnchored) { 0.00018 } else { 0.0045 }
    $latOff = (($o3 * 256 + $o4) / 65535.0 - 0.5) * $scale
    $lonOff = (($o2 * 256 + $o3) / 65535.0 - 0.5) * $scale
    return @{ lat = $latOff; lon = $lonOff }
}

function Get-IpGeo {
    param(
        [string]$Ip,
        [double]$UserLat = 0,
        [double]$UserLon = 0,
        [double]$UserAccuracy = 0
    )
    if (Test-PrivateIp -Ip $Ip) {
        $parts = $Ip.Split('.')
        $subnet = "$($parts[0]).$($parts[1]).$($parts[2]).0/24"
        $useGps = ($UserLat -ne 0 -and $UserLon -ne 0)
        if ($useGps) {
            $off = Get-PrivateIpOffset -Ip $Ip -GpsAnchored
            $lat = [math]::Round($UserLat + $off.lat, 7)
            $lon = [math]::Round($UserLon + $off.lon, 7)
            $rev = Get-ReverseGeo -Lat $UserLat -Lon $UserLon
            $accM = if ($UserAccuracy -gt 0) { [math]::Round($UserAccuracy) } else { 50 }
            $locLabel = if ($rev.display) { [string]$rev.display } else { "Your current location" }
            return @{
                lat = $lat; lon = $lon
                city = $rev.city; region = $rev.region; country = $rev.country
                countryCode = ""; zip = $rev.postcode
                isp = "Same WiFi / LAN device"; org = "Private IP $Ip ($subnet)"
                timezone = ""; isPrivate = $true; subnet = $subnet; source = "gps"
                road = $rev.road; suburb = $rev.suburb
                accuracy = "Attacker on your WiFi (near your laptop GPS +/-${accM}m)"
                label = "Attacker $Ip - $locLabel"
            }
        }
        $hostGeo = Get-HostPublicGeo
        $off = Get-PrivateIpOffset -Ip $Ip
        $lat = [math]::Round([double]$hostGeo.lat + $off.lat, 6)
        $lon = [math]::Round([double]$hostGeo.lon + $off.lon, 6)
        return @{
            lat = $lat; lon = $lon; city = $hostGeo.city; region = $hostGeo.regionName
            country = $hostGeo.country; countryCode = $hostGeo.countryCode
            zip = ""; isp = "Local Network (Private IP)"; org = "LAN subnet $subnet"
            timezone = $hostGeo.timezone; isPrivate = $true; subnet = $subnet; source = "isp-estimate"
            road = ""; suburb = ""
            accuracy = "Enable browser location for exact GPS (private IP)"
            label = "$Ip on $subnet near $($hostGeo.city), $($hostGeo.regionName)"
        }
    }
    $pub = Get-PublicIpGeo -Ip $Ip
    if ($pub) { return $pub }
    return @{
        lat = 0; lon = 0; city = "Unknown"; region = ""; country = "?"; countryCode = ""
        zip = ""; isp = ""; org = ""; timezone = ""; isPrivate = $false; subnet = ""
        source = "unknown"; road = ""; suburb = ""
        accuracy = "Could not resolve location"; label = "Location unknown"
    }
}

function Get-SscliJsonSafe {
    param([string[]]$CmdArgs)
    if (-not (Test-LapiUp)) { return @() }
    try {
        $items = Get-SscliJson -CmdArgs $CmdArgs
        return @($items)
    }
    catch {
        return @()
    }
}

function Get-FlatAlerts {
    $items = Get-SscliJsonSafe -CmdArgs @("alerts", "list")
    return @($items)
}

function Get-FlatDecisions {
    param([string]$Ip = "", [string]$Type = "")
    $args = @("decisions", "list")
    if ($Ip) { $args += @("-i", $Ip) }
    if ($Type) { $args += @("-t", $Type) }
    $items = Get-SscliJsonSafe -CmdArgs $args
    $flat = @()
    foreach ($item in $items) {
        if ($item.decisions) {
            foreach ($d in $item.decisions) { $flat += $d }
        }
        elseif ($item.value) {
            $flat += $item
        }
    }
    return $flat
}

function Invoke-GlobalUnban {
    param([string]$Ip)
    if ($Ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw "Invalid IP: $Ip" }

    $removedDecisions = 0
    for ($i = 0; $i -lt 10; $i++) {
        $before = @(Get-FlatDecisions -Ip $Ip -Type "ban").Count
        if ($before -eq 0) { break }
        Invoke-Sscli -CmdArgs @("decisions", "delete", "-i", $Ip, "-t", "ban") | Out-Null
        Start-Sleep -Milliseconds 400
        $after = @(Get-FlatDecisions -Ip $Ip -Type "ban").Count
        $removedDecisions += [Math]::Max(0, $before - $after)
        if ($after -eq 0) { break }
    }

    $firewallRemoved = Remove-FirewallBlock -Ip $Ip
    Start-Sleep -Milliseconds 200

    $remainingBans = @(Get-FlatDecisions -Ip $Ip -Type "ban").Count
    $firewallActive = Test-FirewallBlocked -Ip $Ip
    $ok = ($remainingBans -eq 0) -and (-not $firewallActive)

    $message = if ($ok) {
        "IP $Ip globally unblocked. Engine ban cleared and Windows Firewall rule removed. The remote device can attack again."
    }
    else {
        "Unblock incomplete for $Ip. Remaining engine bans: $remainingBans. Firewall still blocking: $firewallActive"
    }

    return @{
        ok               = $ok
        ip               = $Ip
        action           = "global_unban"
        decisionsRemoved = $removedDecisions
        remainingBans    = $remainingBans
        firewallRemoved  = $firewallRemoved
        firewallActive   = $firewallActive
        message          = $message
    }
}

function Get-PrometheusMetrics {
    try {
        $raw = (Invoke-WebRequest "http://127.0.0.1:$MetricsPort/metrics" -UseBasicParsing -TimeoutSec 3).Content
        $result = @{
            activeBans      = 0
            activeAlerts    = @{}
            bucketsCreated  = 0
            bucketsOverflow = 0
            eventsPoured    = 0
            parserHits      = 0
            goroutines      = 0
            uptime          = 0
            version         = "v1.7.8"
        }
        foreach ($line in ($raw -split "`n")) {
            if ($line -match '^cs_active_decisions\{.*\}\s+([\d.]+)') { $result.activeBans += [double]$Matches[1] }
            if ($line -match '^cs_alerts\{reason="([^"]+)"\}\s+([\d.]+)') { $result.activeAlerts[$Matches[1]] = [int]$Matches[2] }
            if ($line -match '^cs_bucket_instantiation_total\{.*\}\s+([\d.]+)') { $result.bucketsCreated += [double]$Matches[1] }
            if ($line -match '^cs_bucket_overflowed_total\{.*\}\s+([\d.]+)') { $result.bucketsOverflow += [double]$Matches[1] }
            if ($line -match '^cs_bucket_poured_total\{.*\}\s+([\d.]+)') { $result.eventsPoured += [double]$Matches[1] }
            if ($line -match '^cs_parser_hits_total\{.*\}\s+([\d.]+)') { $result.parserHits += [double]$Matches[1] }
            if ($line -match '^go_goroutines\s+([\d.]+)') { $result.goroutines = [int]$Matches[1] }
            if ($line -match '^process_start_time_seconds\s+([\d.]+)') { $result.uptime = [long]$Matches[1] }
            if ($line -match '^cs_info\{version="([^"]+)"\}') { $result.version = $Matches[1] }
        }
        return $result | ConvertTo-Json -Compress
    }
    catch { return (@{ error = $_.Exception.Message } | ConvertTo-Json -Compress) }
}

Wait-ForBackend -TimeoutSec 15 | Out-Null
if (-not (Test-LapiUp)) {
    Write-Warning "Backend offline on 127.0.0.1:$LapiPort - dashboard starting in offline mode"
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
$listener.Start()

while ($listener.IsListening) {
    $context = $listener.GetContext()
    $request = $context.Request
    $response = $context.Response
    $path = $request.Url.LocalPath
    $method = $request.HttpMethod

    try {
        if ($method -eq "OPTIONS") {
            $response.StatusCode = 204
            $bytes = [byte[]]@()
        }
        elseif ($path -eq "/" -or $path -eq "/index.html") {
            $html = Get-Content (Join-Path $RepoRoot "ui\index.html") -Raw -Encoding UTF8
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($html)
            $response.ContentType = "text/html; charset=utf-8"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/favicon.ico") {
            $bytes = [byte[]]@()
            $response.StatusCode = 204
        }
        elseif ($path -eq "/api/alerts") {
            $data = Get-FlatAlerts
            $json = ConvertTo-JsonArray -Items $data -Depth 10
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/api/decisions") {
            $flat = @(Get-FlatDecisions)
            $json = ConvertTo-JsonArray -Items $flat -Depth 10
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -match '^/api/geo') {
            $ip = $request.QueryString["ip"]
            if (-not $ip) { throw "Missing ip query parameter" }
            $ulat = 0.0; $ulon = 0.0; $uacc = 0.0
            if ($request.QueryString["ulat"]) { [void][double]::TryParse($request.QueryString["ulat"], [ref]$ulat) }
            if ($request.QueryString["ulon"]) { [void][double]::TryParse($request.QueryString["ulon"], [ref]$ulon) }
            if ($request.QueryString["uacc"]) { [void][double]::TryParse($request.QueryString["uacc"], [ref]$uacc) }
            $geo = Get-IpGeo -Ip $ip -UserLat $ulat -UserLon $ulon -UserAccuracy $uacc
            $json = $geo | ConvertTo-Json -Compress
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/api/bans") {
            $bans = @(Get-FlatDecisions -Type "ban")
            $byIp = @{}
            foreach ($d in $bans) {
                $ip = [string]$d.value
                if (-not $ip) { continue }
                if (-not $byIp.ContainsKey($ip)) {
                    $byIp[$ip] = @{
                        ip              = $ip
                        scenario        = $d.scenario
                        duration        = $d.duration
                        origin          = $d.origin
                        engineBanned    = $true
                        firewallBlocked = (Test-FirewallBlocked -Ip $ip)
                    }
                }
            }
            foreach ($ip in @($byIp.Keys)) {
                if (-not $byIp[$ip].firewallBlocked) {
                    $byIp[$ip].firewallBlocked = Test-FirewallBlocked -Ip $ip
                }
            }
            $json = ConvertTo-JsonArray -Items @($byIp.Values) -Depth 6
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/api/metrics") {
            $json = Get-PrometheusMetrics
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/api/unban" -and $method -eq "POST") {
            $body = Read-JsonBody -Request $request
            $ip = [string]$body.ip
            if (-not $ip) { throw "Missing ip" }
            $result = Invoke-GlobalUnban -Ip $ip
            $json = $result | ConvertTo-Json -Compress
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = if ($result.ok) { 200 } else { 500 }
        }
        elseif ($path -eq "/api/block" -and $method -eq "POST") {
            $body = Read-JsonBody -Request $request
            $ip = [string]$body.ip
            if (-not $ip) { throw "Missing ip" }
            $duration = if ($body.duration) { [string]$body.duration } else { "4h" }
            Invoke-Sscli -CmdArgs @("decisions", "add", "--ip", $ip, "-d", $duration, "-R", "sasikiransec/ui-manual", "-t", "ban") | Out-Null
            $json = (@{ ok = $true; ip = $ip; action = "block"; duration = $duration } | ConvertTo-Json -Compress)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/api/health") {
            $backend = Test-LapiUp
            $payload = @{ status = if ($backend) { "ok" } else { "offline" }; service = "SasikiranSec"; version = "v1.7.8"; backend = "127.0.0.1:$LapiPort" }
            $json = $payload | ConvertTo-Json -Compress
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = if ($backend) { 200 } else { 503 }
        }
        else {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes('{"error":"not found"}')
            $response.ContentType = "application/json"
            $response.StatusCode = 404
        }
    }
    catch {
        $err = @{ error = $_.Exception.Message } | ConvertTo-Json -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($err)
        $response.ContentType = "application/json"
        $response.StatusCode = 500
    }

    $response.Headers.Add("Access-Control-Allow-Origin", "*")
    $response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    $response.Headers.Add("Access-Control-Allow-Headers", "Content-Type")
    $response.ContentLength64 = $bytes.Length
    try {
        $response.OutputStream.Write($bytes, 0, $bytes.Length)
    }
    catch {
        # client disconnected mid-response
    }
    try { $response.OutputStream.Close() } catch { }
}
