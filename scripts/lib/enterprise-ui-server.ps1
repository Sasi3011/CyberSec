# Enterprise SOC dashboard server — same UI/API as ui-server.ps1 (:3000) but fleet data from Manager (:8443)

param(
    [int]$Port = 3001,
    [string]$ManagerUrl = "http://localhost:8443",
    [string]$AdminEmail = "admin@demo.local",
    [string]$AdminPassword = "demo123"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$DashboardHtml = Join-Path $RepoRoot "enterprise\dashboard\index.html"

function ConvertTo-JsonArray {
    param($Items, [int]$Depth = 10)
    $arr = @($Items)
    if ($arr.Count -eq 0) { return "[]" }
    if ($arr.Count -eq 1) {
        return "[" + ($arr[0] | ConvertTo-Json -Depth $Depth -Compress) + "]"
    }
    return ($arr | ConvertTo-Json -Depth $Depth -Compress)
}

function Read-JsonBody {
    param($Request)
    $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
    $raw = $reader.ReadToEnd()
    if (-not $raw) { return @{} }
    return ($raw | ConvertFrom-Json)
}

function Test-PrivateIp { param([string]$Ip) return $Ip -match '^(192\.168\.|10\.|172\.(1[6-9]|2|3[01])\.|127\.)' }

function Get-HostPublicGeo {
    try {
        $g = Invoke-RestMethod "http://ip-api.com/json/?fields=status,lat,lon,city,regionName,country,countryCode,timezone" -TimeoutSec 5
        if ($g.status -eq "success") { return $g }
    } catch { }
    return @{ lat = 11.0102; lon = 76.9701; city = "Coimbatore"; regionName = "Tamil Nadu"; country = "India"; countryCode = "IN" }
}

function Get-PrivateIpOffset {
    param([string]$Ip, [switch]$GpsAnchored)
    $parts = $Ip.Split('.')
    if ($parts.Count -ne 4) { return @{ lat = 0; lon = 0 } }
    $scale = if ($GpsAnchored) { 0.00018 } else { 0.0045 }
    $o2 = [int]$parts[1]; $o3 = [int]$parts[2]; $o4 = [int]$parts[3]
    return @{ lat = (($o3 * 256 + $o4) / 65535.0 - 0.5) * $scale; lon = (($o2 * 256 + $o3) / 65535.0 - 0.5) * $scale }
}

function Get-PublicIpGeo {
    param([string]$Ip)
    try {
        $d = Invoke-RestMethod "http://ip-api.com/json/$Ip?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,query" -TimeoutSec 6
        if ($d.status -eq "success") {
            return @{
                lat = [double]$d.lat; lon = [double]$d.lon; city = $d.city; region = $d.regionName
                country = $d.country; countryCode = $d.countryCode; zip = $d.zip
                isp = $d.isp; org = $d.org; isPrivate = $false; subnet = ""; source = "ip-api"
                accuracy = "City-level IP geolocation"; label = "$($d.city), $($d.regionName), $($d.country)"
            }
        }
    } catch { }
    return $null
}

function Get-IpGeo {
    param([string]$Ip, [double]$UserLat = 0, [double]$UserLon = 0, [double]$UserAccuracy = 0)
    if (Test-PrivateIp -Ip $Ip) {
        $parts = $Ip.Split('.'); $subnet = "$($parts[0]).$($parts[1]).$($parts[2]).0/24"
        if ($UserLat -ne 0 -and $UserLon -ne 0) {
            $off = Get-PrivateIpOffset -Ip $Ip -GpsAnchored
            return @{
                lat = [math]::Round($UserLat + $off.lat, 7); lon = [math]::Round($UserLon + $off.lon, 7)
                city = "LAN"; country = "Local"; isPrivate = $true; subnet = $subnet; source = "gps"
                isp = "Same WiFi / LAN"; label = "Attacker $Ip"; accuracy = "Near your laptop GPS"
            }
        }
        $hostGeo = Get-HostPublicGeo
        $off = Get-PrivateIpOffset -Ip $Ip
        return @{
            lat = [math]::Round([double]$hostGeo.lat + $off.lat, 6); lon = [math]::Round([double]$hostGeo.lon + $off.lon, 6)
            city = $hostGeo.city; region = $hostGeo.regionName; country = $hostGeo.country
            isPrivate = $true; subnet = $subnet; source = "isp-estimate"; isp = "Local Network"
            label = "$Ip on $subnet"; accuracy = "Enable browser location for exact GPS"
        }
    }
    $pub = Get-PublicIpGeo -Ip $Ip
    if ($pub) { return $pub }
    return @{ lat = 0; lon = 0; city = "Unknown"; country = "?"; isPrivate = $false; label = "Unknown"; accuracy = "" }
}

$script:ManagerToken = $null
$script:ManagerHeaders = @{}

function Connect-Manager {
    $body = @{ email = $AdminEmail; password = $AdminPassword } | ConvertTo-Json
    $login = Invoke-RestMethod -Uri "$ManagerUrl/api/v1/auth/login" -Method Post -Body $body -ContentType "application/json"
    $script:ManagerToken = $login.access_token
    $script:ManagerHeaders = @{ Authorization = "Bearer $ManagerToken" }
}

function Test-ManagerUp {
    try {
        $h = Invoke-RestMethod -Uri "$ManagerUrl/health" -TimeoutSec 3
        return ($h.status -eq "ok")
    } catch { return $false }
}

function Invoke-ManagerGet {
    param([string]$Path)
    return Invoke-RestMethod -Uri "$ManagerUrl$Path" -Headers $script:ManagerHeaders -TimeoutSec 15
}

function Invoke-ManagerPost {
    param([string]$Path, $Body)
    $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 8 -Compress }
    return Invoke-RestMethod -Uri "$ManagerUrl$Path" -Method Post -Headers $script:ManagerHeaders -Body $json -ContentType "application/json" -TimeoutSec 15
}

function Get-EnterpriseAlerts {
    $r = Invoke-ManagerGet "/api/v1/admin/alerts"
    $list = @()
    foreach ($a in @($r.alerts)) {
        $list += @{
            scenario     = $a.scenario
            source       = @{ ip = $a.source_ip }
            created_at   = $a.detected_at
            events_count = 1
            decisions    = @(@{ type = "ban"; value = $a.source_ip; scenario = $a.scenario; duration = "4h"; origin = "enterprise" })
        }
    }
    return $list
}

function Get-EnterpriseDecisions {
    $r = Invoke-ManagerGet "/api/v1/admin/threat-intel"
    $flat = @()
    foreach ($i in @($r.iocs)) {
        $flat += @{ type = "ban"; value = $i.ip; scenario = $i.scenario; duration = "4h"; origin = "enterprise-ioc" }
    }
    return $flat
}

function Get-EnterpriseBans {
    $decisions = @(Get-EnterpriseDecisions)
    $byIp = @{}
    foreach ($d in $decisions) {
        if (-not $d.value) { continue }
        if (-not $byIp.ContainsKey($d.value)) {
            $byIp[$d.value] = @{
                ip = $d.value; scenario = $d.scenario; duration = $d.duration
                origin = $d.origin; engineBanned = $true; firewallBlocked = $true
            }
        }
    }
    return @($byIp.Values)
}

function Get-EnterpriseMetrics {
    $ov = Invoke-ManagerGet "/api/v1/admin/overview"
    return @{
        activeBans      = [int]$ov.ioc_version
        eventsPoured    = [double]$ov.total_alerts
        bucketsOverflow = [double]$ov.total_alerts
        parserHits      = [double]$ov.total_agents
        bucketsCreated  = [double]($ov.online_agents + $ov.offline_agents + $ov.degraded_agents)
        goroutines      = [int]$ov.online_agents
        onlineAgents    = [int]$ov.online_agents
        offlineAgents   = [int]$ov.offline_agents
        degradedAgents  = [int]$ov.degraded_agents
        engineDownCount = [int]$ov.engine_down_count
        byDepartment    = $ov.by_department
        byStatus        = $ov.by_status
    }
}

function Get-EnterpriseEndpoints {
    return (Invoke-ManagerGet "/api/v1/admin/endpoints")
}

function Import-ThreatIoc {
    param([string]$Ip, [string]$Duration = "4h")
    $body = @{
        source = "soc-dashboard"
        iocs   = @(@{ ip = $Ip; confidence = 85; severity = "high"; scenario = "soc/manual-block" })
    }
    Invoke-ManagerPost "/api/v1/admin/threat-feed/import" $body | Out-Null
}

function Revoke-ThreatIoc {
    param([string]$Ip)
    Invoke-ManagerPost "/api/v1/admin/threat-intel/revoke" @{ ips = @($Ip) } | Out-Null
}

Write-Host "=== CyberSec Enterprise SOC (:3001) — same UI as local :3000 ===" -ForegroundColor Cyan
Write-Host "Dashboard: http://127.0.0.1:$Port"
Write-Host "Manager:   $ManagerUrl"

if (-not (Test-ManagerUp)) {
    Write-Warning "Manager offline — start: cd enterprise\manager; go run ./cmd/manager"
} else {
    try {
        Connect-Manager
        Write-Host "Connected to Manager as $AdminEmail"
    } catch {
        Write-Warning "Manager login failed: $($_.Exception.Message)"
    }
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
    $bytes = [byte[]]@()

    try {
        if ($method -eq "OPTIONS") {
            $response.StatusCode = 204
        }
        elseif ($path -eq "/" -or $path -eq "/index.html") {
            $html = Get-Content $DashboardHtml -Raw -Encoding UTF8
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($html)
            $response.ContentType = "text/html; charset=utf-8"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/favicon.ico") {
            $response.StatusCode = 204
        }
        elseif (-not $script:ManagerToken -and $path -like "/api/*") {
            if (Test-ManagerUp) { Connect-Manager }
            if (-not $script:ManagerToken) { throw "Manager not authenticated" }
        }
        elseif ($path -eq "/api/alerts") {
            $json = ConvertTo-JsonArray -Items (Get-EnterpriseAlerts) -Depth 10
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/api/decisions") {
            $json = ConvertTo-JsonArray -Items (Get-EnterpriseDecisions) -Depth 10
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/api/bans") {
            $json = ConvertTo-JsonArray -Items (Get-EnterpriseBans) -Depth 6
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/api/endpoints") {
            $json = (Get-EnterpriseEndpoints | ConvertTo-Json -Depth 6 -Compress)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -match '^/api/endpoints/(.+)$') {
            $id = $Matches[1]
            $json = (Invoke-ManagerGet "/api/v1/admin/endpoints/$id" | ConvertTo-Json -Depth 8 -Compress)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/api/incidents") {
            $json = (Invoke-ManagerGet "/api/v1/admin/incidents" | ConvertTo-Json -Depth 6 -Compress)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/api/audit-logs") {
            $json = (Invoke-ManagerGet "/api/v1/admin/audit-logs" | ConvertTo-Json -Depth 6 -Compress)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/api/ws-token") {
            $wsBase = $ManagerUrl -replace '^http', 'ws'
            $payload = @{ token = $script:ManagerToken; ws_url = "$wsBase/ws/v1/alerts" }
            $bytes = [System.Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress))
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -match '^/api/geo') {
            $ip = $request.QueryString["ip"]
            if (-not $ip) { throw "Missing ip" }
            $ulat = 0.0; $ulon = 0.0
            if ($request.QueryString["ulat"]) { [void][double]::TryParse($request.QueryString["ulat"], [ref]$ulat) }
            if ($request.QueryString["ulon"]) { [void][double]::TryParse($request.QueryString["ulon"], [ref]$ulon) }
            $geo = Get-IpGeo -Ip $ip -UserLat $ulat -UserLon $ulon
            $bytes = [System.Text.Encoding]::UTF8.GetBytes(($geo | ConvertTo-Json -Compress))
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/api/metrics") {
            $json = if ($script:ManagerToken) { (Get-EnterpriseMetrics | ConvertTo-Json -Compress) } else { '{"error":"offline"}' }
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/api/health") {
            $ok = (Test-ManagerUp) -and $script:ManagerToken
            $payload = @{ status = if ($ok) { "ok" } else { "offline" }; service = "CyberSec Enterprise"; version = "fleet"; backend = $ManagerUrl }
            $bytes = [System.Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress))
            $response.ContentType = "application/json"
            $response.StatusCode = if ($ok) { 200 } else { 503 }
        }
        elseif ($path -eq "/api/block" -and $method -eq "POST") {
            $body = Read-JsonBody -Request $request
            $ip = [string]$body.ip
            if (-not $ip) { throw "Missing ip" }
            Import-ThreatIoc -Ip $ip
            $bytes = [System.Text.Encoding]::UTF8.GetBytes((@{ ok = $true; ip = $ip; action = "block" } | ConvertTo-Json -Compress))
            $response.ContentType = "application/json"
            $response.StatusCode = 200
        }
        elseif ($path -eq "/api/unban" -and $method -eq "POST") {
            $body = Read-JsonBody -Request $request
            $ip = [string]$body.ip
            if (-not $ip) { throw "Missing ip" }
            Revoke-ThreatIoc -Ip $ip
            $result = @{ ok = $true; ip = $ip; message = "IOC revoked org-wide" }
            $bytes = [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Compress))
            $response.ContentType = "application/json"
            $response.StatusCode = 200
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

    $response.OutputStream.Write($bytes, 0, $bytes.Length)
    $response.Close()
}
