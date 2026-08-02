# Internal worker - attack honeypot (spawned by run.ps1 start)
# Each TCP connection logs an SSH brute-force line the engine detects automatically.
# Uses existing crowdsecurity/ssh-bf scenario (capacity 5, leakspeed 10s).

param(
    [int]$Port = 9999,
    [string]$LogPath = ""
)

$usernames = @(
    "root","admin","administrator","user","test","guest","ubuntu",
    "pi","oracle","postgres","mysql","deploy","support","backup",
    "attacker","scanner","hacker","bot","probe","anonymous"
)

function Write-SshFailLine {
    param([string]$Path, [string]$ClientIp)
    if (-not $Path) { return }

    $user = $usernames[(Get-Random -Maximum $usernames.Count)]
    $srcPort = Get-Random -Minimum 40000 -Maximum 65535
    # syslog format the crowdsec syslog-logs parser expects
    $ts = (Get-Date).ToString("MMM dd HH':'mm':'ss", [System.Globalization.CultureInfo]::InvariantCulture)
    $line = "${ts} localhost sshd[9999]: Failed password for invalid user ${user} from ${ClientIp} port ${srcPort} ssh2"

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) {
        $null = New-Item -ItemType Directory -Force -Path $dir
    }
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    try {
        $sw = New-Object System.IO.StreamWriter($fs)
        $sw.WriteLine($line)
        $sw.Flush()
    }
    finally { $fs.Close() }
}

function Get-ClientIp {
    param([System.Net.Sockets.TcpClient]$Client)
    $addr = $Client.Client.RemoteEndPoint.Address.ToString()
    if ($addr -match '^::ffff:(.+)$') { return $Matches[1] }
    return $addr
}

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
$listener.Start()

try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        $clientIp = Get-ClientIp -Client $client

        Write-SshFailLine -Path $LogPath -ClientIp $clientIp

        try {
            $stream = $client.GetStream()
            $msg = [System.Text.Encoding]::UTF8.GetBytes("SasikiranSec honeypot`n")
            $stream.Write($msg, 0, $msg.Length)
        }
        catch { }
        finally { $client.Close() }
    }
}
finally {
    $listener.Stop()
}
