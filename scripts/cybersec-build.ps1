# CyberSec - Build script for Windows
# Builds cybersec.exe and cybercli.exe into bin/

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RepoRoot

function Ensure-Go {
    if (Get-Command go -ErrorAction SilentlyContinue) {
        Write-Host "Go found: $(go version)"
        return
    }
    Write-Host "Installing Go via winget..."
    winget install -e --id GoLang.Go --accept-package-agreements --accept-source-agreements
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path", "User")
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        throw "Go installation failed. Restart PowerShell and run this script again."
    }
}

Ensure-Go

$null = New-Item -ItemType Directory -Force -Path "$RepoRoot\bin"

$tags = "netgo,osusergo,expr_debug,nomsgpack,sqlite_modernc"
$version = "v1.7.8"
$buildDate = Get-Date -Format "yyyy-MM-dd_HH:mm:ss"
$ldflags = "-s " +
    "-X github.com/crowdsecurity/go-cs-lib/version.Version=$version " +
    "-X github.com/crowdsecurity/go-cs-lib/version.BuildDate=$buildDate " +
    "-X github.com/crowdsecurity/crowdsec/pkg/cwversion.Codename=CyberSec"

Write-Host "Building CyberSec engine..."
go build -trimpath -tags $tags -ldflags $ldflags -o "$RepoRoot\bin\cybersec.exe" ./cmd/crowdsec
if ($LASTEXITCODE -ne 0) { throw "cybersec build failed" }

Write-Host "Building cybercli..."
go build -trimpath -tags $tags -ldflags $ldflags -o "$RepoRoot\bin\cybercli.exe" ./cmd/crowdsec-cli
if ($LASTEXITCODE -ne 0) { throw "cybercli build failed" }

Write-Host ""
Write-Host "Build complete!"
Write-Host "  bin\cybersec.exe  - CyberSec security engine"
Write-Host "  bin\cybercli.exe         - CyberSec CLI"
Write-Host ""
Write-Host "Next: .\scripts\run.ps1 setup"
