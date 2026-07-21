# Ferro-Sentry — Windows Install Script
# Usage (generic):     irm https://install.ferrosentry.dev | iex
# Usage (SecuryBlack): irm https://install.ferrosentry.dev | iex -Endpoint api.securyblack.com -Token <TOKEN>
#
# Or with explicit params:
#   $script = irm https://install.ferrosentry.dev
#   & ([scriptblock]::Create($script)) -Endpoint "https://api.securyblack.com" -Token "tok_abc123"
[CmdletBinding()]
param(
    [string]$Endpoint = "",
    [string]$Token    = "",
    [string]$Mode     = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Set TLS 1.2 protocol for PowerShell 5.1 compatibility on Windows Server
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls

# ─── Helpers ──────────────────────────────────────────────────────────────────
function Write-Info    { param($msg) Write-Host "[ferro-sentry] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[ferro-sentry] $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "[ferro-sentry] $msg" -ForegroundColor Yellow }
function Fail          { param($msg) Write-Host "[ferro-sentry] ERROR: $msg" -ForegroundColor Red; exit 1 }

# ─── Constants ────────────────────────────────────────────────────────────────
$GithubRepo  = "securyblack/ferro-sentry"
$BinaryName  = "ferro-sentry.exe"
$InstallDir  = "$env:ProgramFiles\FerroSentry"
$ConfigDir   = "$env:ProgramData\ferro-sentry"
$ConfigFile  = "$ConfigDir\config.toml"
$ServiceName = "FerroSentry"

# ─── Banner ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Ferro-Sentry — Server Security Agent (EDR + Posture)" -ForegroundColor Cyan -NoNewline
Write-Host " (Windows Installer)" -ForegroundColor Gray
Write-Host ""

# ─── Admin check ──────────────────────────────────────────────────────────────
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "This script must be run as Administrator. Right-click PowerShell and select 'Run as Administrator'."
}

# ─── Architecture detection ───────────────────────────────────────────────────
$procArch = $env:PROCESSOR_ARCHITECTURE
$target = switch ($procArch) {
    "AMD64" { "x86_64-pc-windows-msvc" }
    "ARM64" { "aarch64-pc-windows-msvc" }
    default { Fail "Unsupported architecture: $procArch" }
}

Write-Info "Detected architecture: $procArch ($target)"

# ─── Resolve latest release version ──────────────────────────────────────────
Write-Info "Fetching latest release from GitHub..."
$releaseApi  = "https://api.github.com/repos/$GithubRepo/releases/latest"
$releaseInfo = Invoke-RestMethod -Uri $releaseApi -Headers @{ "User-Agent" = "ferro-sentry-installer" }
$version     = $releaseInfo.tag_name

if (-not $version) { Fail "Could not determine latest version. Check your internet connection." }

Write-Info "Latest version: $version"

# ─── Download binary ──────────────────────────────────────────────────────────
$assetName   = "ferro-sentry-$target.zip"
$downloadUrl = "https://github.com/$GithubRepo/releases/download/$version/$assetName"
$checksumUrl = "$downloadUrl.sha256"
$tmpDir      = [System.IO.Path]::GetTempPath() + [System.IO.Path]::GetRandomFileName()
New-Item -ItemType Directory -Path $tmpDir | Out-Null

try {
    Write-Info "Downloading $assetName..."
    $zipPath = "$tmpDir\$assetName"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing

    # Verify checksum if available
    try {
        $checksumFile = "$tmpDir\$assetName.sha256"
        Invoke-WebRequest -Uri $checksumUrl -OutFile $checksumFile -UseBasicParsing
        $expected = (Get-Content $checksumFile).Split(" ")[0].Trim().ToLower()
        $actual   = (Get-FileHash -Algorithm SHA256 $zipPath).Hash.ToLower()
        if ($expected -ne $actual) { Fail "Checksum mismatch. Download may be corrupted." }
        Write-Success "Checksum OK"
    } catch {
        Write-Warn "No checksum file found, skipping verification"
    }

    # ─── Stop existing service before replacing binary ────────────────────────
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Info "Stopping existing service '$ServiceName'..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }

    # ─── Install binary ───────────────────────────────────────────────────────
    Write-Info "Installing binary to $InstallDir..."
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir | Out-Null
    }

    Expand-Archive -Path $zipPath -DestinationPath $tmpDir\extracted -Force
    Copy-Item -Path "$tmpDir\extracted\ferro-sentry.exe" -Destination "$InstallDir\$BinaryName" -Force
    Write-Success "Binary installed"

    # ─── Configuration ────────────────────────────────────────────────────────
    if (-not (Test-Path $ConfigDir)) {
        New-Item -ItemType Directory -Path $ConfigDir | Out-Null
    }

    if ($Mode -eq "local_agent" -or $Mode -eq "agent") {
        $Mode = "agent"
        if (-not $Endpoint) { $Endpoint = "http://localhost:4317" }
        Write-Info "Mode: agent — Ferro-Sentry will send events to $Endpoint"
    }

    # Interactively ask if missing
    if (-not $Endpoint) {
        $Endpoint = Read-Host "  SecuryBlack API endpoint (e.g. https://api.securyblack.com)"
    }
    if (-not $Token) {
        $secToken = Read-Host "  Auth token" -AsSecureString
        $Token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secToken))
    }

    if (-not $Endpoint) { Fail "Endpoint cannot be empty" }
    if (-not $Token) { Fail "Token cannot be empty" }

    Write-Info "Writing config to $ConfigFile..."
    if ($Mode -eq "") { $Mode = "direct" }
    $configContent = @"
# Ferro-Sentry configuration
# Do not share this file — it contains your auth token.
version = "$version"
mode = "$Mode"
api_url = "$Endpoint"
token = "$Token"
log_level = "info"
local_file_path = "C:/ProgramData/ferro-sentry/ferro-sentry_events.jsonl"
"@

    Set-Content -Path $ConfigFile -Value $configContent
    Write-Success "Config written"

    # ─── Windows Service Installation ─────────────────────────────────────────
    Write-Info "Creating Windows Service..."
    $binPathWithArgs = "`"$InstallDir\$BinaryName`""
    & sc.exe create $ServiceName binPath= $binPathWithArgs start= auto DisplayName= "Ferro-Sentry Security Agent" | Out-Null
    & sc.exe description $ServiceName "SecuryBlack Ferro-Sentry security agent (EDR + Posture)" | Out-Null
    
    Write-Info "Starting service..."
    Start-Service -Name $ServiceName
    Write-Success "Ferro-Sentry has been successfully installed and started!"

} finally {
    if (Test-Path $tmpDir) {
        Remove-Item -Path $tmpDir -Recurse -Force
    }
}
