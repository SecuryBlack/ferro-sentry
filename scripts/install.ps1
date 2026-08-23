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

$SbAgentLabel = "ferro-sentry"
$libUrl = "https://raw.githubusercontent.com/securyblack/sb-agent-core/master/scripts/install-lib.ps1"
$libTmp = Join-Path ([System.IO.Path]::GetTempPath()) "sb-agent-core-install-lib.ps1"
Invoke-WebRequest -Uri $libUrl -OutFile $libTmp -UseBasicParsing
. $libTmp

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

Assert-SbAdmin
$target = Get-SbArchTarget
$version = Get-SbLatestVersion -GithubRepo $GithubRepo

$tmpDir = [System.IO.Path]::GetTempPath() + [System.IO.Path]::GetRandomFileName()
New-Item -ItemType Directory -Path $tmpDir | Out-Null

try {
    $assetName = "ferro-sentry-$target.zip"
    $zipPath = Get-SbReleaseAsset -GithubRepo $GithubRepo -Version $version -AssetName $assetName -TmpDir $tmpDir
    Install-SbBinaryFromZip -ZipPath $zipPath -BinaryName $BinaryName -InstallDir $InstallDir -ServiceName $ServiceName

    # ─── Configuration ────────────────────────────────────────────────────────
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null

    if ($Mode -eq "local_agent" -or $Mode -eq "agent") {
        $Mode = "agent"
        if (-not $Endpoint) { $Endpoint = "http://localhost:4317" }
        Write-SbInfo "Mode: agent — Ferro-Sentry will send events to $Endpoint"
    }

    if (-not $Endpoint) {
        $Endpoint = Read-Host "  SecuryBlack API endpoint (e.g. https://api.securyblack.com)"
    }
    if (-not $Token) {
        $secToken = Read-Host "  Auth token" -AsSecureString
        $Token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secToken))
    }

    if (-not $Endpoint) { Invoke-SbFail "Endpoint cannot be empty" }
    if (-not $Token) { Invoke-SbFail "Token cannot be empty" }

    Write-SbInfo "Writing config to $ConfigFile..."
    if ($Mode -eq "") { $Mode = "direct" }
    @"
# Ferro-Sentry configuration
# Do not share this file — it contains your auth token.
version = "$version"
mode = "$Mode"
api_url = "$Endpoint"
token = "$Token"
log_level = "info"
local_file_path = "C:/ProgramData/ferro-sentry/ferro-sentry_events.jsonl"
"@ | Set-Content -Path $ConfigFile

    Write-SbSuccess "Config written"

    # ─── Windows Service ──────────────────────────────────────────────────────
    Register-SbWindowsService -ServiceName $ServiceName -DisplayName "Ferro-Sentry Security Agent" `
        -BinaryPath "`"$InstallDir\$BinaryName`"" `
        -Description "SecuryBlack Ferro-Sentry security agent (EDR + Posture)"

    Write-SbSuccess "Ferro-Sentry has been successfully installed and started!"

} finally {
    if (Test-Path $tmpDir) {
        Remove-Item -Path $tmpDir -Recurse -Force
    }
}
