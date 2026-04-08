<#
.SYNOPSIS
    CyberNest Agent Installer for Windows

.DESCRIPTION
    Downloads and installs the CyberNest SIEM agent as a Windows service.
    Supports installation via NSSM (preferred) or sc.exe (fallback).

.PARAMETER ManagerUrl
    URL of the CyberNest Manager (e.g., https://siem.example.com)

.PARAMETER ApiKey
    Agent API key obtained from the CyberNest dashboard

.PARAMETER Version
    Agent version to install (default: latest)

.PARAMETER InstallDir
    Installation directory (default: C:\Program Files\CyberNest\Agent)

.PARAMETER Port
    Agent metrics port (default: 9100)

.EXAMPLE
    .\install-agent.ps1 -ManagerUrl https://siem.example.com -ApiKey YOUR_API_KEY

.EXAMPLE
    # One-liner (run in elevated PowerShell):
    iwr -useb https://raw.githubusercontent.com/abhiiibabariya-dev/CyberNest/main/scripts/install-agent.ps1 | iex
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManagerUrl,

    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [string]$Version = "latest",

    [string]$InstallDir = "C:\Program Files\CyberNest\Agent",

    [int]$Port = 9100
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ---------- Configuration ----------
$ServiceName = "CyberNestAgent"
$ServiceDisplayName = "CyberNest SIEM Agent"
$ServiceDescription = "CyberNest SIEM agent - collects and forwards security logs"
$ConfigDir = "C:\ProgramData\CyberNest"
$LogDir = "C:\ProgramData\CyberNest\logs"
$BinaryName = "cybernest-agent.exe"

# ---------- Helpers ----------
function Write-Step {
    param([string]$Message)
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[OK]    $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN]  $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# ---------- Check admin ----------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "This script requires Administrator privileges."
    Write-Host "  Right-click PowerShell and select 'Run as administrator'"
    exit 1
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  CyberNest Agent Installer - Windows" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

# ==========================================================================
# 1. Create directories
# ==========================================================================

Write-Step "Creating directories..."

foreach ($dir in @($InstallDir, $ConfigDir, $LogDir, "$InstallDir\buffer")) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Ok "Created $dir"
    }
    else {
        Write-Ok "Exists: $dir"
    }
}

# ==========================================================================
# 2. Stop existing service if running
# ==========================================================================

Write-Step "Checking for existing installation..."

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Warn "Existing service found (status: $($existingService.Status))"
    if ($existingService.Status -eq "Running") {
        Write-Host "  Stopping existing service..."
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 3
    }
    Write-Ok "Existing service stopped"
}

# ==========================================================================
# 3. Download agent binary
# ==========================================================================

Write-Step "Downloading CyberNest agent ($Version)..."

$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$downloadUrl = "$ManagerUrl/api/agents/download?version=$Version&os=windows&arch=$arch"
$binaryPath = Join-Path $InstallDir $BinaryName
$tempFile = [System.IO.Path]::GetTempFileName()

try {
    $headers = @{ "Authorization" = "Bearer $ApiKey" }
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -Headers $headers -UseBasicParsing
    Move-Item -Path $tempFile -Destination $binaryPath -Force
    Write-Ok "Agent downloaded to $binaryPath"
}
catch {
    Write-Warn "Could not download agent binary: $_"
    Write-Warn "Creating placeholder - download manually from your CyberNest Manager"

    $placeholderContent = @"
@echo off
echo [CyberNest Agent] Binary not yet installed. Download from your CyberNest Manager.
exit /b 1
"@
    Set-Content -Path (Join-Path $InstallDir "cybernest-agent.cmd") -Value $placeholderContent
    # Create a minimal exe placeholder note
    Set-Content -Path $binaryPath -Value "PLACEHOLDER - Replace with actual binary"
}
finally {
    Remove-Item -Path $tempFile -ErrorAction SilentlyContinue
}

# ==========================================================================
# 4. Write configuration
# ==========================================================================

Write-Step "Writing agent configuration..."

$configPath = Join-Path $ConfigDir "agent.yml"
$configContent = @"
# CyberNest Agent Configuration
# Generated by install-agent.ps1 on $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")

manager:
  url: "$ManagerUrl"
  api_key: "$ApiKey"
  tls_verify: true
  # ca_cert: C:\ProgramData\CyberNest\ca.crt  # Uncomment for self-signed certs

agent:
  id: ""  # Auto-generated on first run
  port: $Port
  log_level: info
  log_file: "$($LogDir -replace '\\', '/')/agent.log"
  buffer_dir: "$($InstallDir -replace '\\', '/')/buffer"
  max_buffer_size_mb: 256

collectors:
  windows_event_log:
    enabled: true
    channels:
      - name: Security
        event_ids: []  # Empty = all events
      - name: System
        event_ids: []
      - name: Application
        event_ids: []
      - name: Microsoft-Windows-Sysmon/Operational
        event_ids: []
      - name: Microsoft-Windows-PowerShell/Operational
        event_ids: [4103, 4104, 4105, 4106]
      - name: Microsoft-Windows-Windows Defender/Operational
        event_ids: []
      - name: Microsoft-Windows-WMI-Activity/Operational
        event_ids: []

  file:
    enabled: true
    paths:
      - path: C:/inetlogs/W3SVC1/u_ex*.log
        type: iis_access

  process:
    enabled: true
    interval_seconds: 60
    track_command_line: true

  network:
    enabled: true
    capture_dns: true
    capture_connections: true

  sysmon:
    enabled: true
    # Requires Sysmon to be installed separately

heartbeat:
  interval_seconds: 30
  timeout_seconds: 10

output:
  batch_size: 100
  flush_interval_seconds: 5
  compression: gzip
  retry_max: 5
  retry_backoff_seconds: 10
"@

Set-Content -Path $configPath -Value $configContent -Encoding UTF8
Write-Ok "Configuration written to $configPath"

# ==========================================================================
# 5. Install as Windows service
# ==========================================================================

Write-Step "Installing Windows service..."

$nssmPath = $null

# Check for NSSM
$nssmCheck = Get-Command nssm -ErrorAction SilentlyContinue
if ($nssmCheck) {
    $nssmPath = $nssmCheck.Source
}
elseif (Test-Path "C:\tools\nssm\nssm.exe") {
    $nssmPath = "C:\tools\nssm\nssm.exe"
}

if ($nssmPath) {
    # Install via NSSM (preferred)
    Write-Host "  Using NSSM for service installation..."

    & $nssmPath install $ServiceName $binaryPath "--config" $configPath 2>$null
    & $nssmPath set $ServiceName DisplayName $ServiceDisplayName 2>$null
    & $nssmPath set $ServiceName Description $ServiceDescription 2>$null
    & $nssmPath set $ServiceName Start SERVICE_AUTO_START 2>$null
    & $nssmPath set $ServiceName AppStdout "$LogDir\service-stdout.log" 2>$null
    & $nssmPath set $ServiceName AppStderr "$LogDir\service-stderr.log" 2>$null
    & $nssmPath set $ServiceName AppRotateFiles 1 2>$null
    & $nssmPath set $ServiceName AppRotateBytes 10485760 2>$null
    & $nssmPath set $ServiceName AppRestartDelay 10000 2>$null
    & $nssmPath set $ServiceName ObjectName LocalSystem 2>$null

    Write-Ok "Service installed via NSSM"
}
else {
    # Install via sc.exe (fallback)
    Write-Host "  NSSM not found, using sc.exe..."

    if ($existingService) {
        sc.exe delete $ServiceName 2>$null | Out-Null
        Start-Sleep -Seconds 2
    }

    $binPathEscaped = "`"$binaryPath`" --config `"$configPath`""
    sc.exe create $ServiceName `
        binPath= $binPathEscaped `
        DisplayName= $ServiceDisplayName `
        start= auto `
        obj= LocalSystem | Out-Null

    sc.exe description $ServiceName $ServiceDescription | Out-Null

    # Configure recovery: restart on first, second, and subsequent failures
    sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/10000/restart/30000 | Out-Null

    Write-Ok "Service installed via sc.exe"
}

# ==========================================================================
# 6. Configure Windows Firewall
# ==========================================================================

Write-Step "Configuring Windows Firewall..."

$firewallRule = Get-NetFirewallRule -DisplayName "CyberNest Agent" -ErrorAction SilentlyContinue
if (-not $firewallRule) {
    New-NetFirewallRule -DisplayName "CyberNest Agent" `
        -Description "Allow CyberNest Agent metrics and health check" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort $Port `
        -Action Allow `
        -Profile Domain, Private | Out-Null
    Write-Ok "Firewall rule created for port $Port"
}
else {
    Write-Ok "Firewall rule already exists"
}

# ==========================================================================
# 7. Start the service
# ==========================================================================

Write-Step "Starting CyberNest agent service..."

try {
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 3

    $svc = Get-Service -Name $ServiceName
    if ($svc.Status -eq "Running") {
        Write-Ok "CyberNest agent is running"
    }
    else {
        Write-Warn "Service status: $($svc.Status)"
        Write-Warn "Check logs at: $LogDir"
    }
}
catch {
    Write-Warn "Could not start service: $_"
    Write-Warn "Start manually: Start-Service $ServiceName"
}

# ==========================================================================
# 8. Summary
# ==========================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  CyberNest Agent - Installation Complete" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Install dir:    $InstallDir"
Write-Host "  Config:         $configPath"
Write-Host "  Logs:           $LogDir"
Write-Host "  Service:        $ServiceName"
Write-Host "  Manager URL:    $ManagerUrl"
Write-Host ""
Write-Host "  Useful commands:" -ForegroundColor Cyan
Write-Host "    Get-Service $ServiceName                 # Check status"
Write-Host "    Restart-Service $ServiceName              # Restart agent"
Write-Host "    Get-Content '$LogDir\agent.log' -Tail 50  # View logs"
Write-Host "    notepad '$configPath'                      # Edit config"
Write-Host ""
Write-Host "  To uninstall:" -ForegroundColor Yellow
Write-Host "    Stop-Service $ServiceName"
if ($nssmPath) {
    Write-Host "    nssm remove $ServiceName confirm"
}
else {
    Write-Host "    sc.exe delete $ServiceName"
}
Write-Host "    Remove-Item -Recurse '$InstallDir'"
Write-Host "    Remove-Item -Recurse '$ConfigDir'"
Write-Host ""
