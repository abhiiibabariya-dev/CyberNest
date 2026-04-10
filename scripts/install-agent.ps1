<#
.SYNOPSIS
    CyberNest Agent Installer for Windows

.DESCRIPTION
    Downloads, configures, and installs the CyberNest security agent as a Windows service.

.PARAMETER ManagerUrl
    The CyberNest Manager WebSocket URL (e.g., wss://server:5601/ws/agent)

.PARAMETER ApiKey
    Agent API key from CyberNest Manager

.PARAMETER InstallDir
    Installation directory (default: C:\Program Files\CyberNest)

.EXAMPLE
    .\install-agent.ps1 -ManagerUrl "wss://server:5601/ws/agent" -ApiKey "your-key"
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ManagerUrl = $env:MANAGER_URL,

    [Parameter(Mandatory=$false)]
    [string]$ApiKey = $env:API_KEY,

    [string]$InstallDir = "C:\Program Files\CyberNest"
)

$ErrorActionPreference = "Stop"

# Colors
function Write-Info  { Write-Host "[INFO]  $args" -ForegroundColor Cyan }
function Write-Ok    { Write-Host "[OK]    $args" -ForegroundColor Green }
function Write-Err   { Write-Host "[ERROR] $args" -ForegroundColor Red; exit 1 }

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Err "This script must be run as Administrator"
}

if (-not $ManagerUrl) { Write-Err "ManagerUrl is required. Set -ManagerUrl or `$env:MANAGER_URL" }
if (-not $ApiKey)     { Write-Err "ApiKey is required. Set -ApiKey or `$env:API_KEY" }

Write-Host ""
Write-Host "  +=============================================+" -ForegroundColor Cyan
Write-Host "  |     CyberNest Agent Installer (Windows)     |" -ForegroundColor Cyan
Write-Host "  +=============================================+" -ForegroundColor Cyan
Write-Host ""

# Check Python
Write-Info "Checking Python..."
$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3\.") {
            $pythonCmd = $cmd
            break
        }
    } catch {}
}

if (-not $pythonCmd) {
    Write-Info "Python 3 not found. Installing via winget..."
    try {
        winget install Python.Python.3.13 --accept-package-agreements --accept-source-agreements --silent
        $pythonCmd = "python"
    } catch {
        Write-Err "Cannot install Python 3. Please install from https://python.org"
    }
}
Write-Ok "Python found: $(& $pythonCmd --version)"

# Create directories
Write-Info "Creating directories..."
$configDir = "$InstallDir\config"
$logDir = "$InstallDir\logs"
$stateDir = "$InstallDir\state"
foreach ($dir in @($InstallDir, $configDir, $logDir, $stateDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

# Download agent files
Write-Info "Downloading CyberNest agent..."
$repoUrl = "https://github.com/abhiiibabariya-dev/CyberNest/archive/refs/heads/master.zip"
$zipPath = "$env:TEMP\cybernest-master.zip"
$extractPath = "$env:TEMP\cybernest-extract"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $repoUrl -OutFile $zipPath -UseBasicParsing
    if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
    $agentSrc = Get-ChildItem -Path $extractPath -Directory | Select-Object -First 1
    Copy-Item -Path "$($agentSrc.FullName)\agent\*" -Destination $InstallDir -Recurse -Force
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
} catch {
    Write-Info "Download failed, continuing with existing files..."
}
Write-Ok "Agent files ready"

# Create virtual environment
Write-Info "Setting up Python environment..."
& $pythonCmd -m venv "$InstallDir\venv"
& "$InstallDir\venv\Scripts\pip.exe" install --quiet --upgrade pip
if (Test-Path "$InstallDir\requirements.txt") {
    & "$InstallDir\venv\Scripts\pip.exe" install --quiet -r "$InstallDir\requirements.txt"
} else {
    & "$InstallDir\venv\Scripts\pip.exe" install --quiet psutil watchdog aiohttp pyyaml python-dateutil structlog pywin32
}
Write-Ok "Dependencies installed"

# Write configuration
Write-Info "Writing configuration..."
$config = @"
manager:
  url: "$ManagerUrl"
  api_key: "$ApiKey"

tls:
  enabled: false
  ca_cert: "$configDir\certs\ca.pem"
  client_cert: "$configDir\certs\agent.pem"
  client_key: "$configDir\certs\agent-key.pem"

collectors:
  windows_event:
    enabled: true
    channels:
      - Security
      - System
      - Application
      - Microsoft-Windows-PowerShell/Operational
      - Microsoft-Windows-Sysmon/Operational

  fim:
    enabled: true
    paths:
      - C:\Windows\System32
      - C:\Windows\SysWOW64
      - C:\Program Files
    exclude_patterns:
      - "*.log"
      - "*.tmp"
      - "*.etl"

  process_monitor:
    enabled: true
    interval_seconds: 10

  network_monitor:
    enabled: true
    interval_seconds: 15

  registry_monitor:
    enabled: true

heartbeat_interval: 30
batch_size: 50
batch_timeout: 1.0
log_level: INFO
state_file: "$stateDir\agent-state.json"
"@
$config | Out-File -FilePath "$configDir\cybernest-agent.yml" -Encoding UTF8
Write-Ok "Configuration written"

# Register as Windows service using NSSM or sc.exe
Write-Info "Registering Windows service..."
$serviceName = "CyberNestAgent"
$pythonExe = "$InstallDir\venv\Scripts\python.exe"
$agentScript = "$InstallDir\cybernest_agent.py"
$serviceArgs = "`"$agentScript`" --config `"$configDir\cybernest-agent.yml`""

# Try to create service
try {
    # Remove existing service if present
    $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existing) {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $serviceName 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }

    # Create service
    & sc.exe create $serviceName binPath= "`"$pythonExe`" $serviceArgs" start= auto DisplayName= "CyberNest Security Agent" 2>&1 | Out-Null
    & sc.exe description $serviceName "CyberNest SIEM endpoint agent - collects security events and forwards to manager" 2>&1 | Out-Null
    & sc.exe failure $serviceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 2>&1 | Out-Null

    Start-Service -Name $serviceName
    Write-Ok "Service '$serviceName' created and started"
} catch {
    Write-Info "Service registration failed. Start manually:"
    Write-Host "  & `"$pythonExe`" `"$agentScript`" --config `"$configDir\cybernest-agent.yml`""
}

# Add firewall rule
try {
    New-NetFirewallRule -DisplayName "CyberNest Agent" -Direction Outbound -Action Allow -Program $pythonExe -ErrorAction SilentlyContinue | Out-Null
    Write-Ok "Firewall rule added"
} catch {}

Write-Host ""
Write-Host "  +=============================================+" -ForegroundColor Green
Write-Host "  |  CyberNest Agent installed successfully!    |" -ForegroundColor Green
Write-Host "  +=============================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  Install dir:  $InstallDir" -ForegroundColor White
Write-Host "  Config:       $configDir\cybernest-agent.yml" -ForegroundColor White
Write-Host "  Service:      $serviceName" -ForegroundColor White
Write-Host "  Logs:         $logDir" -ForegroundColor White
Write-Host ""
Write-Host "  Commands:" -ForegroundColor Yellow
Write-Host "    Get-Service $serviceName          # Check status"
Write-Host "    Restart-Service $serviceName       # Restart"
Write-Host "    Stop-Service $serviceName          # Stop"
Write-Host ""
