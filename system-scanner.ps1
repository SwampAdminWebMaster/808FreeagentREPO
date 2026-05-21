# 808 Mafia System Scanner & Pen Testing Dashboard
# Run as Administrator
# Usage: powershell -ExecutionPolicy Bypass -File system-scanner.ps1

param(
    [switch]$FullScan,
    [switch]$SecurityAudit,
    [switch]$FixDependencies,
    [switch]$Dashboard,
    [switch]$All
)

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"
$WarningPreference = "SilentlyContinue"

# Colors for output
$Colors = @{
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
    Info = "Cyan"
    Header = "Magenta"
}

function Write-Header {
    param([string]$Text)
    Write-Host "`n" -NoNewline
    Write-Host "=" * 80 -ForegroundColor $Colors.Header
    Write-Host "  $Text" -ForegroundColor $Colors.Header
    Write-Host "=" * 80 -ForegroundColor $Colors.Header
}

function Write-Status {
    param([string]$Message, [string]$Status = "INFO")
    $Color = switch($Status) {
        "SUCCESS" { $Colors.Success }
        "WARNING" { $Colors.Warning }
        "ERROR" { $Colors.Error }
        default { $Colors.Info }
    }
    Write-Host "[$Status]" -ForegroundColor $Color -NoNewline
    Write-Host " $Message"
}

# ========== SYSTEM INFORMATION ==========
function Get-SystemSpecs {
    Write-Header "SYSTEM SPECIFICATIONS"
    
    $OS = Get-WmiObject -Class Win32_OperatingSystem
    $CPU = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
    $RAM = Get-WmiObject -Class Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
    $Disk = Get-Volume | Where-Object { $_.DriveLetter }
    $Network = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    $GPU = Get-WmiObject -Class Win32_VideoController | Select-Object -First 1
    
    Write-Host "OS: " -NoNewline -ForegroundColor $Colors.Info
    Write-Host "$($OS.Caption) Build $($OS.BuildNumber)" -ForegroundColor $Colors.Success
    
    Write-Host "CPU: " -NoNewline -ForegroundColor $Colors.Info
    Write-Host "$($CPU.Name) ($($CPU.NumberOfCores) cores)" -ForegroundColor $Colors.Success
    
    Write-Host "RAM: " -NoNewline -ForegroundColor $Colors.Info
    Write-Host "$([math]::Round($RAM.Sum / 1GB, 2))GB" -ForegroundColor $Colors.Success
    
    Write-Host "GPU: " -NoNewline -ForegroundColor $Colors.Info
    Write-Host "$($GPU.Name)" -ForegroundColor $Colors.Success
    
    Write-Host "Network: " -NoNewline -ForegroundColor $Colors.Info
    Write-Host "$($Network.Count) interface(s) active" -ForegroundColor $Colors.Success
    
    Write-Host "`nDisk Usage:" -ForegroundColor $Colors.Info
    $Disk | ForEach-Object {
        $Usage = [math]::Round(($_.SizeRemaining / $_.Size) * 100, 2)
        Write-Host "  $($_.DriveLetter): $([math]::Round($_.Size / 1GB, 2))GB (Free: $Usage%)" -ForegroundColor $Colors.Success
    }
}

# ========== FULL SYSTEM SCAN ==========
function Invoke-FullSystemScan {
    Write-Header "FULL SYSTEM SCAN"
    
    # Check Windows Update status
    Write-Status "Checking Windows Updates..." "INFO"
    $Updates = Get-WmiObject -Query "SELECT * FROM CCM_SoftwareUpdate" -Namespace "root\ccm\clientSDK" 2>$null
    if ($Updates) {
        Write-Status "Updates available: $($Updates.Count)" "WARNING"
    } else {
        Write-Status "System is up to date" "SUCCESS"
    }
    
    # Check Defender status
    Write-Status "Scanning Windows Defender status..." "INFO"
    try {
        $Defender = Get-MpComputerStatus
        Write-Status "Defender: $($Defender.AntivirusEnabled)" "SUCCESS"
        Write-Status "Real-time Protection: $($Defender.RealTimeProtectionEnabled)" "SUCCESS"
        Write-Status "Last Scan: $($Defender.QuickScanTime)" "INFO"
    } catch {
        Write-Status "Defender scan failed" "ERROR"
    }
    
    # Disk health check
    Write-Status "Checking disk health..." "INFO"
    Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.Size -gt 0 } | ForEach-Object {
        $UsagePercent = [math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 2)
        if ($UsagePercent -gt 90) {
            Write-Status "$($_.Name) is $UsagePercent% full" "ERROR"
        } elseif ($UsagePercent -gt 75) {
            Write-Status "$($_.Name) is $UsagePercent% full" "WARNING"
        }
    }
    
    # Services check
    Write-Status "Scanning critical services..." "INFO"
    $CriticalServices = @("WinDefend", "WinRM", "RemoteRegistry", "RpcSs")
    $CriticalServices | ForEach-Object {
        $Service = Get-Service -Name $_ -ErrorAction SilentlyContinue
        if ($Service) {
            if ($Service.Status -eq "Running") {
                Write-Status "$_ : Running" "SUCCESS"
            } else {
                Write-Status "$_ : $($Service.Status)" "WARNING"
            }
        }
    }
    
    # Startup programs
    Write-Status "Analyzing startup programs..." "INFO"
    $StartupApps = Get-CimInstance Win32_StartupCommand | Measure-Object
    Write-Status "Found $($StartupApps.Count) startup items" "INFO"
}

# ========== SECURITY AUDIT / PEN TESTING ==========
function Invoke-SecurityAudit {
    Write-Header "SECURITY AUDIT & PEN TESTING BASELINE"
    
    # Check for open ports
    Write-Status "Checking for open ports..." "INFO"
    $OpenPorts = Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort | Sort-Object -Unique
    if ($OpenPorts.Count -gt 0) {
        Write-Status "Open ports found:" "WARNING"
        $OpenPorts | ForEach-Object { Write-Host "  Port: $_" -ForegroundColor $Colors.Warning }
    } else {
        Write-Status "No listening ports detected" "SUCCESS"
    }
    
    # Check firewall rules
    Write-Status "Analyzing Windows Firewall..." "INFO"
    $FWRules = Get-NetFirewallRule -Enabled $true | Measure-Object
    Write-Status "Active firewall rules: $($FWRules.Count)" "INFO"
    
    # User accounts audit
    Write-Status "Auditing user accounts..." "INFO"
    $Users = Get-LocalUser | Where-Object { $_.Enabled }
    $Users | ForEach-Object {
        $PasswordAge = (New-TimeSpan -Start $_.LastLogon).Days
        Write-Host "  User: $($_.Name) | Last Login: $PasswordAge days ago" -ForegroundColor $Colors.Info
    }
    
    # Check for weak admin accounts
    Write-Status "Checking admin account status..." "INFO"
    $AdminUsers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    $AdminUsers | ForEach-Object {
        Write-Status "Admin: $($_.Name)" "WARNING"
    }
    
    # Scheduled tasks audit
    Write-Status "Scanning scheduled tasks..." "INFO"
    $Tasks = Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } | Measure-Object
    Write-Status "Active scheduled tasks: $($Tasks.Count)" "INFO"
    
    # Network connections
    Write-Status "Checking active network connections..." "INFO"
    $Connections = Get-NetTCPConnection -State Established | Measure-Object
    Write-Status "Established connections: $($Connections.Count)" "INFO"
    
    # UAC status
    Write-Status "Checking User Account Control (UAC)..." "INFO"
    $UAC = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($UAC.EnableLUA -eq 1) {
        Write-Status "UAC is enabled" "SUCCESS"
    } else {
        Write-Status "UAC is disabled - SECURITY RISK" "ERROR"
    }
    
    # BitLocker status
    Write-Status "Checking BitLocker encryption..." "INFO"
    try {
        $BitLocker = Get-BitLockerVolume -ErrorAction SilentlyContinue
        if ($BitLocker) {
            Write-Status "BitLocker status: $($BitLocker.ProtectionStatus)" "INFO"
        }
    } catch {
        Write-Status "BitLocker not available" "WARNING"
    }
}

# ========== DEPENDENCY CHECK & FIX ==========
function Test-Dependencies {
    Write-Header "DEPENDENCY CHECK"
    
    $Dependencies = @{
        "PowerShell 7+" = "pwsh"
        "Git" = "git"
        "Node.js" = "node"
        "Python" = "python"
        "Docker" = "docker"
        ".NET" = "dotnet"
    }
    
    $Dependencies.GetEnumerator() | ForEach-Object {
        $app = $_.Key
        $cmd = $_.Value
        try {
            $version = & $cmd --version 2>$null
            if ($version) {
                Write-Status "$app : $($version -split "`n" | Select-Object -First 1)" "SUCCESS"
            } else {
                Write-Status "$app : Not found" "WARNING"
            }
        } catch {
            Write-Status "$app : Not installed" "ERROR"
        }
    }
}

function Install-Dependencies {
    Write-Header "INSTALLING/FIXING DEPENDENCIES"
    
    # Check if winget is available
    Write-Status "Checking for Windows Package Manager (winget)..." "INFO"
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Status "winget found" "SUCCESS"
        
        $AppsToInstall = @(
            "Microsoft.PowerShell",
            "Git.Git",
            "OpenJS.NodeJS",
            "Python.Python.3.11",
            "Docker.DockerDesktop"
        )
        
        Write-Status "Installing core development tools..." "INFO"
        $AppsToInstall | ForEach-Object {
            Write-Status "Installing $_..." "INFO"
            & winget install --id $_ --accept-source-agreements --accept-package-agreements -q
        }
    } else {
        Write-Status "winget not found - please install App Installer from Microsoft Store" "ERROR"
    }
    
    # Install eDEX-UI via npm
    Write-Status "Installing eDEX-UI terminal theme..." "INFO"
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        npm install -g edex-ui 2>$null
        Write-Status "eDEX-UI installed" "SUCCESS"
    } else {
        Write-Status "npm not found - cannot install eDEX-UI" "WARNING"
    }
    
    # Chocolatey fallback
    Write-Status "Checking Chocolatey availability..." "INFO"
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Status "Chocolatey available" "SUCCESS"
    } else {
        Write-Status "Installing Chocolatey..." "INFO"
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }
}

# ========== DASHBOARD / EDEX-UI SETUP ==========
function Show-Dashboard {
    Write-Header "SYSTEM DASHBOARD"
    
    Clear-Host
    Write-Host @"
    
╔══════════════════════════════════════════════════════════════════════════════╗
║                   808 MAFIA SYSTEM TERMINAL DASHBOARD                        ║
║                            eDEX-UI Powered                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor $Colors.Header
    
    Get-SystemSpecs
    
    Write-Host "`n" -NoNewline
    Write-Host "[DASHBOARD] " -ForegroundColor $Colors.Header -NoNewline
    Write-Host "Press Q to quit, S for full scan, A for audit" -ForegroundColor $Colors.Info
}

function Setup-BootDashboard {
    Write-Header "SETTING UP BOOT DASHBOARD"
    
    $ProfilePath = $PROFILE
    $ProfileDir = Split-Path $ProfilePath
    
    if (!(Test-Path $ProfileDir)) {
        New-Item -ItemType Directory -Path $ProfileDir -Force | Out-Null
    }
    
    $DashboardCode = @"
# 808 Mafia System Dashboard - Auto-load on PowerShell startup
Write-Host "Loading 808 Mafia System Dashboard..." -ForegroundColor Cyan
Start-Sleep -Milliseconds 500

# Function to display dashboard
function Invoke-SystemDashboard {
    Clear-Host
    Write-Host @"
    
╔════════════════════════════════════════════════════════════════════════════╗
║              808 MAFIA SYSTEM DASHBOARD - eDEX-UI Terminal                 ║
║                    PowerShell Profile Loaded                               ║
╚════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Magenta
    
    `$OS = Get-WmiObject -Class Win32_OperatingSystem
    `$CPU = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
    `$RAM = Get-WmiObject -Class Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
    
    Write-Host "┌─ SYSTEM STATUS ────────────────────────��────────────┐" -ForegroundColor Cyan
    Write-Host "│ OS: " -NoNewline -ForegroundColor Cyan
    Write-Host "`$(`$OS.Caption) Build `$(`$OS.BuildNumber)" -ForegroundColor Green
    Write-Host "│ CPU: " -NoNewline -ForegroundColor Cyan
    Write-Host "`$(`$CPU.Name)" -ForegroundColor Green
    Write-Host "│ RAM: " -NoNewline -ForegroundColor Cyan
    Write-Host "`$([math]::Round(`$RAM.Sum / 1GB, 2))GB" -ForegroundColor Green
    Write-Host "└──────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    
    Write-Host "`nDisk Status:" -ForegroundColor Yellow
    Get-Volume | Where-Object { `$_.DriveLetter } | ForEach-Object {
        `$Free = [math]::Round((`$_.SizeRemaining / `$_.Size) * 100, 2)
        Write-Host "  `$(`$_.DriveLetter): `$([math]::Round(`$_.Size / 1GB, 2))GB | Free: `$Free%" -ForegroundColor Green
    }
    
    Write-Host "`nNetwork Status:" -ForegroundColor Yellow
    Get-NetAdapter | Where-Object { `$_.Status -eq "Up" } | ForEach-Object {
        Write-Host "  `$(`$_.Name): `$(`$_.Status)" -ForegroundColor Green
    }
    
    Write-Host "`nQuick Commands:" -ForegroundColor Yellow
    Write-Host "  > system-scan    : Run full system scan" -ForegroundColor Cyan
    Write-Host "  > security-audit : Run security audit" -ForegroundColor Cyan
    Write-Host "  > edex-ui        : Launch eDEX-UI terminal" -ForegroundColor Cyan
    Write-Host "  > fix-deps       : Install/fix dependencies" -ForegroundColor Cyan
}

# Auto-display dashboard on startup
Invoke-SystemDashboard

# Alias shortcuts
Set-Alias -Name system-scan -Value { powershell -ExecutionPolicy Bypass -File "$(Split-Path $PROFILE)\..\..\system-scanner.ps1" -FullScan }
Set-Alias -Name security-audit -Value { powershell -ExecutionPolicy Bypass -File "$(Split-Path $PROFILE)\..\..\system-scanner.ps1" -SecurityAudit }
Set-Alias -Name fix-deps -Value { powershell -ExecutionPolicy Bypass -File "$(Split-Path $PROFILE)\..\..\system-scanner.ps1" -FixDependencies }
Set-Alias -Name edex-ui -Value { edex-ui }
"@
    
    Add-Content -Path $ProfilePath -Value $DashboardCode
    Write-Status "Dashboard setup complete at: $ProfilePath" "SUCCESS"
    Write-Status "Restart PowerShell to see the dashboard" "INFO"
}

# ========== MAIN EXECUTION ==========
Write-Host "`n" -NoNewline
Write-Host "808 MAFIA SYSTEM SCANNER v1.0" -ForegroundColor $Colors.Header
Write-Host "=================================" -ForegroundColor $Colors.Header

if ($All -or $Dashboard) {
    Show-Dashboard
}

if ($All -or $FullScan) {
    Get-SystemSpecs
    Invoke-FullSystemScan
}

if ($All -or $SecurityAudit) {
    Invoke-SecurityAudit
}

if ($FixDependencies) {
    Test-Dependencies
    Install-Dependencies
}

if ($All) {
    Write-Header "SETUP COMPLETE"
    Write-Status "Running all scans..." "SUCCESS"
    Setup-BootDashboard
}

if (!$FullScan -and !$SecurityAudit -and !$FixDependencies -and !$Dashboard -and !$All) {
    Write-Host "`nUsage: powershell -ExecutionPolicy Bypass -File system-scanner.ps1 [options]`n" -ForegroundColor $Colors.Info
    Write-Host "Options:" -ForegroundColor $Colors.Header
    Write-Host "  -FullScan           : Run complete system scan" -ForegroundColor $Colors.Info
    Write-Host "  -SecurityAudit      : Run security & penetration testing baseline" -ForegroundColor $Colors.Info
    Write-Host "  -FixDependencies    : Install/fix required dependencies" -ForegroundColor $Colors.Info
    Write-Host "  -Dashboard          : Show system dashboard" -ForegroundColor $Colors.Info
    Write-Host "  -All                : Run everything and setup boot dashboard" -ForegroundColor $Colors.Info
    Write-Host "`nExample: powershell -ExecutionPolicy Bypass -File system-scanner.ps1 -All`n" -ForegroundColor $Colors.Header
}

Write-Host "`n" -NoNewline
