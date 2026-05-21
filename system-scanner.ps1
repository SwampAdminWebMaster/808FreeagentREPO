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
    Write-Host ("=" * 80) -ForegroundColor $Colors.Header
    Write-Host "  $Text" -ForegroundColor $Colors.Header
    Write-Host ("=" * 80) -ForegroundColor $Colors.Header
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
    $Updates = Get-WmiObject -Query "SELECT * FROM CCM_SoftwareUpdate" -Namespace "root\ccm\clientSDK" -ErrorAction SilentlyContinue 2>$null
    if ($Updates) {
        Write-Status "Updates available: $($Updates.Count)" "WARNING"
    } else {
        Write-Status "System is up to date" "SUCCESS"
    }
    
    # Check Defender status
    Write-Status "Scanning Windows Defender status..." "INFO"
    try {
        $Defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($Defender) {
            Write-Status "Defender: $($Defender.AntivirusEnabled)" "SUCCESS"
            Write-Status "Real-time Protection: $($Defender.RealTimeProtectionEnabled)" "SUCCESS"
            Write-Status "Last Scan: $($Defender.QuickScanTime)" "INFO"
        }
    } catch {
        Write-Status "Defender scan not available" "WARNING"
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
    $CriticalServices = @("WinDefend", "RpcSs", "BITS")
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
    $StartupApps = Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Measure-Object
    Write-Status "Found $($StartupApps.Count) startup items" "INFO"
}

# ========== SECURITY AUDIT / PEN TESTING ==========
function Invoke-SecurityAudit {
    Write-Header "SECURITY AUDIT & PEN TESTING BASELINE"
    
    # Check for open ports
    Write-Status "Checking for open ports..." "INFO"
    $OpenPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object
    if ($OpenPorts.Count -gt 0) {
        Write-Status "Open ports found:" "WARNING"
        $OpenPorts | ForEach-Object { Write-Host "  Port: $_" -ForegroundColor $Colors.Warning }
    } else {
        Write-Status "No listening ports detected" "SUCCESS"
    }
    
    # Check firewall rules
    Write-Status "Analyzing Windows Firewall..." "INFO"
    try {
        $FWRules = Get-NetFirewallRule -Enabled $true -ErrorAction SilentlyContinue | Measure-Object
        Write-Status "Active firewall rules: $($FWRules.Count)" "INFO"
    } catch {
        Write-Status "Firewall check not available" "WARNING"
    }
    
    # User accounts audit
    Write-Status "Auditing user accounts..." "INFO"
    try {
        $Users = Get-LocalUser | Where-Object { $_.Enabled } -ErrorAction SilentlyContinue
        $Users | ForEach-Object {
            Write-Host "  User: $($_.Name)" -ForegroundColor $Colors.Info
        }
    } catch {
        Write-Status "User audit not available" "WARNING"
    }
    
    # Check for admin accounts
    Write-Status "Checking admin account status..." "INFO"
    try {
        $AdminUsers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        if ($AdminUsers) {
            Write-Status "Admin accounts found: $($AdminUsers.Count)" "WARNING"
        }
    } catch {
        Write-Status "Admin check not available" "WARNING"
    }
    
    # Scheduled tasks audit
    Write-Status "Scanning scheduled tasks..." "INFO"
    try {
        $Tasks = Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } -ErrorAction SilentlyContinue | Measure-Object
        Write-Status "Active scheduled tasks: $($Tasks.Count)" "INFO"
    } catch {
        Write-Status "Task scan not available" "WARNING"
    }
    
    # Network connections
    Write-Status "Checking active network connections..." "INFO"
    try {
        $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Measure-Object
        Write-Status "Established connections: $($Connections.Count)" "INFO"
    } catch {
        Write-Status "Connection check not available" "WARNING"
    }
    
    # UAC status
    Write-Status "Checking User Account Control (UAC)..." "INFO"
    try {
        $UAC = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
        if ($UAC.EnableLUA -eq 1) {
            Write-Status "UAC is enabled" "SUCCESS"
        } else {
            Write-Status "UAC is disabled - SECURITY RISK" "ERROR"
        }
    } catch {
        Write-Status "UAC check not available" "WARNING"
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
    }
    
    $Dependencies.GetEnumerator() | ForEach-Object {
        $app = $_.Key
        $cmd = $_.Value
        try {
            $version = & $cmd --version 2>$null | Select-Object -First 1
            if ($version) {
                Write-Status "$app : $version" "SUCCESS"
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
    } else {
        Write-Status "winget not found - install App Installer from Microsoft Store" "ERROR"
        return
    }
    
    Write-Status "Installing core development tools..." "INFO"
    Write-Status "Git..." "INFO"
    winget install --id Git.Git --accept-source-agreements --accept-package-agreements -q 2>$null
    
    Write-Status "Node.js..." "INFO"
    winget install --id OpenJS.NodeJS --accept-source-agreements --accept-package-agreements -q 2>$null
    
    Write-Status "Python..." "INFO"
    winget install --id Python.Python.3.11 --accept-source-agreements --accept-package-agreements -q 2>$null
    
    Write-Status "Dependencies installation complete" "SUCCESS"
}

# ========== DASHBOARD ==========
function Show-Dashboard {
    Clear-Host
    Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                   808 MAFIA SYSTEM TERMINAL DASHBOARD                        ║
║                         Windows Security Audit                               ║
╚══════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor $Colors.Header
    
    Get-SystemSpecs
    
    Write-Host "`n[DASHBOARD]" -ForegroundColor $Colors.Header -NoNewline
    Write-Host " System dashboard loaded - Press Q to quit" -ForegroundColor $Colors.Info
}

function Setup-BootDashboard {
    Write-Header "SETTING UP BOOT DASHBOARD"
    
    $ProfilePath = $PROFILE
    $ProfileDir = Split-Path $ProfilePath
    
    if (!(Test-Path $ProfileDir)) {
        New-Item -ItemType Directory -Path $ProfileDir -Force | Out-Null
    }
    
    $DashboardCode = @'

# 808 Mafia System Dashboard - Auto-load on PowerShell startup
Write-Host "Loading 808 Mafia System Dashboard..." -ForegroundColor Cyan
Start-Sleep -Milliseconds 500

function Invoke-SystemDashboard {
    Clear-Host
    Write-Host "╔═══════════════════════════════════════════════════════════════════════════��╗" -ForegroundColor Magenta
    Write-Host "║              808 MAFIA SYSTEM DASHBOARD - PowerShell Terminal               ║" -ForegroundColor Magenta
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""
    
    $OS = Get-WmiObject -Class Win32_OperatingSystem
    $CPU = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
    $RAM = Get-WmiObject -Class Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
    
    Write-Host "┌─ SYSTEM STATUS ────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "│ OS: $($OS.Caption) Build $($OS.BuildNumber)" -ForegroundColor Cyan
    Write-Host "│ CPU: $($CPU.Name)" -ForegroundColor Cyan
    Write-Host "│ RAM: $([math]::Round($RAM.Sum / 1GB, 2))GB" -ForegroundColor Cyan
    Write-Host "└─────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host "Disk Status:" -ForegroundColor Yellow
    Get-Volume | Where-Object { $_.DriveLetter } | ForEach-Object {
        $Free = [math]::Round(($_.SizeRemaining / $_.Size) * 100, 2)
        Write-Host "  $($_.DriveLetter): $([math]::Round($_.Size / 1GB, 2))GB | Free: $Free%" -ForegroundColor Green
    }
    Write-Host ""
}

Invoke-SystemDashboard

'@
    
    if (Test-Path $ProfilePath) {
        Add-Content -Path $ProfilePath -Value $DashboardCode
    } else {
        Set-Content -Path $ProfilePath -Value $DashboardCode
    }
    
    Write-Status "Dashboard setup complete" "SUCCESS"
    Write-Status "Restart PowerShell to see the dashboard on boot" "INFO"
}

# ========== MAIN EXECUTION ==========
Write-Host "`n" -NoNewline
Write-Host "808 MAFIA SYSTEM SCANNER v1.0 - FIXED" -ForegroundColor $Colors.Header
Write-Host ("=" * 50) -ForegroundColor $Colors.Header

if ($All) {
    Show-Dashboard
    Get-SystemSpecs
    Invoke-FullSystemScan
    Invoke-SecurityAudit
    Test-Dependencies
    Setup-BootDashboard
    Write-Header "ALL SCANS COMPLETE"
    Write-Status "System audit finished successfully" "SUCCESS"
}
elseif ($Dashboard) {
    Show-Dashboard
}
elseif ($FullScan) {
    Get-SystemSpecs
    Invoke-FullSystemScan
}
elseif ($SecurityAudit) {
    Invoke-SecurityAudit
}
elseif ($FixDependencies) {
    Test-Dependencies
    Install-Dependencies
}
else {
    Write-Host "`nUsage:`n" -ForegroundColor $Colors.Info
    Write-Host "powershell -ExecutionPolicy Bypass -File system-scanner.ps1 -All`n" -ForegroundColor $Colors.Header
    Write-Host "Options:" -ForegroundColor $Colors.Header
    Write-Host "  -All                : Run everything (recommended)" -ForegroundColor $Colors.Info
    Write-Host "  -Dashboard          : Show system dashboard" -ForegroundColor $Colors.Info
    Write-Host "  -FullScan           : Run complete system scan" -ForegroundColor $Colors.Info
    Write-Host "  -SecurityAudit      : Run security & pen testing" -ForegroundColor $Colors.Info
    Write-Host "  -FixDependencies    : Install missing tools`n" -ForegroundColor $Colors.Info
}

Write-Host ""
