# PC Forensic & System Analysis Tool
# Author: System Analysis Script
# Purpose: Gather system information and analyze artifacts

$ErrorActionPreference = "SilentlyContinue"

# Create output directory with timestamp
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outputDir = "$env:USERPROFILE\Desktop\PCForensics_$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$logFile = "$outputDir\forensic_report.txt"

function Write-Log {
    param($Message, $Color = "White")
    Write-Host $Message -ForegroundColor $Color
    Add-Content -Path $logFile -Value $Message
}

function Get-Separator {
    return "`n" + ("=" * 80) + "`n"
}

Write-Log "$(Get-Separator)" "Cyan"
Write-Log "PC FORENSIC & SYSTEM ANALYSIS TOOL" "Cyan"
Write-Log "Scan Started: $(Get-Date)" "Cyan"
Write-Log "$(Get-Separator)" "Cyan"

# ============================================================================
# SYSTEM INFORMATION
# ============================================================================
Write-Log "`n[*] Gathering System Information..." "Yellow"

$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$bios = Get-CimInstance -ClassName Win32_BIOS

Write-Log "`nComputer Name: $($computerSystem.Name)"
Write-Log "Username: $env:USERNAME"
Write-Log "Domain: $($computerSystem.Domain)"
Write-Log "OS: $($os.Caption) - Build $($os.BuildNumber)"
Write-Log "Install Date: $($os.InstallDate)"
Write-Log "Last Boot Time: $($os.LastBootUpTime)"
Write-Log "System Uptime: $((Get-Date) - $os.LastBootUpTime)"
Write-Log "BIOS Version: $($bios.SMBIOSBIOSVersion)"
Write-Log "Serial Number: $($bios.SerialNumber)"

# ============================================================================
# FACTORY RESET / INSTALL DATE DETECTION
# ============================================================================
Write-Log "`n[*] Checking for Factory Reset / Install History..." "Yellow"

$installDate = $os.InstallDate
Write-Log "`nWindows Installation Date: $installDate"

# Check for reset markers
$resetMarkers = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State",
    "HKLM:\SYSTEM\Setup"
)

foreach ($marker in $resetMarkers) {
    if (Test-Path $marker) {
        $values = Get-ItemProperty -Path $marker -ErrorAction SilentlyContinue
        if ($values) {
            Write-Log "`nSetup Registry Key: $marker"
            $values.PSObject.Properties | ForEach-Object {
                if ($_.Name -notlike "PS*") {
                    Write-Log "  $($_.Name): $($_.Value)"
                }
            }
        }
    }
}

# Check Event Logs for installation/reset events
Write-Log "`nChecking Event Logs for Reset/Install Events..."
$setupEvents = Get-WinEvent -LogName System -FilterXPath "*[System[EventID=1074 or EventID=6005 or EventID=6006]]" -MaxEvents 50 -ErrorAction SilentlyContinue
if ($setupEvents) {
    Write-Log "Recent System Events (Shutdown/Startup):"
    $setupEvents | Select-Object -First 10 | ForEach-Object {
        Write-Log "  [$($_.TimeCreated)] EventID: $($_.Id) - $($_.Message.Split("`n")[0])"
    }
}

# ============================================================================
# DISK INFORMATION & HISTORY
# ============================================================================
Write-Log "`n[*] Gathering Disk Information..." "Yellow"

$disks = Get-CimInstance -ClassName Win32_DiskDrive
Write-Log "`nPhysical Disks:"
foreach ($disk in $disks) {
    Write-Log "  Device: $($disk.DeviceID)"
    Write-Log "  Model: $($disk.Model)"
    Write-Log "  Serial: $($disk.SerialNumber)"
    Write-Log "  Size: $([math]::Round($disk.Size / 1GB, 2)) GB"
    Write-Log "  Interface: $($disk.InterfaceType)"
    Write-Log ""
}

$volumes = Get-Volume
Write-Log "Volumes/Partitions:"
foreach ($vol in $volumes) {
    if ($vol.DriveLetter) {
        Write-Log "  Drive $($vol.DriveLetter): - $($vol.FileSystemLabel)"
        Write-Log "    Size: $([math]::Round($vol.Size / 1GB, 2)) GB"
        Write-Log "    Free: $([math]::Round($vol.SizeRemaining / 1GB, 2)) GB"
        Write-Log "    FileSystem: $($vol.FileSystem)"
        Write-Log ""
    }
}

# USB History
Write-Log "`n[*] USB Device History..." "Yellow"
$usbDevices = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue
if ($usbDevices) {
    Write-Log "Previously Connected USB Devices:"
    $usbDevices | Select-Object FriendlyName, Mfg -Unique | ForEach-Object {
        if ($_.FriendlyName) {
            Write-Log "  $($_.FriendlyName) - $($_.Mfg)"
        }
    }
}

# ============================================================================
# USER ACCOUNT INFORMATION
# ============================================================================
Write-Log "`n[*] Gathering User Account Information..." "Yellow"

$localUsers = Get-LocalUser
Write-Log "`nLocal User Accounts:"
foreach ($user in $localUsers) {
    Write-Log "  Username: $($user.Name)"
    Write-Log "    Enabled: $($user.Enabled)"
    Write-Log "    Last Logon: $($user.LastLogon)"
    Write-Log "    Password Last Set: $($user.PasswordLastSet)"
    Write-Log ""
}

# ============================================================================
# MUICACHE ANALYSIS
# ============================================================================
Write-Log "`n[*] Analyzing MUICache (Application Execution History)..." "Yellow"

$muiCachePaths = @(
    "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKLM:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
)

$muiCacheFile = "$outputDir\muicache_entries.txt"
$suspiciousApps = @()

foreach ($path in $muiCachePaths) {
    if (Test-Path $path) {
        Write-Log "`nMUICache Path: $path"
        $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        if ($items) {
            $items.PSObject.Properties | ForEach-Object {
                if ($_.Name -notlike "PS*") {
                    $entry = "$($_.Name) = $($_.Value)"
                    Add-Content -Path $muiCacheFile -Value $entry
                    
                    # Check for suspicious keywords
                    $suspiciousKeywords = @("cheat", "hack", "inject", "bypass", "aimbot", "wallhack", "esp", "triggerbot", "macro", "exploit")
                    foreach ($keyword in $suspiciousKeywords) {
                        if ($_.Name -match $keyword -or $_.Value -match $keyword) {
                            $suspiciousApps += $entry
                        }
                    }
                }
            }
        }
    }
}

Write-Log "MUICache entries saved to: $muiCacheFile" "Green"

# ============================================================================
# PREFETCH ANALYSIS
# ============================================================================
Write-Log "`n[*] Analyzing Prefetch Data..." "Yellow"

$prefetchPath = "C:\Windows\Prefetch"
$prefetchFile = "$outputDir\prefetch_files.txt"

if (Test-Path $prefetchPath) {
    $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue
    Write-Log "Found $($prefetchFiles.Count) prefetch files"
    
    "Prefetch Files (Most Recent First):" | Out-File $prefetchFile
    $prefetchFiles | Sort-Object LastWriteTime -Descending | ForEach-Object {
        $line = "$($_.LastWriteTime) - $($_.Name)"
        Add-Content -Path $prefetchFile -Value $line
        
        # Check for suspicious keywords in prefetch
        $suspiciousKeywords = @("CHEAT", "HACK", "INJECT", "BYPASS", "AIMBOT", "WALLHACK", "ESP", "TRIGGERBOT")
        foreach ($keyword in $suspiciousKeywords) {
            if ($_.Name -match $keyword) {
                $suspiciousApps += "PREFETCH: $($_.Name) - Modified: $($_.LastWriteTime)"
            }
        }
    }
    Write-Log "Prefetch data saved to: $prefetchFile" "Green"
} else {
    Write-Log "Prefetch directory not accessible or doesn't exist" "Red"
}

# ============================================================================
# TEMP FOLDERS ANALYSIS
# ============================================================================
Write-Log "`n[*] Analyzing Temp Folders..." "Yellow"

$tempPaths = @(
    "$env:TEMP",
    "$env:USERPROFILE\AppData\Local\Temp",
    "C:\Windows\Temp"
)

$tempFile = "$outputDir\temp_analysis.txt"
"Temp Folders Analysis" | Out-File $tempFile

foreach ($tempPath in $tempPaths) {
    if (Test-Path $tempPath) {
        Write-Log "`nAnalyzing: $tempPath"
        Add-Content -Path $tempFile -Value "`n=== $tempPath ==="
        
        $tempFiles = Get-ChildItem -Path $tempPath -Force -ErrorAction SilentlyContinue | 
                     Sort-Object LastWriteTime -Descending | 
                     Select-Object -First 100
        
        foreach ($file in $tempFiles) {
            $line = "$($file.LastWriteTime) - $($file.Name) - $($file.Length) bytes"
            Add-Content -Path $tempFile -Value $line
            
            # Check for suspicious files
            $suspiciousKeywords = @("cheat", "hack", "inject", "bypass", "aimbot", "dll")
            foreach ($keyword in $suspiciousKeywords) {
                if ($file.Name -match $keyword) {
                    $suspiciousApps += "TEMP: $($file.FullName) - Modified: $($file.LastWriteTime)"
                }
            }
        }
    }
}

Write-Log "Temp analysis saved to: $tempFile" "Green"

# ============================================================================
# APPDATA ANALYSIS
# ============================================================================
Write-Log "`n[*] Analyzing AppData Folders..." "Yellow"

$appDataPaths = @(
    "$env:APPDATA",
    "$env:LOCALAPPDATA"
)

$appDataFile = "$outputDir\appdata_analysis.txt"
"AppData Folders Analysis" | Out-File $appDataFile

foreach ($appDataPath in $appDataPaths) {
    if (Test-Path $appDataPath) {
        Write-Log "`nAnalyzing: $appDataPath"
        Add-Content -Path $appDataFile -Value "`n=== $appDataPath ==="
        
        $folders = Get-ChildItem -Path $appDataPath -Directory -Force -ErrorAction SilentlyContinue |
                   Sort-Object LastWriteTime -Descending
        
        foreach ($folder in $folders) {
            $line = "$($folder.LastWriteTime) - $($folder.Name)"
            Add-Content -Path $appDataFile -Value $line
            
            # Check for suspicious folders
            $suspiciousKeywords = @("cheat", "hack", "inject", "bypass", "aimbot", "exploit")
            foreach ($keyword in $suspiciousKeywords) {
                if ($folder.Name -match $keyword) {
                    $suspiciousApps += "APPDATA: $($folder.FullName) - Modified: $($folder.LastWriteTime)"
                }
            }
        }
    }
}

Write-Log "AppData analysis saved to: $appDataFile" "Green"

# ============================================================================
# RUNNING PROCESSES
# ============================================================================
Write-Log "`n[*] Analyzing Running Processes..." "Yellow"

$processFile = "$outputDir\running_processes.txt"
$processes = Get-Process | Sort-Object CPU -Descending

"Running Processes" | Out-File $processFile
$processes | ForEach-Object {
    $line = "$($_.ProcessName) - PID: $($_.Id) - Path: $($_.Path)"
    Add-Content -Path $processFile -Value $line
    
    # Check for suspicious processes
    $suspiciousKeywords = @("cheat", "hack", "inject", "bypass", "aimbot")
    foreach ($keyword in $suspiciousKeywords) {
        if ($_.ProcessName -match $keyword -or $_.Path -match $keyword) {
            $suspiciousApps += "PROCESS: $($_.ProcessName) (PID: $($_.Id)) - Path: $($_.Path)"
        }
    }
}

Write-Log "Process list saved to: $processFile" "Green"

# ============================================================================
# INSTALLED PROGRAMS
# ============================================================================
Write-Log "`n[*] Gathering Installed Programs..." "Yellow"

$programsFile = "$outputDir\installed_programs.txt"

$programs = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                             HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Sort-Object DisplayName

"Installed Programs" | Out-File $programsFile
$programs | ForEach-Object {
    $line = "$($_.DisplayName) - Version: $($_.DisplayVersion) - Publisher: $($_.Publisher) - Installed: $($_.InstallDate)"
    Add-Content -Path $programsFile -Value $line
    
    # Check for suspicious programs
    $suspiciousKeywords = @("cheat", "hack", "inject", "bypass", "aimbot", "trainer")
    foreach ($keyword in $suspiciousKeywords) {
        if ($_.DisplayName -match $keyword) {
            $suspiciousApps += "INSTALLED: $($_.DisplayName) - Publisher: $($_.Publisher)"
        }
    }
}

Write-Log "Installed programs saved to: $programsFile" "Green"

# ============================================================================
# STARTUP PROGRAMS
# ============================================================================
Write-Log "`n[*] Checking Startup Programs..." "Yellow"

$startupFile = "$outputDir\startup_programs.txt"
"Startup Programs" | Out-File $startupFile

$startupLocations = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($location in $startupLocations) {
    if (Test-Path $location) {
        Add-Content -Path $startupFile -Value "`n=== $location ==="
        $items = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
        $items.PSObject.Properties | ForEach-Object {
            if ($_.Name -notlike "PS*") {
                $line = "$($_.Name) = $($_.Value)"
                Add-Content -Path $startupFile -Value $line
            }
        }
    }
}

Write-Log "Startup programs saved to: $startupFile" "Green"

# ============================================================================
# BROWSER HISTORY (Basic Check)
# ============================================================================
Write-Log "`n[*] Checking Browser Data Locations..." "Yellow"

$browserPaths = @{
    "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
    "Edge" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
    "Firefox" = "$env:APPDATA\Mozilla\Firefox\Profiles"
}

$browserFile = "$outputDir\browser_info.txt"
"Browser Data Locations" | Out-File $browserFile

foreach ($browser in $browserPaths.GetEnumerator()) {
    if (Test-Path $browser.Value) {
        $line = "$($browser.Key): $($browser.Value) - EXISTS"
        Write-Log $line
        Add-Content -Path $browserFile -Value $line
    } else {
        Add-Content -Path $browserFile -Value "$($browser.Key): Not Found"
    }
}

# ============================================================================
# SUSPICIOUS FINDINGS SUMMARY
# ============================================================================
Write-Log "`n$(Get-Separator)" "Cyan"
Write-Log "SUSPICIOUS FINDINGS SUMMARY" "Red"
Write-Log "$(Get-Separator)" "Cyan"

if ($suspiciousApps.Count -gt 0) {
    Write-Log "`nFound $($suspiciousApps.Count) potentially suspicious items:" "Red"
    $suspiciousApps | Sort-Object -Unique | ForEach-Object {
        Write-Log "  [!] $_" "Yellow"
    }
    
    $suspiciousFile = "$outputDir\SUSPICIOUS_FINDINGS.txt"
    $suspiciousApps | Sort-Object -Unique | Out-File $suspiciousFile
    Write-Log "`nSuspicious findings saved to: $suspiciousFile" "Red"
} else {
    Write-Log "`nNo obvious suspicious items detected based on keywords." "Green"
    Write-Log "Note: This is a basic keyword scan. Manual review recommended." "Yellow"
}

# ============================================================================
# COMPLETION
# ============================================================================
Write-Log "`n$(Get-Separator)" "Cyan"
Write-Log "SCAN COMPLETE" "Green"
Write-Log "Scan Ended: $(Get-Date)" "Cyan"
Write-Log "All results saved to: $outputDir" "Green"
Write-Log "$(Get-Separator)" "Cyan"

# Open the output directory
Start-Process explorer.exe $outputDir

Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")