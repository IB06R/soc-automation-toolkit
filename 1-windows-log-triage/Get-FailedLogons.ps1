<#
.SYNOPSIS
    Parses Windows Security logs for Event ID 4625 (Failed Logon), translates failure/logon codes,
    and flags both Brute-Force and Password-Spraying patterns.
.EXAMPLE
    .\Get-FailedLogons.ps1 -HoursBack 12 -Threshold 5 -Gui
#>

param (
    [int]$HoursBack = 24,
    [int]$Threshold = 5,
    [string]$ComputerName = $env:COMPUTERNAME,
    [string]$OutputCsv = ".\failed_logon_triage.csv",
    [switch]$Gui
)

# Verify Administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Access Denied: Run PowerShell as Administrator to read Windows Security logs."
    exit 1
}

# Lookup tables to translate raw Windows telemetry into human-readable context
$LogonTypeMap = @{
    '2'  = 'Interactive (Local Keyboard)'
    '3'  = 'Network (SMB / Share / NLA)'
    '4'  = 'Batch (Scheduled Task)'
    '5'  = 'Service'
    '7'  = 'Unlock Workstation'
    '8'  = 'NetworkCleartext (IIS/Basic Auth)'
    '10' = 'RemoteInteractive (RDP)'
    '11' = 'CachedInteractive (Offline Domain)'
}

$SubStatusMap = @{
    '0xc0000064' = 'Username does not exist'
    '0xc000006a' = 'Incorrect password'
    '0xc0000234' = 'Account currently locked out'
    '0xc0000072' = 'Account disabled'
    '0xc000006f' = 'Logon outside authorized hours'
    '0xc0000070' = 'Unauthorized workstation'
    '0xc0000193' = 'Account expired'
    '0xc0000071' = 'Password expired'
}

$StartTime = (Get-Date).AddHours(-$HoursBack)
Write-Host "[*] Querying Event ID 4625 on [$ComputerName] since $StartTime..." -ForegroundColor Cyan

try {
    $Events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
        LogName   = 'Security'
        ID        = 4625
        StartTime = $StartTime
    } -ErrorAction Stop
} catch {
    Write-Host "[+] No failed logon events (ID 4625) found on [$ComputerName] in the last $HoursBack hours." -ForegroundColor Green
    exit 0
}

$ParsedEvents = foreach ($Event in $Events) {
    [xml]$XmlData = $Event.ToXml()
    $EventData = @{}
    foreach ($Node in $XmlData.Event.EventData.Data) {
        $EventData[$Node.Name] = $Node.'#text'
    }

    $RawType = $EventData['LogonType']
    $RawSub  = if ($EventData['SubStatus']) { $EventData['SubStatus'].ToLower() } else { '' }

    [PSCustomObject]@{
        TimeCreated   = $Event.TimeCreated
        TargetUser    = $EventData['TargetUserName']
        TargetDomain  = $EventData['TargetDomainName']
        LogonType     = if ($LogonTypeMap.ContainsKey($RawType)) { "$RawType - $($LogonTypeMap[$RawType])" } else { $RawType }
        SourceIP      = if ($EventData['IpAddress'] -and $EventData['IpAddress'] -ne '-') { $EventData['IpAddress'] } else { 'Local/N/A' }
        FailureReason = if ($SubStatusMap.ContainsKey($RawSub)) { "$($SubStatusMap[$RawSub]) ($RawSub)" } else { $RawSub }
    }
}

# 1. Brute-Force Detection (Same IP + Same Target User)
Write-Host "`n--- Brute-Force Check (Grouped by Source IP & Target User) ---" -ForegroundColor Yellow
$BruteForceGroups = $ParsedEvents | Group-Object SourceIP, TargetUser | Sort-Object Count -Descending
foreach ($Group in $BruteForceGroups) {
    $Severity = if ($Group.Count -ge $Threshold) { "[HIGH - BRUTE FORCE]" } else { "[INFO]" }
    $Color    = if ($Group.Count -ge $Threshold) { "Red" } else { "Gray" }
    Write-Host "$Severity Attempts: $($Group.Count) | $($Group.Name)" -ForegroundColor $Color
}

# 2. Password Spraying Detection (Same IP targeting multiple distinct usernames)
Write-Host "`n--- Password-Spray Check (Unique Users Targeted per Source IP) ---" -ForegroundColor Yellow
$IpGroups = $ParsedEvents | Group-Object SourceIP
foreach ($IpGroup in $IpGroups) {
    $UniqueUsers = ($IpGroup.Group.TargetUser | Select-Object -Unique).Count
    if ($UniqueUsers -ge $Threshold) {
        Write-Host "[HIGH - PASSWORD SPRAY] Source IP: $($IpGroup.Name) targeted $UniqueUsers distinct accounts!" -ForegroundColor Red
    } else {
        Write-Host "[INFO] Source IP: $($IpGroup.Name) targeted $UniqueUsers unique account(s)" -ForegroundColor Gray
    }
}

# Export CSV with graceful fallback if target file is locked by Excel/another process
try {
    $ParsedEvents | Export-Csv -Path $OutputCsv -NoTypeInformation -ErrorAction Stop
    Write-Host "`n[+] Exported $($ParsedEvents.Count) total events to $OutputCsv" -ForegroundColor Green
} catch {
    $FallbackCsv = ".\failed_logon_triage_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    Write-Warning "Target file '$OutputCsv' is locked by another process. Falling back to '$FallbackCsv'."
    $ParsedEvents | Export-Csv -Path $FallbackCsv -NoTypeInformation
    Write-Host "[+] Exported $($ParsedEvents.Count) total events to $FallbackCsv" -ForegroundColor Green
}

# Optional Interactive Windows GUI Grid
if ($Gui) {
    Write-Host "[*] Launching interactive Out-GridView window..." -ForegroundColor Cyan
    $ParsedEvents | Out-GridView -Title "Event ID 4625 Triage - $ComputerName (Last $HoursBack hrs)"
}
