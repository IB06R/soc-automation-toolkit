<#
.SYNOPSIS
    Parses Windows Security logs for Event ID 4625 (Failed Logon) and flags brute-force thresholds.
.EXAMPLE
    .\Get-FailedLogons.ps1 -HoursBack 24 -Threshold 5
#>

param (
    [int]$HoursBack = 24,
    [int]$Threshold = 5,
    [string]$OutputCsv = ".\failed_logon_triage.csv"
)

# Verify Administrator privileges (required to read the Security log)
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Access Denied: Run PowerShell as Administrator to read Windows Security logs."
    exit 1
}

$StartTime = (Get-Date).AddHours(-$HoursBack)
Write-Host "[*] Querying Event ID 4625 since $StartTime..." -ForegroundColor Cyan

try {
    $Events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        ID        = 4625
        StartTime = $StartTime
    } -ErrorAction Stop
} catch {
    Write-Host "[+] No failed logon events (ID 4625) found in the last $HoursBack hours." -ForegroundColor Green
    exit 0
}

$ParsedEvents = foreach ($Event in $Events) {
    [xml]$XmlData = $Event.ToXml()
    $EventData = @{}
    foreach ($Node in $XmlData.Event.EventData.Data) {
        $EventData[$Node.Name] = $Node.'#text'
    }

    [PSCustomObject]@{
        TimeCreated   = $Event.TimeCreated
        TargetUser    = $EventData['TargetUserName']
        TargetDomain  = $EventData['TargetDomainName']
        LogonType     = $EventData['LogonType']
        SourceIP      = if ($EventData['IpAddress'] -and $EventData['IpAddress'] -ne '-') { $EventData['IpAddress'] } else { 'Local/N/A' }
        FailureReason = $EventData['SubStatus']
    }
}

# Group by SourceIP and TargetUser to spot brute-force patterns
Write-Host "`n--- Summary by Source IP & Target User ---" -ForegroundColor Yellow
$Grouped = $ParsedEvents | Group-Object SourceIP, TargetUser | Sort-Object Count -Descending

foreach ($Group in $Grouped) {
    $Severity = if ($Group.Count -ge $Threshold) { "[HIGH - THRESHOLD EXCEEDED]" } else { "[INFO]" }
    $Color = if ($Group.Count -ge $Threshold) { "Red" } else { "Gray" }
    Write-Host "$Severity Count: $($Group.Count) | $($Group.Name)" -ForegroundColor $Color
}

$ParsedEvents | Export-Csv -Path $OutputCsv -NoTypeInformation
Write-Host "`n[+] Exported $($ParsedEvents.Count) total events to $OutputCsv" -ForegroundColor Green
