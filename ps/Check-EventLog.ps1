# Created by github.com/jcoester
# Repository: https://github.com/cjee21/Check-UEFISecureBootVariables

# DB and DBX update events
# See https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69
$provider = "Microsoft-Windows-TPM-WMI"
$eventIds = 1032,1033,1034,1035,1036,1037,1042,1043,1044,1045,
            1795,1796,1797,1798,1799,1800,1801,1802,1803,1808

# SkuSiPolicy.p7b policy events
# https://support.microsoft.com/en-us/topic/guidance-for-blocking-rollback-of-virtualization-based-security-vbs-related-security-updates-b2e7ebf4-f64d-4884-a390-38d63171b8d3
$logName = 'Microsoft-Windows-CodeIntegrity/Operational'
$policyGuid = '{976d12c8-cb9f-4730-be52-54600843238e}'

# BucketConfidenceLevel
# https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69#bkmk_specific_events
$buckets = @{
    "High Confidence"    = "Green"
    "Under Observation"  = "DarkCyan"
    "Temporarily Paused" = "DarkYellow"
    "No Data Observed"   = "DarkYellow"
    "Not Supported"      = "DarkRed"
}

# Spacer
Import-Module $PSScriptRoot\Get-SystemOverview.psm1 -Force

# Color rules
function Get-BucketColor($value) {
    foreach ($k in $buckets.Keys) {
        if ($value -like "*$k*") { return $buckets[$k] }
    }
    "White"
}

function Get-UpdateColor($value) {
    if ($value -match 'Boot Manager \(2023\)') { return "Green" }
    if ($value -eq "0") { return "Yellow" }
    "White"
}

function Get-CertificateColor($issuer) {
    $year = if ($issuer -match '(\d{4})') { [int]$Matches[1] } else { 0 }
    if ($year -ge 2023) { return "Green" } else { return "Yellow" }
    "White"
}

function Get-LevelColor($level) {
    switch ($level) {
        2 { "Red" }    # Error
        3 { "Yellow" } # Warning
        4 { "Cyan" }   # Information
        default { "White" }
    }
}

# Formatters
function Format-LogMessage($msg) {
    $msg -split "`r?`n" | ForEach-Object {
        Format-Line $_
    }
}

function Format-Line($line) {

    # URL
    if ($line -match 'https://') {
        Write-Host $line -ForegroundColor DarkGray
        return
    }

    # Key: Value structure
    if ($line -match '^[^:]+:\s*.+') {

        $parts = $line -split ':', 2
        $key   = $parts[0].Trim()
        $value = $parts[1].Trim()

        switch ($key) {
            "DeviceAttributes" { 
                Format-DeviceAttributes $value 
            }
            "BucketConfidenceLevel" { 
                Write-Line $key $value (Get-BucketColor $value) 
            }
            "UpdateType" { 
                Write-Line $key $value (Get-UpdateColor $value) 
            }
            default { 
                Write-Line $key $value 
            }
        }

        return
    }

    # Sentence splitter
    if ($line -match '\. ') {
        foreach ($part in ($line -split '(?<=[.])\s+')) {
            if ($part) {
                Write-Host $part -ForegroundColor DarkGray
            }
        }
        return
    }

    # Default
    Write-Host $line -ForegroundColor DarkGray
}

function Format-DeviceAttributes($value) {
    Write-Host "DeviceAttributes: " -ForegroundColor DarkGray -NoNewline

    $items = $value -split ';'

    foreach ($item in $items) {

        $item = $item.Trim()

        if ($item -match '^([^:]+):(.*)$') {
            Write-Host "$($matches[1]):" -ForegroundColor DarkGray -NoNewline
            Write-Host $matches[2] -NoNewline
            Write-Host "; " -ForegroundColor DarkGray -NoNewline
        }
    }
    Write-Host
}

function Write-Line($label, $value, $color) {
    Write-Host "$label`: " -ForegroundColor DarkGray -NoNewline

    if ($PSBoundParameters.ContainsKey('Color')) {
        Write-Host $value -ForegroundColor $color
    }
    else {
        Write-Host $value # Default color
    }
}

function Show-SkuSi-Signature($LogEntry) {

    $xml = [xml]$LogEntry.ToXml()
    if ($xml.Event.System.Provider.Name -ne "Microsoft-Windows-CodeIntegrity") { return }

    $issuer = ($xml.Event.EventData.Data | Where-Object Name -eq 'IssuerName').'#text'
    if (-not $issuer) { return }

    Write-Host $issuer -ForegroundColor (Get-CertificateColor $issuer)
}

# ---------------------------------------------------------------------
# MAIN
do {
    Write-Host
    $choice = Read-Host "[Enter] Show Secure Boot Events, [F] with Full Details, [S] SkuSi Policy events"
    switch ($choice.ToUpper()) {
        'F' {
            $events = Get-WinEvent -FilterHashtable @{
                ProviderName = $provider
                Id           = $eventIds
            } | Sort-Object TimeCreated
            $showDetails = $true
        }
        'S' {
            $events = Get-WinEvent -LogName $logName | Where-Object {
                $xml = [xml]$_.ToXml()
                $guid = $xml.Event.EventData.Data |
                    Where-Object { $_.Name -eq 'PolicyGUID' } |
                    Select-Object -ExpandProperty '#text'
                $guid -eq $policyGuid
            } | Sort-Object TimeCreated
            $showDetails = $true
        }
        default {
            $events = Get-WinEvent -FilterHashtable @{
                ProviderName = $provider
                Id           = $eventIds
            } | Sort-Object TimeCreated
            $showDetails = $false
        }
    }

    if (-not $events) {
        Write-Host "No Secure Boot / policy events found." -ForegroundColor Yellow
        return
    }

    Write-Host
    foreach ($logEntry in $events) {

        Write-Host ("{0} [{1}] " -f $logEntry.TimeCreated, $logEntry.Id) -NoNewline

        # Split into: Summary & Details
        $parts = $logEntry.Message -split '(?<=[.])\s+', 2

        # Summary
        Write-Host $parts[0] -ForegroundColor (Get-LevelColor $logEntry.Level)

        # Details
        if ($showDetails) {
            if ($parts.Count -gt 1) {
                Format-LogMessage $parts[1]
            }

            # Add Signature information for SkuSi policy 
            Show-SkuSi-Signature($logEntry)

            Spacer
        }
    }
} while ($true)