#requires -modules tentools

<#PSScriptInfo

.VERSION 1.0

.GUID d6fa5a44-8b2f-4f28-84d6-70344622ecf8

.AUTHOR James Smart

.COMPANYNAME Brookhaven National Laboratory

.COPYRIGHT Copyright (c) 2022, Brookhaven National Laboratory

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES

.PRIVATEDATA

.DESCRIPTION 
Gets information from a tennable.sc or nessus instance regarding the vulnerabilities specified in Binding Operational Directive 22-01.

#> 
[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $AssetName
)

function New-BOD2201Filter {
    [CmdletBinding()]
    param (
        #CVEs to search for.
        [Parameter()]
        [String[]]
        $CVEs,    
        #Asset ID to filter to.
        [Parameter()]
        [String]
        $AssetID
    ) 

    $filters = @()

    $filters += @{
        id = 'cveID'
        filterName  = 'cveID'
        operator = '='
        type = 'vuln'
        isPredefined = 'True'
        value = $cves -join ','
    }

    if ($AssetID) {
        $filters += @{
            filterName  = 'asset'
            operator = '='
            value = @{id=$AssetID}
        }
    }

    $filters
}

if (-not (Get-TNSession)) {
    Write-Error "Connect to server with Connect-TNServer first." -ErrorAction Stop
}

Write-Progress -Activity "Getting CISA Known Exploited Vulnerabilities."
$DataURL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
$VulnerabilityData = Invoke-WebRequest -Uri $DataURL
$Vulnerabilities = $VulnerabilityData | ConvertFrom-Json | Select-Object -expandproperty Vulnerabilities

Write-Verbose "Got $($Vulnerabilities.count) vulnerabilities with due dates."

if ($AssetName) {
    $Asset = Get-TNAsset -Name $AssetName
    if (-not $Asset) {
        Write-Warning "Asset '$AssetName' not found.  Returning data for all assets."
        $AssetName = '' # Make sure it's not in the output
    }
    else {
        Write-Verbose "Filtering to Asset '$AssetName' with ID '$($Asset.ID)'"
    }
    
}

$filters = New-BOD2201Filter -CVEs $Vulnerabilities.cveid -AssetID $Asset.ID
Write-Progress -Activity "Getting CISA Known Exploited Vulnerabilities found by the scanner."
$analysis = Get-TNAnalysis -Filter $filters -SourceType cumulative -SortBy  score -Tool sumcve

$BOD2201_ByCVE = @()
$BOD2201_ByHost = @{}

foreach ($foundCVE in ($analysis)) {
    $duedate = $Vulnerabilities | Where-Object {$_.cveid -eq $foundCVE.cveID} | Select-Object -ExpandProperty DueDate 
    if ($duedate) {

        $filters = @{
            id = 'cveID'
            filterName  = 'cveID'
            operator = '='
            type = 'vuln'
            isPredefined = 'True'
            value = $foundCVE.cveid
        }
        $filters = New-BOD2201Filter -CVEs $foundCVE.cveid -AssetID $Asset.ID
        
        $ipdata = Get-TNAnalysis -Filter $filters -SourceType cumulative -SortBy score -Tool sumip 

        $cvedetail = [PSCustomObject]@{
            cveID = $foundCVE.cveID
            duedate = $duedate
            total = $foundCVE.total
            hostTotal = $foundCVE.hostTotal
            overdue = ((get-date) -gt (get-date $duedate))
            ipdata = $ipdata | select-object DnsName, NetBiosName, IP, MacAddress
        }

        $BOD2201_ByCVE += $cvedetail

        foreach ($ip in $ipdata) {
            if (-not $BOD2201_ByHost[$ip.dnsname]) {
                $BOD2201_ByHost[$ip.dnsname] = @()
            }
            $BOD2201_ByHost[$ip.dnsname] += [PSCustomObject]@{
                cveID = $foundCVE.cveID
                duedate = $duedate
                overdue = ((get-date) -gt (get-date $duedate))
            }
        }
    }
}

$CVECount =  $BOD2201_ByCVE.Count
$OverDueCVEs = $BOD2201_ByCVE | where-object {$_.overdue} | Measure-Object | Select-Object -ExpandProperty Count 
$IPCount = $BOD2201_ByHost.Keys.Count

Write-Verbose "CVEs found that are on the CISA Known Exploited Vulnerabilities list: $CVECount"
Write-Verbose "CVEs found that are on the CISA Known Exploited Vulnerabilities list, and are overdue: $OverDueCVEs"
Write-Verbose "IPs with CVEs from the CISA Known Exploited Vulnerabilities list: $IPCount"


[PSCustomObject]@{
    AssetName = $AssetName
    CVECount = $CVECount
    OverDueCVEs = $OverDueCVEs
    IPCount = $IPCount
    CVEs = $BOD2201_ByCVE | Sort-Object duedate 
    Hosts = $BOD2201_ByHost
}
