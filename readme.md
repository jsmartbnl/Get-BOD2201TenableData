# BOD 22-01 Tenable Data

Gets information from a tenable.sc or nessus instance regarding the vulnerabilities specified in [Binding Operational Directive 22-01](https://cyber.dhs.gov/bod/22-01/).

It relies on the [tentools](https://www.powershellgallery.com/packages/tentools/0.0.14) module from the powershell gallery.

Vulnerability data including the due date is sourced from the [JSON version](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) of the [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

## Examples

### Connect to tenable and get a list of all unmitigated vulnerabilities specified in BOD 22-01

``` powershell
Connect-TNServer #remember to add your connection information
.\Get-BOD2201TenableData.ps1
```

### Connect to tenable and get a list of all unmitigated vulnerabilities specified in BOD 22-01 that appear in a given asset

``` powershell
Connect-TNServer #remember to add your connection information
.\Get-BOD2201TenableData.ps1 -AssetName "your asset name here"
```
