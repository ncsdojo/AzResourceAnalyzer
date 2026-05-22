# AzResourceAnalyzer

PowerShell 7 module for Azure resource collection and posture assessment.

## Install

```powershell
Import-Module ./AzResourceAnalyzer
```

## Usage

```powershell
Import-Module ./AzResourceAnalyzer

Connect-ArSession -TenantId 'contoso.onmicrosoft.com'
Invoke-ArExport
Invoke-ArAudit

Disconnect-ArSession
```

All output goes to `%TEMP%/NCS/AzResourceAnalyzer`. The HTML report opens
in the browser automatically when `Invoke-ArAudit` finishes.

Without a session, every command returns:

```
WARNING: No active session. Run Connect-ArSession first to authenticate.

  Example:
    Connect-ArSession -TenantId 'contoso.onmicrosoft.com'
    Invoke-ArAudit
```

## Commands

| Command | Description |
|---|---|
| `Connect-ArSession` | Authenticate via device code, store session |
| `Disconnect-ArSession` | Clear tokens from memory |
| `Invoke-ArExport` | Run resource collectors, write JSON exports |
| `Invoke-ArAudit` | Run CIS checks against exports, produce report |

## Connect-ArSession

```powershell
Connect-ArSession -TenantId 'contoso.onmicrosoft.com'
Connect-ArSession -TenantId '...' -AuthTimeout 60
```

Uses `Write-Progress` for the device code polling. Tokens stored as
`SecureString` and scrubbed on disconnect. On failure:

```
WARNING: <reason>. Run Connect-ArSession to try again.
```

## Invoke-ArExport

```powershell
Invoke-ArExport                                    # all collectors
Invoke-ArExport -Collector VirtualMachine           # one collector
Invoke-ArExport -Collector VirtualMachine, NSG      # several
Invoke-ArExport -ListCollectors                     # print available
Invoke-ArExport -SkipGraph -SkipKeyVault            # Resource Graph only
```

The `-Collector` parameter supports tab completion after importing the module.

Discovers collector definitions from `Collectors/` at runtime and writes
JSON exports to `%TEMP%/NCS/AzResourceAnalyzer`. Purges previous exports
on each run to avoid stale data. Pass `-OutputPath` to write elsewhere
without purging.

## Invoke-ArAudit

```powershell
Invoke-ArAudit                                     # default path
Invoke-ArAudit -ExportPath C:\other\exports         # custom path
Invoke-ArAudit -ListChecks                          # print available
Invoke-ArAudit -MinSeverity High                    # filter by severity
```

Reads exports from `%TEMP%/NCS/AzResourceAnalyzer` by default (same
location `Invoke-ArExport` writes to). Produces an HTML report, JSON
findings, and CSV, then opens the report in the browser.

## Adding collectors

Drop a `.ps1` in `Collectors/<ApiType>/` that returns a hashtable:

```powershell
# Collectors/ResourceGraph/MyResource.ps1
@{
    Name        = "MyResource"
    ApiType     = "ResourceGraph"
    Table       = "resources"
    FileName    = "MyResources"
    Label       = "my resource(s)"
    UniqueField = "resourceName"
    Query       = @"
resources
| where type =~ 'microsoft.example/things'
| project subscriptionId, resourceName = name, tags
"@
}
```

## Adding checks

Drop a `.ps1` in `Checks/<Section>/` that returns a hashtable:

```powershell
# Checks/CIS-9-Storage/CIS-9-99-1.ps1
@{
    CIS       = "9.99.1"
    Title     = "Something must be enabled"
    Severity  = "High"
    Automated = $true
    Check     = {
        param($D)
        $bad = @($D.StorageAccounts | Where-Object { -not $_.someProp })
        if ($bad.Count -gt 0) {
            return @(@{ AffectedResources = @($bad.storageAccountName)
                        Description = "$($bad.Count) missing someProp" })
        }
        return @()
    }
}
```

New files are picked up on next run with no code changes.

## Module layout

```
AzResourceAnalyzer/
  AzResourceAnalyzer.psd1          manifest
  AzResourceAnalyzer.psm1          loader
  LICENSE                          MIT
  CHANGELOG.md

  Classes/
    ArTokenStore.ps1               token storage and device code auth

  Private/
    Assert-ArSession.ps1           session guard, token accessors
    ResourceGraphWorker.ps1        parallel Resource Graph execution
    GraphCollector.ps1             Microsoft Graph with pagination
    KeyVaultCollector.ps1          Key Vault data plane
    NSGHelpers.ps1                 NSG rule analysis
    Write-Log.ps1                  logging

  Public/
    Connect-ArSession.ps1          authenticate and store session
    Disconnect-ArSession.ps1       dispose session
    Invoke-ArExport.ps1            run collectors
    Invoke-ArAudit.ps1             run checks, produce report

  Collectors/                      70 collectors
    ResourceGraph/                 62
    MicrosoftGraph/                5
    KeyVault/                      3

  Checks/                          269 checks
    CIS-2-Analytics/               12
    CIS-3-Compute/                 56
    CIS-5-Identity/                17
    CIS-6-Management/              26
    CIS-7-Networking/              35
    CIS-8-Security/                93
    CIS-9-Storage/                 30
```

---
Copyright (c) NCS Dojo. All Rights Reserved.
