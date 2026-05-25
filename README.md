```
     _____         __________                                                  _____                .__                              
    /  _  \ _______\______   \ ____   __________  __ _________   ____  ____   /  _  \   ____ _____  |  | ___.__.________ ___________ 
   /  /_\  \\___   /|       _// __ \ /  ___/  _ \|  |  \_  __ \_/ ___\/ __ \ /  /_\  \ /    \\__  \ |  |<   |  |\___   // __ \_  __ \
  /    |    \/    / |    |   \  ___/ \___ (  <_> )  |  /|  | \/\  \__\  ___//    |    \   |  \/ __ \|  |_\___  | /    /\  ___/|  | \/
  \____|__  /_____ \|____|_  /\___  >____  >____/|____/ |__|    \___  >___  >____|__  /___|  (____  /____/ ____|/_____ \\___  >__|   
          \/      \/       \/     \/     \/                         \/    \/        \/     \/     \/     \/           \/    \/
```    

Copyright (c) NCS Dojo. All Rights Reserved.

PowerShell 7 module for Azure resource collection and CIS benchmark posture assessment.

## Requirements

- PowerShell 7.0 or later
- Code-signing certificate (all `.ps1` files must be signed for environments enforcing Constrained Language Mode)

## Install

```powershell
Install-Module AzResourceAnalyzer -Scope CurrentUser
```

Or import directly from a local folder:

```powershell
Import-Module ./AzResourceAnalyzer
```

## Usage

```powershell
Import-Module AzResourceAnalyzer

Connect-ArSession -TenantId 'contoso.onmicrosoft.com'
Invoke-ArExport
Invoke-ArAudit

Disconnect-ArSession
```

All output goes to `%TEMP%/NCS/AzResourceAnalyzer`. The HTML report opens
in the browser automatically when `Invoke-ArAudit` finishes.

Without a session, every command returns a friendly prompt:

```
  Not connected. Run Connect-ArSession first.

  Example:
    Connect-ArSession -TenantId 'contoso.onmicrosoft.com'
    Invoke-ArExport
```

## Commands

| Command | Description |
|---|---|
| `Connect-ArSession` | Authenticate via browser sign-in (PKCE), store session |
| `Disconnect-ArSession` | Clear tokens from memory |
| `Invoke-ArExport` | Run resource collectors, write JSON exports |
| `Invoke-ArAudit` | Run CIS checks against exports, produce HTML report |

## Connect-ArSession

```powershell
Connect-ArSession -TenantId 'contoso.onmicrosoft.com'
Connect-ArSession -TenantId '...' -AuthTimeout 120
```

Opens a browser window for each token scope (ARM, Graph, Vault).
On connection, the module checks permissions, roles, subscription access,
and Entra ID license tier. Tokens stored as `SecureString` and scrubbed
on disconnect.

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

Resource Graph collectors run in parallel via runspace pools.

## Invoke-ArAudit

```powershell
Invoke-ArAudit                                     # default path
Invoke-ArAudit -ExportPath C:\other\exports         # custom path
Invoke-ArAudit -ListChecks                          # print available
Invoke-ArAudit -MinSeverity High                    # filter by severity
```

Reads exports from `%TEMP%/NCS/AzResourceAnalyzer` by default (same
location `Invoke-ArExport` writes to). Produces an interactive HTML
report with donut chart, section cards, severity filters, and per-finding
detail including affected resources and remediation guidance. Also outputs
JSON findings and CSV.

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
  LICENSE
  CHANGELOG.md

  Classes/
    ArTokenStore.ps1               PKCE browser auth and token storage

  Private/
    Assert-ArSession.ps1           session guard, token accessors
    Test-ArEnvironment.ps1         PS7, permission, and license checks
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
