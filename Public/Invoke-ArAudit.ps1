function Invoke-ArAudit {
    <#
.SYNOPSIS
    Azure resource posture assessment.
.DESCRIPTION
    Requires an active session from Connect-ArSession.
    Discovers checks from Checks/ and runs them against JSON exports
    produced by Invoke-ArExport. Generates HTML report, JSON, and CSV.

    Copyright (c) NCS Dojo. All Rights Reserved.
.PARAMETER ExportPath
    Directory containing JSON exports. Defaults to temp NCS/AzResourceAnalyzer.
.PARAMETER MinSeverity
    Minimum severity to include. Default: Info.
.PARAMETER ListChecks
    Print available checks and exit.
#>
    [CmdletBinding()]
    param(
        [Alias('ExportDir','InputPath')][string]$ExportPath,
        [Alias('OutputDir')][string]$OutputPath,
        [ValidateSet('Critical','High','Medium','Low','Info')][string]$MinSeverity = 'Info',
        [switch]$ListChecks,
        [string]$CheckPath
    )

if (-not $ExportPath) { $ExportPath = Join-Path ([System.IO.Path]::GetTempPath()) 'NCS/AzResourceAnalyzer' }
if (-not $OutputPath) { $OutputPath = $ExportPath }

if (-not (Test-Path $ExportPath -PathType Container)) {
    Write-Host "  ERROR: Export directory not found: $ExportPath" -ForegroundColor Red
    Write-Host "  Run Invoke-ArExport first to generate exports." -ForegroundColor Yellow
    return
}
if (-not (Test-Path $OutputPath -PathType Container)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}




if (-not $script:_ArSession -or -not $script:_ArTenantId) {
    Write-Warning "No active session. Run Connect-ArSession first to authenticate.`n`n  Example:`n    Connect-ArSession -TenantId 'contoso.onmicrosoft.com'`n    Invoke-ArAudit`n"
    return
}
$TenantId = $script:_ArTenantId


$CISSections = @{
    "2" = @{ Name="Analytics Services";          Total=12 }
    "3" = @{ Name="Compute Services";            Total=24 }
    "5" = @{ Name="Identity Services";           Total=17 }
    "6" = @{ Name="Management and Governance";   Total=26 }
    "7" = @{ Name="Networking Services";         Total=21 }
    "8" = @{ Name="Security Services";           Total=50 }
    "9" = @{ Name="Storage Services";            Total=23 }
}

$SeverityOrder = @{ "Critical"=5; "High"=4; "Medium"=3; "Low"=2; "Info"=1 }
$SeverityColors = @{ "Critical"="#B91C3A"; "High"="#C4650A"; "Medium"="#8B7231"; "Low"="#2B6CB0"; "Info"="#6B7280" }




if (-not $CheckPath) { $CheckPath = Join-Path $script:_ArModuleRoot "Checks" }

Write-Host ""
Write-Information "`n  NCS Dojo — AzResourceAnalyzer" -InformationAction Continue
Write-Information "  Tenant: $TenantId" -InformationAction Continue
Write-Host ""

$checkFiles = Get-ChildItem -Path $CheckPath -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue |
    Sort-Object DirectoryName, Name

if ($checkFiles.Count -eq 0) {
    Write-Host "  ERROR: No check files found in $CheckPath" -ForegroundColor Red
    return
}

$Checks = [System.Collections.Generic.List[hashtable]]::new()
$loadErrors = 0

foreach ($file in $checkFiles) {
    try {
        $definition = . $file.FullName
        if ($null -ne $definition -and $definition -is [hashtable]) {
            $requiredFields = @('CIS', 'Title', 'Severity', 'Automated', 'Check')
            $missing = @($requiredFields | Where-Object { -not $definition.ContainsKey($_) })
            if ($missing.Count -gt 0) {
                Write-Host "    WARN: $($file.Name) missing fields: $($missing -join ', ')" -ForegroundColor Yellow
                continue
            }
            $definition['_sourceFile'] = $file.FullName
            $Checks.Add($definition)
        }
    }
    catch {
        $loadErrors++
        Write-Host "    ERROR: $($file.Name): $_" -ForegroundColor Red
    }
}

# Sort by CIS number
$Checks = [System.Collections.Generic.List[hashtable]]@(
    $Checks | Sort-Object {
        $parts = $_.CIS -split '\.'
        ($parts | ForEach-Object { [int]$_ }) -join '.'
        # Numeric sort: pad each segment
        ($parts | ForEach-Object { '{0:D4}' -f [int]$_ }) -join '.'
    }
)

Write-Host "  Discovered $($Checks.Count) checks ($loadErrors errors)" -ForegroundColor $(if ($loadErrors -eq 0) { 'Green' } else { 'Yellow' })

# Group by section
foreach ($sec in ($CISSections.Keys | Sort-Object { [int]$_ })) {
    $count = @($Checks | Where-Object { $_.CIS.Split('.')[0] -eq $sec }).Count
    if ($count -gt 0) {
        Write-Host "    Section $sec ($($CISSections[$sec].Name)): $count checks" -ForegroundColor Gray
    }
}


if ($ListChecks) {
    Write-Host ""
    Write-Host "  Available Checks:" -ForegroundColor Cyan
    Write-Host "  $('-' * 80)" -ForegroundColor Gray
    $lastSection = ""
    foreach ($chk in $Checks) {
        $sec = $chk.CIS.Split('.')[0]
        if ($sec -ne $lastSection) {
            $secName = if ($CISSections.ContainsKey($sec)) { $CISSections[$sec].Name } else { "Unknown" }
            Write-Host ""
            Write-Host "  [Section $sec — $secName]" -ForegroundColor Yellow
            $lastSection = $sec
        }
        $autoFlag = if ($chk.Automated) { "AUTO" } else { "MANUAL" }
        Write-Host "    CIS $($chk.CIS.PadRight(10)) $($chk.Severity.PadRight(10)) $autoFlag  $($chk.Title)" -ForegroundColor Gray
    }
    Write-Host ""
    return
}


Write-Host ""
Write-Host "  Loading from $ExportPath" -ForegroundColor Gray

$D = @{}
$jsonFiles = Get-ChildItem $ExportPath -Filter "*.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch 'Manifest|ExportLog|CIS_' } |
    Sort-Object LastWriteTime -Descending

$loaded = @{}
foreach ($file in $jsonFiles) {
    $prefix = $file.BaseName -replace '_\d{8}_\d{6}$', ''
    if ($loaded.ContainsKey($prefix)) { continue }
    $loaded[$prefix] = $true

    try {
        $json = Get-Content $file.FullName -Raw | ConvertFrom-Json
        $data = @()
        if ($null -ne $json -and $json.PSObject.Properties['data']) {
            $raw = $json.data
            if ($null -ne $raw) {
                $data = if ($raw -is [array]) { $raw } else { @(,$raw) }
            }
        }
        $D[$prefix] = $data
        Write-Host "    $($prefix.PadRight(28)) $($data.Count)" -ForegroundColor Gray
    }
    catch {
        Write-Host "    $($prefix.PadRight(28)) LOAD ERROR" -ForegroundColor Red
    }
}

Write-Host "  $($D.Count) sources loaded" -ForegroundColor $(if ($D.Count -gt 0) { 'Green' } else { 'Yellow' })

# Schema validation
$schemaExpected = @{
    VirtualMachines         = @('vmName','securityType','secureBootEnabled','vtpmEnabled','encryptionAtHost','managedIdentityType')
    StorageAccounts         = @('storageAccountName','httpsOnly','minimumTlsVersion','networkDefaultAction','allowBlobPublicAccess')
    NSGs                    = @('nsgName','ruleName','ruleDirection','ruleAccess','destPortRange','ruleKind')
    VNets                   = @('vnetName','subnetName','encryptionEnabled')
    KeyVaults               = @('vaultName','enableRbacAuthorization','enableSoftDelete','enablePurgeProtection')
    AppServices             = @('appName','httpsOnly','minTlsVersion','ftpsState','remoteDebugging','publicNetworkAccess')
    SQLServers              = @('serverName','minTlsVersion','publicNetworkAccess','azureAdOnlyAuth')
    CosmosDBAccounts        = @('accountName','publicNetworkAccess','disableLocalAuth')
    PostgreSQLServers       = @('serverName','publicNetworkAccess','geoRedundantBackup')
    MySQLServers            = @('serverName','publicNetworkAccess','geoRedundantBackup')
    RedisCaches             = @('cacheName','enableNonSslPort','minimumTlsVersion','publicNetworkAccess')
    DataFactories           = @('factoryName','publicNetworkAccess','managedIdentityType')
    ContainerRegistries     = @('registryName','adminUserEnabled','publicNetworkAccess')
    Disks                   = @('diskName','encryptionType','publicNetworkAccess')
    DefenderPricing         = @('planName','pricingTier')
    RBACAssignments         = @('principalId','principalType','roleDefinitionId','roleScope')
    MFARegistration         = @('userPrincipalName','isMfaRegistered')
    BlobContainers          = @('containerName','storageAccount','publicAccess')
    FileShares              = @('shareName','storageAccount')
    SQLAuditSettings        = @('serverName','state')
    SQLThreatDetection      = @('serverName','state')
    BackupPolicies          = @('policyName','vaultName','retentionDailyCount')
    PostgreSQLConfigs       = @('serverName','configName','configValue')
    MySQLConfigs            = @('serverName','configName','configValue')
}

$schemaWarnings = @()
foreach ($source in $schemaExpected.Keys) {
    if (-not $D.ContainsKey($source)) { continue }
    $items = @($D[$source])
    if ($items.Count -eq 0) { continue }
    $sample = $items[0]
    $missing = @()
    foreach ($prop in $schemaExpected[$source]) {
        if (-not $sample.PSObject.Properties[$prop]) { $missing += $prop }
    }
    if ($missing.Count -gt 0) {
        $warn = "$source — missing properties: $($missing -join ', ')"
        $schemaWarnings += $warn
        Write-Host "    SCHEMA WARNING: $warn" -ForegroundColor Yellow
    }
}
if ($schemaWarnings.Count -gt 0) {
    Write-Host "  $($schemaWarnings.Count) schema warning(s)" -ForegroundColor Yellow
} else {
    Write-Host "  Schema validation passed" -ForegroundColor Green
}

# Subscription extraction
$subscriptionMap = @{}
$subscriptionNames = @{}
$nameFields = @('vmName','storageAccountName','appName','serverName','vaultName','nsgName',
    'cacheName','factoryName','registryName','groupName','diskName','peeringName','vnetName',
    'accountName','policyName','shareName','containerName','slotName','userPrincipalName','configName')

foreach ($key in $D.Keys) {
    foreach ($item in @($D[$key])) {
        if (-not $item.PSObject.Properties['subscriptionId'] -or -not $item.subscriptionId) { continue }
        $subId = [string]$item.subscriptionId
        if (-not $subscriptionNames.ContainsKey($subId)) { $subscriptionNames[$subId] = $subId }
        foreach ($nf in $nameFields) {
            if ($item.PSObject.Properties[$nf] -and $item.$nf) {
                $subscriptionMap[[string]$item.$nf] = $subId
            }
        }
    }
}

# Friendly names from Subscriptions export
$subFiles = Get-ChildItem $ExportPath -Filter "Subscriptions_*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($subFiles) {
    try {
        $subJson = Get-Content $subFiles.FullName -Raw | ConvertFrom-Json
        $subData = if ($subJson.PSObject.Properties['data']) { $subJson.data } else { $subJson }
        foreach ($sub in @($subData)) {
            if ($sub.PSObject.Properties['subscriptionId'] -and $sub.PSObject.Properties['displayName']) {
                $subscriptionNames[$sub.subscriptionId] = $sub.displayName
            }
            elseif ($sub.PSObject.Properties['subscriptionId'] -and $sub.PSObject.Properties['subscriptionName']) {
                $subscriptionNames[$sub.subscriptionId] = $sub.subscriptionName
            }
        }
    } catch { }
}

# Manifest subscription names
$manifestFiles = Get-ChildItem $ExportPath -Filter "Manifest_*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($manifestFiles) {
    try {
        $manifest = Get-Content $manifestFiles.FullName -Raw | ConvertFrom-Json
        if ($manifest.PSObject.Properties['subscriptions']) {
            foreach ($sub in @($manifest.subscriptions)) {
                $subId = $null; $subName = $null
                if ($sub.PSObject.Properties['subscriptionId']) { $subId = $sub.subscriptionId }
                elseif ($sub.PSObject.Properties['id']) { $subId = $sub.id }
                if ($sub.PSObject.Properties['displayName']) { $subName = $sub.displayName }
                elseif ($sub.PSObject.Properties['name']) { $subName = $sub.name }
                if ($subId -and $subName) { $subscriptionNames[$subId] = $subName }
            }
        }
    } catch { }
}

foreach ($key in @($subscriptionNames.Keys)) {
    if ($subscriptionNames[$key] -eq $key) { $subscriptionNames[$key] = $key.Substring(0, 8) + '...' }
}

Write-Host "  $($subscriptionNames.Count) subscription(s) detected" -ForegroundColor Gray
Write-Host ""

if ($D.Count -eq 0) {
    Write-Host "  No JSON exports found in $ExportPath" -ForegroundColor Red
    Write-Host "  Run Invoke-ArExport first." -ForegroundColor Yellow
    return
}


$sevThreshold = $SeverityOrder[$MinSeverity]
$findings = [System.Collections.Generic.List[object]]::new()
$checksRun = 0
$checksPassed = 0

Write-Host "  Running $($Checks.Count) checks..." -ForegroundColor Gray

foreach ($check in $Checks) {
    $checksRun++
    $cisRef    = $check.CIS
    $section   = [int]($cisRef.Split('.')[0])
    $secName   = if ($CISSections.ContainsKey("$section")) { $CISSections["$section"].Name } else { "Unknown" }

    try {
        $rawResults = & $check.Check $D
        $results = @()
        if ($null -ne $rawResults) {
            foreach ($item in @($rawResults)) {
                if ($null -ne $item) { $results += $item }
            }
        }
    }
    catch {
        $results = @(@{
            AffectedResources = @("Check execution error: $_")
            Description       = "Internal error running check $cisRef"
        })
    }

    try {
        if ($results.Count -eq 0) {
            $checksPassed++
            $findings.Add([PSCustomObject]@{
                CIS = $cisRef; Section = $section; SectionName = $secName; Title = $check.Title
                Severity = "Pass"; Automated = $check.Automated; Status = "Pass"
                Description = ""; AffectedResources = @(); Recommendation = ""
            })
        }
        else {
            foreach ($r in $results) {
                $isManual = $false
                if ($r -is [hashtable] -and $r.ContainsKey('Manual') -and $r['Manual']) { $isManual = $true }
                if ($isManual) { continue }
                $sev = $check.Severity
                $status = "Fail"
                $desc = if ($r -is [hashtable] -and $r.ContainsKey('Description')) { $r['Description'] } else { "" }
                $rec = ""
                if ($r -is [hashtable] -and $r.ContainsKey('Recommendation')) { $rec = $r['Recommendation'] }
                elseif ($check.ContainsKey('Recommendation') -and $check['Recommendation']) { $rec = $check['Recommendation'] }
                $affected = @()
                if ($r -is [hashtable] -and $r.ContainsKey('AffectedResources')) { $affected = @($r['AffectedResources']) }

                if ($SeverityOrder.ContainsKey($sev) -and $SeverityOrder[$sev] -ge $sevThreshold) {
                    $findings.Add([PSCustomObject]@{
                        CIS = $cisRef; Section = $section; SectionName = $secName; Title = $check.Title
                        Severity = $sev; Automated = $check.Automated; Status = $status
                        Description = $desc; AffectedResources = $affected; Recommendation = $rec
                    })
                }
            }
        }
    }
    catch {
        Write-Host "    $cisRef error: $_" -ForegroundColor Red
        $findings.Add([PSCustomObject]@{
            CIS = $cisRef; Section = $section; SectionName = $secName; Title = $check.Title
            Severity = "Info"; Automated = $check.Automated; Status = "Fail"
            Description = "Result processing error: $_"; AffectedResources = @(); Recommendation = ""
        })
    }
}

# PS7 safe conversion
[array]$findings = @($findings.ToArray())

# Tag with subscription IDs
foreach ($f in $findings) {
    $subs = @()
    foreach ($r in @($f.AffectedResources)) {
        $rStr = [string]$r
        if ($subscriptionMap.ContainsKey($rStr)) { $subs += $subscriptionMap[$rStr] }
        else {
            $token = ($rStr -split '[\s:/—\-]')[0]
            if ($token -and $subscriptionMap.ContainsKey($token)) { $subs += $subscriptionMap[$token] }
        }
    }
    $f | Add-Member -NotePropertyName 'Subscriptions' -NotePropertyValue @($subs | Select-Object -Unique) -Force
}

$failFindings = @($findings | Where-Object { $_.Status -eq 'Fail' })
$passFindings = @($findings | Where-Object { $_.Status -eq 'Pass' })


$sectionMetrics = @{}
foreach ($sec in $CISSections.Keys) {
    $secFindings = @($findings | Where-Object { $_.Section -eq $sec })
    $secFail = @($secFindings | Where-Object { $_.Status -eq 'Fail' })
    $secPass = @($secFindings | Where-Object { $_.Status -eq 'Pass' })
    $total = $CISSections[$sec].Total
    $automated = $secPass.Count + $secFail.Count
    if ($automated -eq 0) { continue }
    $score = [math]::Round(($secPass.Count / $automated) * 100)
    $sectionMetrics[$sec] = @{
        Name = $CISSections[$sec].Name; Total = $total; Automated = $automated
        Passed = $secPass.Count; Failed = $secFail.Count; Score = $score
    }
}

$totalAuto = 0; $totalPassed = 0
foreach ($m in @($sectionMetrics.Values)) { $totalAuto += $m.Automated; $totalPassed += $m.Passed }
$overallScore = if ($totalAuto -gt 0) { [math]::Round(($totalPassed / $totalAuto) * 100) } else { 0 }

$findingsJson = @($findings | Where-Object { $_.Status -ne 'Pass' } | ForEach-Object {
    @{
        cis = $_.CIS; section = $_.Section; title = $_.Title; severity = $_.Severity
        status = $_.Status; desc = $_.Description; rec = $_.Recommendation
        affected = @($_.AffectedResources).Count; subs = @($_.Subscriptions)
    }
}) | ConvertTo-Json -Depth 5 -Compress
if (-not $findingsJson -or $findingsJson -eq 'null') { $findingsJson = '[]' }

$reportDataJson = @{
    score = $overallScore; generated = (Get-Date -Format "yyyy-MM-dd HH:mm")
    counts = @{
        critical = @($failFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
        high     = @($failFindings | Where-Object { $_.Severity -eq 'High' }).Count
        medium   = @($failFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
        low      = @($failFindings | Where-Object { $_.Severity -eq 'Low' }).Count
        passed   = $passFindings.Count
    }
    subscriptions = $subscriptionNames; schemaWarnings = $schemaWarnings
} | ConvertTo-Json -Depth 3 -Compress

$sectionMetricsJson = $sectionMetrics | ConvertTo-Json -Depth 3 -Compress


# NCS Logo (inline SVG)
$logoSvg = @'
<svg xmlns="http://www.w3.org/2000/svg" width="315" height="80" viewBox="0 0 3150 800" preserveAspectRatio="xMidYMid meet">
  <defs>
    <linearGradient id="grayGrad" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%"  stop-color="#99999b"/>
      <stop offset="100%" stop-color="#64686e"/>
    </linearGradient>
    <linearGradient id="blueGrad" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%"  stop-color="#53aede"/>
      <stop offset="100%" stop-color="#196ca6"/>
    </linearGradient>
  </defs>
  <path d="M-0.00,404.23 L-0.00,8.47 L362.50,11.73 L725.00,15.00 L792.34,46.90 C846.25,72.44 865.57,88.09 889.22,125.38 C933.76,195.61 940.00,246.01 940.00,535.49 L940.00,800.00 L836.78,800.00 L733.56,800.00 L737.95,557.50 C742.54,303.89 737.28,254.66 700.65,208.09 C690.04,194.61 663.80,178.31 642.33,171.88 C598.11,158.63 273.04,145.55 228.90,155.24 L200.00,161.59 L200.00,480.79 L200.00,800.00 L100.00,800.00 L0.00,800.00 L-0.00,404.23 Z M1320.00,786.14 C1161.43,745.65 1082.70,634.51 1072.37,436.56 C1058.98,179.95 1162.48,36.50 1376.14,15.55 C1478.32,5.53 1715.79,2.49 1877.08,9.14 L2019.17,15.00 L1981.56,80.00 L1943.96,145.00 L1684.48,150.16 C1400.24,155.82 1359.98,163.41 1321.26,218.64 C1274.93,284.74 1267.68,461.66 1307.62,551.94 C1344.58,635.49 1410.25,650.00 1751.52,650.00 L2000.31,650.00 L1960.15,713.58 C1938.07,748.55 1920.00,782.30 1920.00,788.58 C1920.00,804.35 1382.75,802.16 1320.00,786.14 Z" fill="url(#grayGrad)" fill-rule="evenodd"/>
  <path d="M2031.54,792.88 C2033.44,788.55 2054.64,752.37 2078.64,712.50 L2122.28,640.00 L2483.64,639.44 C2736.16,639.04 2855.48,635.28 2879.79,626.94 C2918.42,613.68 2936.87,578.74 2926.68,538.12 C2914.89,491.15 2886.24,486.28 2580.00,479.26 C2282.57,472.45 2248.93,467.85 2172.28,423.57 C2109.61,387.37 2078.82,335.12 2074.74,258.05 C2070.34,174.88 2088.96,123.94 2140.74,77.51 C2218.13,8.12 2232.05,6.30 2717.50,2.36 C2955.38,0.42 3150.00,2.02 3150.00,5.92 C3150.00,9.81 3130.88,45.86 3107.50,86.01 L3065.00,159.03 L2704.54,162.01 C2376.54,164.73 2341.59,166.63 2316.47,183.10 C2293.29,198.30 2289.36,207.12 2291.93,238.10 C2294.58,269.93 2300.49,277.74 2335.00,294.92 C2371.20,312.94 2402.10,315.37 2660.00,320.41 C2967.43,326.42 2990.79,330.11 3070.19,385.13 C3123.25,421.90 3150.00,480.03 3150.00,558.56 C3150.00,661.79 3111.56,717.02 3004.97,766.92 L2945.00,795.00 L2486.54,797.88 C2234.38,799.47 2029.63,797.22 2031.54,792.88 Z" fill="url(#blueGrad)" fill-rule="evenodd"/>
</svg>
'@

# Report CSS
$cssBlock = @'
:root{--navy:#00263A;--navy2:#0A3D5C;--gold:#B4975A;--bg:#FFFFFF;--surface:#F7F7F5;--surface2:#EEEDEA;--card:#EEEDEA;--border:#D9D6CF;--border-light:#EEECE7;--text:#00263A;--muted:#5C6B7A;--text3:#8F9BAA;
--crit:#B91C3A;--high:#C4650A;--med:#8B7231;--low:#2B6CB0;--info:#6B7280;--pass:#00856A;
--accent:#B4975A;--serif:Georgia,'Times New Roman',serif;--sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.6;-webkit-font-smoothing:antialiased}
.container{max-width:1100px;margin:0 auto;padding:0 2.5rem 4rem}
header{display:flex;align-items:center;padding:2rem 0 1.5rem;border-bottom:2px solid var(--navy);gap:24px}
.logo{flex-shrink:0}
.logo svg{width:120px;height:auto}
.header-content{flex:1;text-align:center}
header h1{font-family:var(--serif);font-size:1.75rem;font-weight:400;color:var(--navy)}
header .subtitle{color:var(--muted);margin-top:6px;font-size:.8rem;letter-spacing:.02em}
.score-ring{display:inline-flex;flex-direction:column;align-items:center;justify-content:center;width:120px;height:120px;border-radius:50%;border:4px solid var(--border);margin:24px auto;position:relative}
.score-ring .pct{font-family:var(--serif);font-size:2rem;font-weight:400;color:var(--navy)}
.score-ring .label{font-size:.6rem;color:var(--text3);text-transform:uppercase;letter-spacing:.1em;position:absolute;bottom:-20px;font-weight:500}
.metrics{display:flex;gap:0;justify-content:center;padding:1.5rem 0;border-bottom:1px solid var(--border-light)}
.metric{flex:1;padding:0 1.5rem;border-right:1px solid var(--border-light);text-align:left}
.metric:first-child{padding-left:0}.metric:last-child{border-right:none}
.metric .val{font-family:var(--serif);font-size:1.75rem;font-weight:400;line-height:1}
.metric .lbl{font-size:.65rem;color:var(--text3);text-transform:uppercase;letter-spacing:.1em;margin-top:4px;font-weight:500}
.sections{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px;margin:24px 0}
.sec-card{background:var(--surface);padding:16px;cursor:pointer;border:1px solid var(--border-light);transition:border-color .2s}
.sec-card:hover,.sec-card.active{border-color:var(--gold)}
.sec-card h3{font-family:var(--serif);font-size:.9rem;font-weight:400;color:var(--navy);margin-bottom:8px}
.sec-bar{height:6px;background:var(--card);overflow:hidden;margin:8px 0}
.sec-bar-fill{height:100%;transition:width .3s}
.sec-stats{display:flex;gap:12px;font-size:.7rem;color:var(--text3)}
.sec-stats span{display:flex;align-items:center;gap:4px}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.filters{display:flex;gap:5px;margin:24px 0;flex-wrap:wrap;align-items:center}
.filters label{font-size:.65rem;color:var(--text3);text-transform:uppercase;letter-spacing:.08em;margin-right:4px;font-weight:500}
.btn{padding:3px 12px;border:1px solid var(--border);background:transparent;color:var(--muted);cursor:pointer;font-family:var(--sans);font-size:.65rem;font-weight:500;letter-spacing:.03em;text-transform:uppercase;transition:all .15s}
.btn:hover{border-color:var(--navy);color:var(--navy)}
.btn.active{background:var(--navy);color:#fff;border-color:var(--navy)}
.finding{background:var(--bg);padding:14px 0;margin:0;border-bottom:1px solid var(--border-light);border-left:3px solid var(--border)}
.finding.Critical{border-left-color:var(--crit)}.finding.High{border-left-color:var(--high)}
.finding.Medium{border-left-color:var(--med)}.finding.Low{border-left-color:var(--low)}
.finding.Info{border-left-color:var(--info)}
.finding .fhead{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;padding-left:16px}
.finding .cis-ref{font-family:monospace;font-size:.78rem;color:var(--navy);font-weight:600;letter-spacing:.02em}
.badge{display:inline-block;padding:2px 12px;border-radius:16px;font-size:.6rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#fff}
.badge.Critical{background:var(--crit)}.badge.High{background:var(--high)}
.badge.Medium{background:var(--med)}.badge.Low{background:var(--low)}
.badge.Info{background:var(--info)}
.finding .ftitle{font-size:.85rem;font-weight:400;color:var(--text);padding-left:16px;margin-bottom:4px}
.finding .desc{font-size:.78rem;color:var(--muted);margin:4px 0;padding-left:16px}
.finding .affected{font-size:.72rem;color:var(--muted);margin:8px 0 0 16px;padding:10px 16px;background:var(--surface);border-left:3px solid var(--gold);font-family:monospace;max-height:400px;overflow-y:auto;white-space:pre-wrap}
.finding .rec{font-size:.78rem;color:var(--pass);margin-top:8px;padding-left:16px;font-style:italic}
.empty{text-align:left;color:var(--text3);padding:2rem 0;font-size:.85rem;font-style:italic}
.sub-filter{margin-left:auto}
.sub-filter select{padding:3px 10px;border:1px solid var(--border);background:transparent;color:var(--text);font-family:var(--sans);font-size:.65rem;font-weight:500;letter-spacing:.03em;text-transform:uppercase;cursor:pointer;appearance:auto;min-width:160px}
.sub-filter select:focus{border-color:var(--navy);outline:none}
.schema-warnings{background:var(--surface);border-left:3px solid var(--high);padding:12px 16px;margin:16px 0;font-size:.78rem;color:var(--muted)}
.schema-warnings strong{color:var(--text);font-size:.8rem}
footer{text-align:center;color:var(--text3);font-size:.7rem;padding:1.5rem 0;border-top:2px solid var(--navy);margin-top:3rem}
@media(max-width:600px){.container{padding:0 1rem 3rem}.metrics{flex-wrap:wrap;gap:1rem}.metric{border-right:none;padding:0}header{flex-direction:column;text-align:center}}
'@

# Report JavaScript
$jsBlock = @'
(function(){
"use strict";
var report=JSON.parse(document.getElementById("report-data").textContent);
var findings=JSON.parse(document.getElementById("findings-data").textContent);
var sections=JSON.parse(document.getElementById("sections-data").textContent);
var activeSection=null,activeSev="all",activeSub="all";

function mk(tag,cls){var e=document.createElement(tag);if(cls)e.className=cls;return e;}
function txt(tag,cls,t){var e=mk(tag,cls);e.textContent=t;return e;}

document.getElementById("subtitle").textContent="Control Gap Analysis \u2014 Generated "+report.generated;
document.getElementById("score-pct").textContent=report.score+"%";
var ring=document.getElementById("score-ring");
ring.style.borderColor=report.score>=80?"var(--pass)":report.score>=50?"var(--med)":"var(--crit)";

var mbar=document.getElementById("metrics-bar");
var mdef=[["crit","Critical",report.counts.critical],["high","High",report.counts.high],["med","Medium",report.counts.medium],["low","Low",report.counts.low],["pass","Passed",report.counts.passed]];
mdef.forEach(function(m){
  var d=mk("div","metric");
  var v=txt("div","val",String(m[2]));v.style.color="var(--"+m[0]+")";
  d.appendChild(v);d.appendChild(txt("div","lbl",m[1]));mbar.appendChild(d);
});

if(report.schemaWarnings&&report.schemaWarnings.length>0){
  var warnDiv=mk("div","schema-warnings");
  warnDiv.appendChild(txt("strong","","Schema Validation Warnings"));
  report.schemaWarnings.forEach(function(w){warnDiv.appendChild(txt("div","",w));});
  document.getElementById("sections").parentNode.insertBefore(warnDiv,document.getElementById("sections"));
}

function renderSections(){
  var el=document.getElementById("sections");
  while(el.firstChild)el.removeChild(el.firstChild);
  var keys=Object.keys(sections).sort(function(a,b){return parseInt(a)-parseInt(b)});
  keys.forEach(function(k){
    var s=sections[k];
    var scoreColor=s.Score>=80?"var(--pass)":s.Score>=50?"var(--med)":"var(--crit)";
    var card=mk("div","sec-card"+(activeSection===parseInt(k)?" active":""));
    card.appendChild(txt("h3","","Section "+k+": "+s.Name));
    var bar=mk("div","sec-bar");var fill=mk("div","sec-bar-fill");
    fill.style.width=s.Score+"%";fill.style.background=scoreColor;bar.appendChild(fill);card.appendChild(bar);
    var stats=mk("div","sec-stats");
    var sp=mk("span","");var d1=mk("span","dot");d1.style.background="var(--pass)";sp.appendChild(d1);sp.appendChild(document.createTextNode(s.Passed+" passed"));stats.appendChild(sp);
    var sf=mk("span","");var d2=mk("span","dot");d2.style.background="var(--crit)";sf.appendChild(d2);sf.appendChild(document.createTextNode(s.Failed+" failed"));stats.appendChild(sf);
    var sc=mk("span","");sc.style.marginLeft="auto";sc.style.fontWeight="600";sc.style.color=scoreColor;sc.textContent=s.Score+"%";stats.appendChild(sc);
    card.appendChild(stats);
    card.addEventListener("click",function(){activeSection=activeSection===parseInt(k)?null:parseInt(k);renderSections();renderFindings();});
    el.appendChild(card);
  });
}

function renderFindings(){
  var el=document.getElementById("findings-list");
  while(el.firstChild)el.removeChild(el.firstChild);
  var filtered=findings.filter(function(f){
    if(activeSection&&f.section!==activeSection)return false;
    if(activeSev!=="all"){if(f.severity!==activeSev)return false;}
    if(activeSub!=="all"){if(!f.subs||f.subs.length===0){}else if(f.subs.indexOf(activeSub)===-1)return false;}
    return true;
  });
  if(filtered.length===0){el.appendChild(txt("div","empty","No findings match the current filters."));return;}
  filtered.sort(function(a,b){var so={Critical:5,High:4,Medium:3,Low:2,Info:1};return(so[b.severity]||0)-(so[a.severity]||0);});
  filtered.forEach(function(f){
    var badgeClass=f.severity;
    var card=mk("div","finding "+f.severity);
    var head=mk("div","fhead");head.appendChild(txt("span","cis-ref","CIS "+f.cis));head.appendChild(txt("span","badge "+badgeClass,badgeClass));card.appendChild(head);
    card.appendChild(txt("div","ftitle",f.title));
    if(f.desc)card.appendChild(txt("div","desc",f.desc));
    if(f.affected&&f.affected>0){var aff=mk("div","affected");aff.textContent=f.affected+" affected resource(s)";card.appendChild(aff);}
    if(f.subs&&f.subs.length>0){
      var subLabels=f.subs.map(function(s){return report.subscriptions&&report.subscriptions[s]?report.subscriptions[s]:s.substring(0,8)+"...";});
      card.appendChild(txt("div","desc",""+subLabels.join(", ")));
    } else {
      card.appendChild(txt("div","desc","Tenant-wide"));
    }
    if(f.rec)card.appendChild(txt("div","rec",""+f.rec));
    el.appendChild(card);
  });
}

var filterBar=document.getElementById("filters");
["all","Critical","High","Medium","Low"].forEach(function(sev){
  var b=mk("button","btn"+(sev==="all"?" active":""));b.textContent=sev==="all"?"All":sev;
  b.addEventListener("click",function(){
    activeSev=sev;filterBar.querySelectorAll(".btn").forEach(function(x){x.classList.remove("active");});b.classList.add("active");renderFindings();
  });
  filterBar.appendChild(b);
});

if(report.subscriptions&&Object.keys(report.subscriptions).length>0){
  var subWrap=mk("div","sub-filter");
  var sel=document.createElement("select");
  var allOpt=document.createElement("option");allOpt.value="all";allOpt.textContent="All subscriptions";sel.appendChild(allOpt);
  var subKeys=Object.keys(report.subscriptions).sort(function(a,b){
    return(report.subscriptions[a]||a).localeCompare(report.subscriptions[b]||b);
  });
  subKeys.forEach(function(subId){
    var opt=document.createElement("option");opt.value=subId;
    opt.textContent=report.subscriptions[subId]||subId.substring(0,13)+"...";
    sel.appendChild(opt);
  });
  sel.addEventListener("change",function(){activeSub=sel.value;renderFindings();});
  subWrap.appendChild(sel);filterBar.appendChild(subWrap);
}

renderSections();
renderFindings();
})();
'@

# CSP hashes
$sha = [System.Security.Cryptography.SHA256]::Create()
$cssHash  = [Convert]::ToBase64String($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($cssBlock)))
$jsHash   = [Convert]::ToBase64String($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($jsBlock)))
$sha.Dispose()

$cspContent = "default-src 'none'; script-src 'sha256-$jsHash'; style-src 'sha256-$cssHash'; img-src data:; font-src data:; base-uri 'none'; form-action 'none'; object-src 'none'"


$htmlTemplate = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta http-equiv="Content-Security-Policy" content="$cspContent">
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NCS Dojo — AzResourceAnalyzer</title>
<style>$cssBlock</style>
</head>
<body>
<div class="container">
<header>
<div class="logo">$logoSvg</div>
<div class="header-content">
<h1>AzResourceAnalyzer</h1>
<div class="subtitle" id="subtitle"></div>
</div>
</header>
<div style="text-align:center">
<div class="score-ring" id="score-ring"><span class="pct" id="score-pct"></span><span class="label">Compliance</span></div>
<div class="metrics" id="metrics-bar"></div>
</div>
<div class="sections" id="sections"></div>
<div class="filters" id="filters"><label>Filter:</label></div>
<div id="findings-list"></div>
<footer>Copyright &copy; NCS Dojo. All Rights Reserved.<br>AzResourceAnalyzer | Auditor: $($script:_ArTenantId) — Generated from Azure Resource Graph, Microsoft Graph, and Key Vault data plane exports.</footer>
</div>
<script type="application/json" id="report-data">$reportDataJson</script>
<script type="application/json" id="sections-data">$sectionMetricsJson</script>
<script type="application/json" id="findings-data">$findingsJson</script>
<script>$jsBlock</script>
</body>
</html>
"@


$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# JSON findings
$jsonPath = Join-Path $OutputPath "CIS_Findings_$timestamp.json"
@($findings) | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8

$htmlPath = Join-Path $OutputPath "CIS_Report_$timestamp.html"
$htmlTemplate | Set-Content -Path $htmlPath -Encoding UTF8

$csvPath = Join-Path $OutputPath "CIS_Findings_$timestamp.csv"
@($findings) | Where-Object { $_.Status -ne 'Pass' } |
    Select-Object CIS, SectionName, Title, Severity, Status, Description, @{N='AffectedResources';E={$_.AffectedResources -join '; '}}, @{N='Subscriptions';E={$_.Subscriptions -join '; '}}, Recommendation |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$scoreColor = if ($overallScore -ge 80) { "Green" } elseif ($overallScore -ge 50) { "Yellow" } else { "Red" }
Write-Host ""
Write-Host "  Score:    $overallScore%  |  $checksPassed passed  |  $($failFindings.Count) findings" -ForegroundColor $scoreColor
Write-Host "  Report:   $htmlPath" -ForegroundColor Gray
Write-Host "  Findings: $jsonPath" -ForegroundColor Gray
Write-Host "  CSV:      $csvPath" -ForegroundColor Gray
Write-Host ""

Write-Warning "Output files contain sensitive tenant data. Treat $OutputPath as confidential."
Start-Process -FilePath $htmlPath

}

# SIG # Begin signature block
# MII9GgYJKoZIhvcNAQcCoII9CzCCPQcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBPOX9eHYBJqspX
# qttUWChH7cGAvDOaBU6rzJ2LZGQqa6CCIdwwggXMMIIDtKADAgECAhBUmNLR1FsZ
# lUgTecgRwIeZMA0GCSqGSIb3DQEBDAUAMHcxCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jvc29mdCBJZGVu
# dGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAy
# MDAeFw0yMDA0MTYxODM2MTZaFw00NTA0MTYxODQ0NDBaMHcxCzAJBgNVBAYTAlVT
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jv
# c29mdCBJZGVudGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRo
# b3JpdHkgMjAyMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALORKgeD
# Bmf9np3gx8C3pOZCBH8Ppttf+9Va10Wg+3cL8IDzpm1aTXlT2KCGhFdFIMeiVPvH
# or+Kx24186IVxC9O40qFlkkN/76Z2BT2vCcH7kKbK/ULkgbk/WkTZaiRcvKYhOuD
# PQ7k13ESSCHLDe32R0m3m/nJxxe2hE//uKya13NnSYXjhr03QNAlhtTetcJtYmrV
# qXi8LW9J+eVsFBT9FMfTZRY33stuvF4pjf1imxUs1gXmuYkyM6Nix9fWUmcIxC70
# ViueC4fM7Ke0pqrrBc0ZV6U6CwQnHJFnni1iLS8evtrAIMsEGcoz+4m+mOJyoHI1
# vnnhnINv5G0Xb5DzPQCGdTiO0OBJmrvb0/gwytVXiGhNctO/bX9x2P29Da6SZEi3
# W295JrXNm5UhhNHvDzI9e1eM80UHTHzgXhgONXaLbZ7LNnSrBfjgc10yVpRnlyUK
# xjU9lJfnwUSLgP3B+PR0GeUw9gb7IVc+BhyLaxWGJ0l7gpPKWeh1R+g/OPTHU3mg
# trTiXFHvvV84wRPmeAyVWi7FQFkozA8kwOy6CXcjmTimthzax7ogttc32H83rwjj
# O3HbbnMbfZlysOSGM1l0tRYAe1BtxoYT2v3EOYI9JACaYNq6lMAFUSw0rFCZE4e7
# swWAsk0wAly4JoNdtGNz764jlU9gKL431VulAgMBAAGjVDBSMA4GA1UdDwEB/wQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTIftJqhSobyhmYBAcnz1AQ
# T2ioojAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQwFAAOCAgEAr2rd5hnn
# LZRDGU7L6VCVZKUDkQKL4jaAOxWiUsIWGbZqWl10QzD0m/9gdAmxIR6QFm3FJI9c
# Zohj9E/MffISTEAQiwGf2qnIrvKVG8+dBetJPnSgaFvlVixlHIJ+U9pW2UYXeZJF
# xBA2CFIpF8svpvJ+1Gkkih6PsHMNzBxKq7Kq7aeRYwFkIqgyuH4yKLNncy2RtNwx
# AQv3Rwqm8ddK7VZgxCwIo3tAsLx0J1KH1r6I3TeKiW5niB31yV2g/rarOoDXGpc8
# FzYiQR6sTdWD5jw4vU8w6VSp07YEwzJ2YbuwGMUrGLPAgNW3lbBeUU0i/OxYqujY
# lLSlLu2S3ucYfCFX3VVj979tzR/SpncocMfiWzpbCNJbTsgAlrPhgzavhgplXHT2
# 6ux6anSg8Evu75SjrFDyh+3XOjCDyft9V77l4/hByuVkrrOj7FjshZrM77nq81YY
# uVxzmq/FdxeDWds3GhhyVKVB0rYjdaNDmuV3fJZ5t0GNv+zcgKCf0Xd1WF81E+Al
# GmcLfc4l+gcK5GEh2NQc5QfGNpn0ltDGFf5Ozdeui53bFv0ExpK91IjmqaOqu/dk
# ODtfzAzQNb50GQOmxapMomE2gj4d8yu8l13bS3g7LfU772Aj6PXsCyM2la+YZr9T
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggabMIIEg6ADAgECAhMzAAE6T9lx
# 3eo/npL1AAAAATpPMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBBT0MgQ0EgMDMwHhcNMjYwNTIxMTg1MTE4WhcNMjYwNTI0
# MTg1MTE4WjBfMQswCQYDVQQGEwJDQTEQMA4GA1UECBMHQWxiZXJ0YTEQMA4GA1UE
# BxMHQ2FsZ2FyeTEVMBMGA1UEChMMRGFycmVuIE1heWVzMRUwEwYDVQQDEwxEYXJy
# ZW4gTWF5ZXMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCnVDNpGjHl
# JgszvxN+dtZEikDyGdiuoXOP/NV/PcHCsQXESnF1SUa2vXjiRr5ppchGTCTN45RW
# f9i5GgeG4zgIBsvI3OrAx8atJe4wsezXSVTrJsyrLM6yy9xkTXcGMJxx6g5VoNm8
# /Lg9Zhp2ST9MNkWP1X3bdEc5O2OkIs8pKldqL0SAZ7Aw6HshFPXMfi0QA8pshH1m
# ZmdQIlyQh/m7WRYsnVq2N/XZ80lDtxHnsbBLUinh5KfZmoC3MmdQuxmAvDMXO5wx
# gvwa7g+66/vFp111lfS9eOFwxjUXpICnDaNV01PExdHk1Fm2wP7gGmxviCjA4UV5
# EFpoTXqvpGYVw4BvnCZ/szsu/Slr1rDpxdBc15SJ3gkw9QS90rV8YIqDO8iyS/C/
# pFaa5YklAH93Y8paacWVzg4SvWzAXmhP71PHnoStYyTIOELRz3DYNQUv3xvFsKoi
# sclutKjKuTiXYojwpfzkOXLs0Kl0MCdaselLfwpZILLWyIdeBwzo7g0CAwEAAaOC
# AdMwggHPMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMDoGA1UdJQQzMDEG
# CisGAQQBgjdhAQAGCCsGAQUFBwMDBhkrBgEEAYI3YYuPpXGB3qaBQNv/tAST5rkV
# MB0GA1UdDgQWBBR+UjK+gq4lWZR8FjbnMSfjErFoFDAfBgNVHSMEGDAWgBSkQwx/
# dlqlhec+jSgPDBeiRWlwxjBnBgNVHR8EYDBeMFygWqBYhlZodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBJRCUyMFZlcmlmaWVk
# JTIwQ1MlMjBBT0MlMjBDQSUyMDAzLmNybDB0BggrBgEFBQcBAQRoMGYwZAYIKwYB
# BQUHMAKGWGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWlj
# cm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENTJTIwQU9DJTIwQ0ElMjAwMy5jcnQw
# VAYDVR0gBE0wSzBJBgRVHSAAMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTANBgkqhkiG9w0B
# AQwFAAOCAgEAtaw54Hz+2BUfCYDiR4REkDLEqQQGSNm393kUM090/K+HI4zxgos6
# dpLBpdinakSSmTM0XpHEE54+yfjB0X8yjkZhr6QXQWVVTzP8bx/kQWYVMwu/v66f
# VlrMO58rUI2hMFKGwwsK/R6cdMP3amiOYrRhnEOSh98q+ie+GOq35uKeaPoYev67
# 1abV8hBv5l06LyelJWvNVJvKT53ehTjRuf9jFfe9sWwlddH3pNLRfnJhTeUCEHBl
# HqQwxwQVju7Z45yN6FihPkkq1DxzBkEmH/5HOMovjGDNDulG7F8k2rkYBL877oUc
# Ug11e/vig1ud5yJqGnod+Y3O9ZbdTEwWM1mllTWdVVq2BPLuMaSimJuUX2Ss+Ilz
# R1HBgofgWgsBHPtbqgW3LvG5OTwg4n2qu/c3GUG6ryqvHVRBuenMp9C+46lJU3w4
# wBD39RfUABk9jcO4G0WPoWJRMie9LcLIhK0pAezlfxlWnwNewE2N/1QnAvKC17h2
# OmcpsE9uRcqcft4asKk1FraXvs0iNAxctjOTdYnAUg3u4K4Hjau2jJpA3rfjQJHC
# N8SICi4KCGZtHXXltRcJ4x3qYzt2OttJRnY5aj5PKTMcPeHkXrgfngBWAwLphU83
# riIUV3Ew/C7ZKwtWf1huH6eZjjtKMQ5kE9QFBYxkrSgBWzw4wpq0UjMwggabMIIE
# g6ADAgECAhMzAAE6T9lx3eo/npL1AAAAATpPMA0GCSqGSIb3DQEBDAUAMFoxCzAJ
# BgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNV
# BAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBBT0MgQ0EgMDMwHhcNMjYwNTIx
# MTg1MTE4WhcNMjYwNTI0MTg1MTE4WjBfMQswCQYDVQQGEwJDQTEQMA4GA1UECBMH
# QWxiZXJ0YTEQMA4GA1UEBxMHQ2FsZ2FyeTEVMBMGA1UEChMMRGFycmVuIE1heWVz
# MRUwEwYDVQQDEwxEYXJyZW4gTWF5ZXMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAw
# ggGKAoIBgQCnVDNpGjHlJgszvxN+dtZEikDyGdiuoXOP/NV/PcHCsQXESnF1SUa2
# vXjiRr5ppchGTCTN45RWf9i5GgeG4zgIBsvI3OrAx8atJe4wsezXSVTrJsyrLM6y
# y9xkTXcGMJxx6g5VoNm8/Lg9Zhp2ST9MNkWP1X3bdEc5O2OkIs8pKldqL0SAZ7Aw
# 6HshFPXMfi0QA8pshH1mZmdQIlyQh/m7WRYsnVq2N/XZ80lDtxHnsbBLUinh5KfZ
# moC3MmdQuxmAvDMXO5wxgvwa7g+66/vFp111lfS9eOFwxjUXpICnDaNV01PExdHk
# 1Fm2wP7gGmxviCjA4UV5EFpoTXqvpGYVw4BvnCZ/szsu/Slr1rDpxdBc15SJ3gkw
# 9QS90rV8YIqDO8iyS/C/pFaa5YklAH93Y8paacWVzg4SvWzAXmhP71PHnoStYyTI
# OELRz3DYNQUv3xvFsKoisclutKjKuTiXYojwpfzkOXLs0Kl0MCdaselLfwpZILLW
# yIdeBwzo7g0CAwEAAaOCAdMwggHPMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQD
# AgeAMDoGA1UdJQQzMDEGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhkrBgEEAYI3YYuP
# pXGB3qaBQNv/tAST5rkVMB0GA1UdDgQWBBR+UjK+gq4lWZR8FjbnMSfjErFoFDAf
# BgNVHSMEGDAWgBSkQwx/dlqlhec+jSgPDBeiRWlwxjBnBgNVHR8EYDBeMFygWqBY
# hlZodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQl
# MjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBBT0MlMjBDQSUyMDAzLmNybDB0BggrBgEF
# BQcBAQRoMGYwZAYIKwYBBQUHMAKGWGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENTJTIwQU9D
# JTIwQ0ElMjAwMy5jcnQwVAYDVR0gBE0wSzBJBgRVHSAAMEEwPwYIKwYBBQUHAgEW
# M2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5
# Lmh0bTANBgkqhkiG9w0BAQwFAAOCAgEAtaw54Hz+2BUfCYDiR4REkDLEqQQGSNm3
# 93kUM090/K+HI4zxgos6dpLBpdinakSSmTM0XpHEE54+yfjB0X8yjkZhr6QXQWVV
# TzP8bx/kQWYVMwu/v66fVlrMO58rUI2hMFKGwwsK/R6cdMP3amiOYrRhnEOSh98q
# +ie+GOq35uKeaPoYev671abV8hBv5l06LyelJWvNVJvKT53ehTjRuf9jFfe9sWwl
# ddH3pNLRfnJhTeUCEHBlHqQwxwQVju7Z45yN6FihPkkq1DxzBkEmH/5HOMovjGDN
# DulG7F8k2rkYBL877oUcUg11e/vig1ud5yJqGnod+Y3O9ZbdTEwWM1mllTWdVVq2
# BPLuMaSimJuUX2Ss+IlzR1HBgofgWgsBHPtbqgW3LvG5OTwg4n2qu/c3GUG6ryqv
# HVRBuenMp9C+46lJU3w4wBD39RfUABk9jcO4G0WPoWJRMie9LcLIhK0pAezlfxlW
# nwNewE2N/1QnAvKC17h2OmcpsE9uRcqcft4asKk1FraXvs0iNAxctjOTdYnAUg3u
# 4K4Hjau2jJpA3rfjQJHCN8SICi4KCGZtHXXltRcJ4x3qYzt2OttJRnY5aj5PKTMc
# PeHkXrgfngBWAwLphU83riIUV3Ew/C7ZKwtWf1huH6eZjjtKMQ5kE9QFBYxkrSgB
# Wzw4wpq0UjMwggcoMIIFEKADAgECAhMzAAAAGA3rkVWpigCYAAAAAAAYMA0GCSqG
# SIb3DQEBDAUAMGMxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xNDAyBgNVBAMTK01pY3Jvc29mdCBJRCBWZXJpZmllZCBDb2RlIFNp
# Z25pbmcgUENBIDIwMjEwHhcNMjYwMzI2MTgxMTMyWhcNMzEwMzI2MTgxMTMyWjBa
# MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSsw
# KQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1MgQU9DIENBIDAzMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyIDaYDRWoon9lVnlj+SOj5xV8Sf5
# Qd+3yUeeRgr0exi2QTJAYo24ilcIKQSN8TOZ3+POM5x/6p3Cfjgqust44J0FvkfG
# Xe1Puy45a5nLJGpc0kNIITMRKZwVvPxx7NlfGSc0JOhz/kg7G77C+y3ZR/3jtpeJ
# pJ4QwcK9Gf0Peuk7xLYeW/JAsY9b6oleGDbYSxkamUfbtnyv8gTFrvN6ejuLqNhH
# YPvoBHsOSC+7555yhapkof0fbzyct1hdWHGXsAFMfLF2TVJ8d2YVYOfZdi6YrT4s
# MxOhTKiLKmhL1XtzM7hXdmv7lg2R+lWw8lIkSu/JiINQ0GAPcwxMsgRXDSPp8VUs
# 4Jby+ruz0bjaoHFd7H+hC8cPPcrEDP2eEdYURVl0acjliigCrXwR05NFJzYj3MZi
# zDGLPI3lIzonX1T40yK8v1FcJ8MXZZCvOXGXwRDGGfwwTTsHaJj+OfWNZ/IsypG4
# bGvqeJcPnEFcQEwRcfYIEe/R4a8k+xw5qTy75CbwWeMFuAlt9lE9kjMg3tvJyDlN
# 5voXx5VXinCwUHMpuVaEQ4yHAlSO7qoBltjzTBNHH3ovMwsAsuhwrLLCVhUu3oP2
# GxYZwEyXMlnzK5DbgGzHzDfDaYPHK0uo1VaMMg9Bhuc3YIvrkFXEiv+t/JgNcRGC
# t6ZyKEIDtPbrgwcCAwEAAaOCAdwwggHYMA4GA1UdDwEB/wQEAwIBhjAQBgkrBgEE
# AYI3FQEEAwIBADAdBgNVHQ4EFgQUpEMMf3ZapYXnPo0oDwwXokVpcMYwVAYDVR0g
# BE0wSzBJBgRVHSAAMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTAZBgkrBgEEAYI3FAIEDB4K
# AFMAdQBiAEMAQTASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFNlBKbAP
# D2Ns72nX9c0pnqRIajDmMHAGA1UdHwRpMGcwZaBjoGGGX2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQl
# MjBDb2RlJTIwU2lnbmluZyUyMFBDQSUyMDIwMjEuY3JsMH0GCCsGAQUFBwEBBHEw
# bzBtBggrBgEFBQcwAoZhaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBJRCUyMFZlcmlmaWVkJTIwQ29kZSUyMFNpZ25pbmcl
# MjBQQ0ElMjAyMDIxLmNydDANBgkqhkiG9w0BAQwFAAOCAgEAcccgVvl+poXUYksA
# /TzDFnBlAJ8ef0FMJzb2XRRhF/uA0QyK/VgoeAvO8B7cPpYNQ97sytdA7LT19CxS
# wRQAt71jGF+CJl8KC4aEdMZTfJlHaKyd24J6QiVriNed9WdawsD7lK0pAcXziBg5
# N6dhAm9x6P8R4uT0UkfzlK1rkB8F4mlzE7l7tyES3s8FZGaRZjcGEQ+e0fTcdhf8
# jO7czmNB4dIRgmmBCt/P+ha0tEl2nV1sg1An5+VzhgAkY1Apx8fiUFBtH+Ehw/om
# 5aQCNIJfmR51ZnV18R02Xk2tAmAiIRcSj9vdtrNIOsy5nolddy1lJrbf1Be061l6
# TItv9FDZ4mg6B+65zxkVecVV/Ll8uLGYouGrMM6jzO2O/ps3K2p6mfBI2ZOYIy4U
# NwNrGWqa5TrvAmkZsn3CIlR+81X4AL5vNTFlxc4gH+5su0Dr58hBTxnXavDEnz7X
# 0csP1Kt7h+iqaGiTSHz2B+n3HmUoud0WrdQPYKxMat0To4YUqU3HIbgSLQDDVT8a
# CjW1Jvokf1915C/vVkIIp48h3voVy3JWPLwBlxQ9aeND6jCKQGLJhCQRSlvXX+P/
# 9TeaEA6/xWPSASZf6Ekve/Yua7U+zWc/Sr2K2gj0QRrNEAsvrFr4EGtHKDO9ECVS
# 3lcJksVDv9KHdMPUK8u20i68RqAwggeeMIIFhqADAgECAhMzAAAAB4ejNKN7pY4c
# AAAAAAAHMA0GCSqGSIb3DQEBDAUAMHcxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jvc29mdCBJZGVudGl0
# eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAyMDAe
# Fw0yMTA0MDEyMDA1MjBaFw0zNjA0MDEyMDE1MjBaMGMxCzAJBgNVBAYTAlVTMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNDAyBgNVBAMTK01pY3Jvc29m
# dCBJRCBWZXJpZmllZCBDb2RlIFNpZ25pbmcgUENBIDIwMjEwggIiMA0GCSqGSIb3
# DQEBAQUAA4ICDwAwggIKAoICAQCy8MCvGYgo4t1UekxJbGkIVQm0Uv96SvjB6yUo
# 92cXdylN65Xy96q2YpWCiTas7QPTkGnK9QMKDXB2ygS27EAIQZyAd+M8X+dmw6SD
# tzSZXyGkxP8a8Hi6EO9Zcwh5A+wOALNQbNO+iLvpgOnEM7GGB/wm5dYnMEOguua1
# OFfTUITVMIK8faxkP/4fPdEPCXYyy8NJ1fmskNhW5HduNqPZB/NkWbB9xxMqowAe
# WvPgHtpzyD3PLGVOmRO4ka0WcsEZqyg6efk3JiV/TEX39uNVGjgbODZhzspHvKFN
# U2K5MYfmHh4H1qObU4JKEjKGsqqA6RziybPqhvE74fEp4n1tiY9/ootdU0vPxRp4
# BGjQFq28nzawuvaCqUUF2PWxh+o5/TRCb/cHhcYU8Mr8fTiS15kRmwFFzdVPZ3+J
# V3s5MulIf3II5FXeghlAH9CvicPhhP+VaSFW3Da/azROdEm5sv+EUwhBrzqtxoYy
# E2wmuHKws00x4GGIx7NTWznOm6x/niqVi7a/mxnnMvQq8EMse0vwX2CfqM7Le/sm
# bRtsEeOtbnJBbtLfoAsC3TdAOnBbUkbUfG78VRclsE7YDDBUbgWt75lDk53yi7C3
# n0WkHFU4EZ83i83abd9nHWCqfnYa9qIHPqjOiuAgSOf4+FRcguEBXlD9mAInS7b6
# V0UaNwIDAQABo4ICNTCCAjEwDgYDVR0PAQH/BAQDAgGGMBAGCSsGAQQBgjcVAQQD
# AgEAMB0GA1UdDgQWBBTZQSmwDw9jbO9p1/XNKZ6kSGow5jBUBgNVHSAETTBLMEkG
# BFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA
# QwBBMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUyH7SaoUqG8oZmAQHJ89Q
# EE9oqKIwgYQGA1UdHwR9MHsweaB3oHWGc2h0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElkZW50aXR5JTIwVmVyaWZpY2F0aW9u
# JTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAyMC5jcmwwgcMG
# CCsGAQUFBwEBBIG2MIGzMIGBBggrBgEFBQcwAoZ1aHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBJZGVudGl0eSUyMFZlcmlm
# aWNhdGlvbiUyMFJvb3QlMjBDZXJ0aWZpY2F0ZSUyMEF1dGhvcml0eSUyMDIwMjAu
# Y3J0MC0GCCsGAQUFBzABhiFodHRwOi8vb25lb2NzcC5taWNyb3NvZnQuY29tL29j
# c3AwDQYJKoZIhvcNAQEMBQADggIBAH8lKp7+1Kvq3WYK21cjTLpebJDjW4ZbOX3H
# D5ZiG84vjsFXT0OB+eb+1TiJ55ns0BHluC6itMI2vnwc5wDW1ywdCq3TAmx0KWy7
# xulAP179qX6VSBNQkRXzReFyjvF2BGt6FvKFR/imR4CEESMAG8hSkPYso+GjlngM
# 8JPn/ROUrTaeU/BRu/1RFESFVgK2wMz7fU4VTd8NXwGZBe/mFPZG6tWwkdmA/jLb
# p0kNUX7elxu2+HtHo0QO5gdiKF+YTYd1BGrmNG8sTURvn09jAhIUJfYNotn7OlTh
# tfQjXqe0qrimgY4Vpoq2MgDW9ESUi1o4pzC1zTgIGtdJ/IvY6nqa80jFOTg5qzAi
# RNdsUvzVkoYP7bi4wLCj+ks2GftUct+fGUxXMdBUv5sdr0qFPLPB0b8vq516slCf
# RwaktAxK1S40MCvFbbAXXpAZnU20FaAoDwqq/jwzwd8Wo2J83r7O3onQbDO9TyDS
# tgaBNlHzMMQgl95nHBYMelLEHkUnVVVTUsgC0Huj09duNfMaJ9ogxhPNThgq3i8w
# 3DAGZ61AMeF0C1M+mU5eucj1Ijod5O2MMPeJQ3/vKBtqGZg4eTtUHt/BPjN74SsJ
# syHqAdXVS5c+ItyKWg3Eforhox9k3WgtWTpgV4gkSiS4+A09roSdOI4vrRw+p+fL
# 4WrxSK5nMYIalDCCGpACAQEwcTBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZp
# ZWQgQ1MgQU9DIENBIDAzAhMzAAE6T9lx3eo/npL1AAAAATpPMA0GCWCGSAFlAwQC
# AQUAoF4wEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwLwYJKoZIhvcNAQkEMSIEINRSrhBumgjbuFiH9BabZ7n6yHc/IKhcZ9cQn0uG
# wQqAMA0GCSqGSIb3DQEBAQUABIIBgDbTUcEYk0TpslBpvCtQILNDUar3KWTCqRsx
# 6HHRjtUImhU8HUYm4E4pf7MCPSZyIM3a9S/NpDX3ABGSQr3I4mPf+n/1fdYyWKzm
# GXx4/6ITQXM6OIyYoKmUwGeT1K+nMeyiY7ObRlD8MO/QRZuFDAk15hRON5bUasJb
# qsT+jZmVdfuXoucFP+sAMVd//ZdW2pAGtQnXWQGQvU2mtXj3Ud3sMTJ2za3AWPqy
# ke5xdjXxD1PCtKuxwUKxmDRiOFsuOBWm4ow2FJ+mCzbDMaLQo2LY8JudB+vPuMaN
# y9LAcPVhvlW+q77laInNATUryzERhb5Tr4u2sqxLsihap9WkY5G5YCqKc1uHEiYR
# nZepahkpIw8WrB2Ie7cTC+ASZXdrpHQ7ZgGH4qlfm8paA3USERMiLvON/hX3jc4R
# YzltKDVbIMpkFVjIEbOy8rp2nLpOt6AV7IM3HNmiaDBRQV/4+/xCfy3qreKl0zTj
# CVXF40visbO99ee8Ahd7oQPI0jWhv6GCGBQwghgQBgorBgEEAYI3AwMBMYIYADCC
# F/wGCSqGSIb3DQEHAqCCF+0wghfpAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFiBgsq
# hkiG9w0BCRABBKCCAVEEggFNMIIBSQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCByiZF7mdNboy02WFR+XK1SD/zsI4EaxwmyVaMILzOHWAIGagxE157j
# GBMyMDI2MDUyMjE1NDgyOC45ODRaMASAAgH0oIHhpIHeMIHbMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046NzgwMC0w
# NUUwLUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3Rh
# bXBpbmcgQXV0aG9yaXR5oIIPITCCB4IwggVqoAMCAQICEzMAAAAF5c8P/2YuyYcA
# AAAAAAUwDQYJKoZIhvcNAQEMBQAwdzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjFIMEYGA1UEAxM/TWljcm9zb2Z0IElkZW50aXR5
# IFZlcmlmaWNhdGlvbiBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDIwMB4X
# DTIwMTExOTIwMzIzMVoXDTM1MTExOTIwNDIzMVowYTELMAkGA1UEBhMCVVMxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFB1YmxpYyBSU0EgVGltZXN0YW1waW5nIENBIDIwMjAwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCefOdSY/3gxZ8FfWO1BiKjHB7X55cz0RMFvWVGR3eR
# wV1wb3+yq0OXDEqhUhxqoNv6iYWKjkMcLhEFxvJAeNcLAyT+XdM5i2CgGPGcb95W
# JLiw7HzLiBKrxmDj1EQB/mG5eEiRBEp7dDGzxKCnTYocDOcRr9KxqHydajmEkzXH
# OeRGwU+7qt8Md5l4bVZrXAhK+WSk5CihNQsWbzT1nRliVDwunuLkX1hyIWXIArCf
# rKM3+RHh+Sq5RZ8aYyik2r8HxT+l2hmRllBvE2Wok6IEaAJanHr24qoqFM9WLeBU
# Sudz+qL51HwDYyIDPSQ3SeHtKog0ZubDk4hELQSxnfVYXdTGncaBnB60QrEuazvc
# ob9n4yR65pUNBCF5qeA4QwYnilBkfnmeAjRN3LVuLr0g0FXkqfYdUmj1fFFhH8k8
# YBozrEaXnsSL3kdTD01X+4LfIWOuFzTzuoslBrBILfHNj8RfOxPgjuwNvE6YzauX
# i4orp4Sm6tF245DaFOSYbWFK5ZgG6cUY2/bUq3g3bQAqZt65KcaewEJ3ZyNEobv3
# 5Nf6xN6FrA6jF9447+NHvCjeWLCQZ3M8lgeCcnnhTFtyQX3XgCoc6IRXvFOcPVrr
# 3D9RPHCMS6Ckg8wggTrtIVnY8yjbvGOUsAdZbeXUIQAWMs0d3cRDv09SvwVRd61e
# vQIDAQABo4ICGzCCAhcwDgYDVR0PAQH/BAQDAgGGMBAGCSsGAQQBgjcVAQQDAgEA
# MB0GA1UdDgQWBBRraSg6NS9IY0DPe9ivSek+2T3bITBUBgNVHSAETTBLMEkGBFUd
# IAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsG
# AQQBgjcUAgQMHgoAUwB1AGIAQwBBMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgw
# FoAUyH7SaoUqG8oZmAQHJ89QEE9oqKIwgYQGA1UdHwR9MHsweaB3oHWGc2h0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElkZW50
# aXR5JTIwVmVyaWZpY2F0aW9uJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9y
# aXR5JTIwMjAyMC5jcmwwgZQGCCsGAQUFBwEBBIGHMIGEMIGBBggrBgEFBQcwAoZ1
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQl
# MjBJZGVudGl0eSUyMFZlcmlmaWNhdGlvbiUyMFJvb3QlMjBDZXJ0aWZpY2F0ZSUy
# MEF1dGhvcml0eSUyMDIwMjAuY3J0MA0GCSqGSIb3DQEBDAUAA4ICAQBfiHbHfm21
# WhV150x4aPpO4dhEmSUVpbixNDmv6TvuIHv1xIs174bNGO/ilWMm+Jx5boAXrJxa
# gRhHQtiFprSjMktTliL4sKZyt2i+SXncM23gRezzsoOiBhv14YSd1Klnlkzvgs29
# XNjT+c8hIfPRe9rvVCMPiH7zPZcw5nNjthDQ+zD563I1nUJ6y59TbXWsuyUsqw7w
# XZoGzZwijWT5oc6GvD3HDokJY401uhnj3ubBhbkR83RbfMvmzdp3he2bvIUztSOu
# FzRqrLfEvsPkVHYnvH1wtYyrt5vShiKheGpXa2AWpsod4OJyT4/y0dggWi8g/tgb
# hmQlZqDUf3UqUQsZaLdIu/XSjgoZqDjamzCPJtOLi2hBwL+KsCh0Nbwc21f5xvPS
# wym0Ukr4o5sCcMUcSy6TEP7uMV8RX0eH/4JLEpGyae6Ki8JYg5v4fsNGif1OXHJ2
# IWG+7zyjTDfkmQ1snFOTgyEX8qBpefQbF0fx6URrYiarjmBprwP6ZObwtZXJ23jK
# 3Fg/9uqM3j0P01nzVygTppBabzxPAh/hHhhls6kwo3QLJ6No803jUsZcd4JQxiYH
# Hc+Q/wAMcPUnYKv/q2O444LO1+n6j01z5mggCSlRwD9faBIySAcA9S8h22hIAcRQ
# qIGEjolCK9F6nK9ZyX4lhthsGHumaABdWzCCB5cwggV/oAMCAQICEzMAAABXJNOV
# 4KLpyTEAAAAAAFcwDQYJKoZIhvcNAQEMBQAwYTELMAkGA1UEBhMCVVMxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1
# YmxpYyBSU0EgVGltZXN0YW1waW5nIENBIDIwMjAwHhcNMjUxMDIzMjA0NjUzWhcN
# MjYxMDIyMjA0NjUzWjCB2zELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUG
# A1UECxMeblNoaWVsZCBUU1MgRVNOOjc4MDAtMDVFMC1EOTQ3MTUwMwYDVQQDEyxN
# aWNyb3NvZnQgUHVibGljIFJTQSBUaW1lIFN0YW1waW5nIEF1dGhvcml0eTCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALFspQqTCH24syS2NZD1ztnJl9h0
# Vr0WwJnikmeXse/4wspnVexGqfiHNoqkbVg5CinuYC+iVfNMLZ+QtqhySz8VGBSj
# Rt1JB5ACNtTKAjfmFp4U/Cv2Lj4m+vuve9I3W3hSiImTFsHeYZ6V/Sd43rXrhHV2
# 6fw3xQSteSbg9yTs1rhdrLkAj4KmI0D5P4KavtygirVyUW10gkifWLSE1NiB8Jn3
# RO5dj32deeMNONaaPnw3k49ICTs3Ffyb+ekNDPsNfYwCqPyOTxM6y1dSD0J5j+KK
# 9V+EWyV5PDjV8jjn1zsStlS6TcYJJStcgHs2xT9rs6ooWl5FtYfRkCxhDShEp3s8
# IHUWizTWmLZvAE/6WR2Cd+ZmVapGXTCHJKUByZPxdX0i8gynirR+EwuHHNxEilDI
# CLatO2WZu+CQrH4Zq0NYo1TQ4tUpZ/kAWpoAu1r4mW5EJ3HkEavQ2PuoQDcDq2rA
# GVIla9pD7o9Yxwzl81BuDvUEyu9D/6F0qmQDdaE791HxfCUxpgMYPpdWTzs+dDGP
# ehwQ8P92yP8ARjby5Ony1Z68RjeQebpxf5WL441myFHcgT1UJzzil7tPEkR22NfT
# NR6Fl+jzWb/r80nqlXllhynSowtxo1Y22xqYviS24smikUsBKqOPbSS77uvXEO3V
# rG5LGouE1EZ1Y9pjAgMBAAGjggHLMIIBxzAdBgNVHQ4EFgQUjoPJXi01DgIJSGfm
# 416Yg+0SkqcwHwYDVR0jBBgwFoAUa2koOjUvSGNAz3vYr0npPtk92yEwbAYDVR0f
# BGUwYzBhoF+gXYZbaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwv
# TWljcm9zb2Z0JTIwUHVibGljJTIwUlNBJTIwVGltZXN0YW1waW5nJTIwQ0ElMjAy
# MDIwLmNybDB5BggrBgEFBQcBAQRtMGswaQYIKwYBBQUHMAKGXWh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwUHVibGljJTIw
# UlNBJTIwVGltZXN0YW1waW5nJTIwQ0ElMjAyMDIwLmNydDAMBgNVHRMBAf8EAjAA
# MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDBmBgNVHSAE
# XzBdMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wCAYGZ4EMAQQC
# MA0GCSqGSIb3DQEBDAUAA4ICAQBydcB2POmZOUlAQz2NuXf7vWCVWmjWu9bsY1+H
# Mjv1yeLjxDQkjsJEU5zaIDy8Uw9BYN8+ExX/9k/9CBUsXbVlbU44c65/liyJ83kW
# sFIUwhVazwSShFlbIZviIO/5weyWyTfPPpbSJgWy+ZE9UrQS3xulJLAHA2zUkMMP
# dAlF4RrngcZZ0r45AF9aIYjdestWwdrNK70MfArHqZdgrgXn03w6zBs1v7czceWG
# itg/DlsHqk1mXBpSTuGI2TSPN3E60IIXx5f/AFzh4/HFi98BBZbUELNsXkWAG9yn
# Z5e6CFiil1mgWCWOT90D7Igvg0zKe3o3WCk629/en94K/sC/zLOf2d7yFmTySb9f
# KjcONH1Db3kZ8MzEJ8fHTNmxrl10Gecuz/Gl0+ByTKN+PambZ+F0MIlBPww6fvjF
# C9JII73fw3qO169+9TxTz2G+E26GYY1dcffsAhw6DqTQgbflbl1O/MrSXSs0NSb9
# nBD9RfR/f8Ei7DA1L1jBO7vZhhJTjw2TzFa/ALgRLi3W00hHWi8LGQaZc8SwXIMY
# WfwrN9MgYbhN0Iak9WA2dqWuekXsTwNkmrD3E6E+oCYCehNOgZmds0Ezb1jo7OV0
# Kh22Ll3KHg3MHtlGguxAzhg/BpixPS4qrULLkAjO7+yNsUfrD2U9gMf/OR4yJDPt
# zM0ytTGCB0YwggdCAgEBMHgwYTELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1YmxpYyBSU0Eg
# VGltZXN0YW1waW5nIENBIDIwMjACEzMAAABXJNOV4KLpyTEAAAAAAFcwDQYJYIZI
# AWUDBAIBBQCgggSfMBEGCyqGSIb3DQEJEAIPMQIFADAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MDUyMjE1NDgyOFowLwYJKoZI
# hvcNAQkEMSIEIH+yWsjseYbGer0IjByGEThKZ048Kj3sd0w/e3V3CcKzMIG5Bgsq
# hkiG9w0BCRACLzGBqTCBpjCBozCBoAQg9TyfZLUFbkxliGyizuH9VVDpVFNvQEQh
# KQ2ZhUx421IwfDBlpGMwYTELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1YmxpYyBSU0EgVGlt
# ZXN0YW1waW5nIENBIDIwMjACEzMAAABXJNOV4KLpyTEAAAAAAFcwggNhBgsqhkiG
# 9w0BCRACEjGCA1AwggNMoYIDSDCCA0QwggIsAgEBMIIBCaGB4aSB3jCB2zELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9z
# b2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNO
# Ojc4MDAtMDVFMC1EOTQ3MTUwMwYDVQQDEyxNaWNyb3NvZnQgUHVibGljIFJTQSBU
# aW1lIFN0YW1waW5nIEF1dGhvcml0eaIjCgEBMAcGBSsOAwIaAxUA/S8xOZxCUQFB
# NkrN8Wiij1x5y8OgZzBlpGMwYTELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1YmxpYyBSU0Eg
# VGltZXN0YW1waW5nIENBIDIwMjAwDQYJKoZIhvcNAQELBQACBQDturfPMCIYDzIw
# MjYwNTIyMTEwOTAzWhgPMjAyNjA1MjMxMTA5MDNaMHcwPQYKKwYBBAGEWQoEATEv
# MC0wCgIFAO26t88CAQAwCgIBAAICLZ4CAf8wBwIBAAICEuEwCgIFAO28CU8CAQAw
# NgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgC
# AQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEAp+ECphD6s7pIxdp6+nRgXC/eKqD0
# ARxoMFnQRkeANfsm795D9YKPH+t/7Ja9tEjSQ50rZY174MZr32W4YKAHg6hodObL
# 9cIQgY5EgwqErfrcXM+V+JisVwvWmZ3wfWsKuZ6Z4f2AR6RYzdCBZRYo2m7mOFE1
# AFcePr0PB+2bRE3MHj8TEzsqo7mBTzeMJCBSBEqnhkkpgJVgrcEMXtP4KbKvnzk+
# pYs9KFHj7iTih1P+g4fOkB7rP5ay3rIXD6+CLE856TXFgEurHdCdigQIpjRKAblA
# 32xXmsBjTOXAQTQIw1xG1rDNZjr9mCUA62ifCV12aE9sI2VS/r+mEhqdDTANBgkq
# hkiG9w0BAQEFAASCAgBHzBffpy4jU3XpXUZ9dTD5zdugSQlki6VNnFy4FOTSFgPc
# XF0prIQ5Dld/nMbHsdrcznuShvZV8hxxvl3n5q75ay2QXNmanLORA8u1gMC9uD8n
# i4qqTfNqKx5g9Ifq27hoQXactxpeJ0/ZpAbBy4rHN55HAqIKRlSP3NTE2rQRDlLG
# qeQE8x4YK9JqGWQkEeAbjhfdUjuEO6qY6lQ/+/4uMOSrUoqlQsTCGwwO77SCXIet
# QendjdmM9KOOLoU4HgU4yALfpbmlEYGCXR9/aJo/pwPs2JJbxOFKCDzZxTNwVyS6
# OmSYylh5+KOsQ/wOjWt8oCavnpkB9ZGqEAgfkfxJvVbm4cpu1/G3x9h1XAMnxGD+
# mV0L/QqB0yYf+sTNagJxtwwCvsZteDnNwDyKepP2saxAH/Ai0EHp4Saei+hr7btl
# M9tTZTpL2Ad0CSsMPergU+eSM2/1J/YVJBH36vom4kvD9m+5SQzasJl3RwdnsJv5
# eBwvkKcpBIVE8Oyez47NapRWOxu4CPTbgyY7D2IzmiAgAivbDzvEsWQ7NW3MiXJK
# WWuTA1NA9NRxUj/GOOTrmSgVuzOE4LtW6d+NQyZ/VuFdSLCvAitPujcuIkWSIs+J
# jANaCplPCwz2rK0JwS6lBUlniyLiYsLJT4Qbt/UUGVql9Ptr92uLSGR2E3GrwQ==
# SIG # End signature block
