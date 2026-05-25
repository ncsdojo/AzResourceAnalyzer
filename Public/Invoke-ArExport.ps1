function Invoke-ArExport {
    <#
.SYNOPSIS
    Exports Azure resource inventory.
.DESCRIPTION
    Requires an active session from Connect-ArSession.
    Discovers collectors from Collectors/ and runs them against
    your tenant via Resource Graph, Microsoft Graph, and Key Vault APIs.

    Copyright (c) NCS Dojo. All Rights Reserved.
.PARAMETER Collector
    Collector name(s) to run, or "All" (default). Use -ListCollectors to see options.
.PARAMETER ListCollectors
    Print available collectors and exit.
#>
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        [string[]]$Collector = @("All"),
        [switch]$ListCollectors,
        [string[]]$SubscriptionId,
        [int]$MaxThreads = 50,
        [int]$SubscriptionBatchSize = 50,
        [switch]$SkipGraph,
        [switch]$SkipKeyVault,
        [string]$CollectorPath
    )

if (-not $script:_ArSession -or -not $script:_ArTenantId) {
    Write-Host "`n  Not connected. Run Connect-ArSession first.`n" -ForegroundColor Yellow
    Write-Host "  Example:" -ForegroundColor Gray
    Write-Host "    Connect-ArSession -TenantId 'contoso.onmicrosoft.com'" -ForegroundColor Gray
    Write-Host "    Invoke-ArExport`n" -ForegroundColor Gray
    return
}

if (-not $OutputPath) { $OutputPath = Join-Path ($env:TEMP) 'NCS/AzResourceAnalyzer' }




if (-not $CollectorPath) {
    $CollectorPath = Join-Path $script:_ArModuleRoot "Collectors"
}

Write-Host ""
Write-Information "`n  NCS Dojo — Resource Export" -InformationAction Continue
Write-Host "  Discovering collectors from: $CollectorPath" -ForegroundColor Gray
Write-Host ""

$collectorFiles = Get-ChildItem -Path $CollectorPath -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue |
    Sort-Object DirectoryName, Name

if ($collectorFiles.Count -eq 0) {
    Write-Host "  ERROR: No collector files found in $CollectorPath" -ForegroundColor Red
    Write-Host "  Ensure .ps1 files exist under Collectors/ResourceGraph/, Collectors/MicrosoftGraph/, etc." -ForegroundColor Yellow
    return
}

$AllCollectors = [System.Collections.Generic.List[hashtable]]::new()
$loadErrors = 0

foreach ($file in $collectorFiles) {
    try {
        $definition = . $file.FullName
        if ($null -ne $definition -and $definition -is [hashtable]) {
            $requiredFields = @('Name', 'ApiType', 'FileName', 'Label', 'UniqueField')
            $missing = @($requiredFields | Where-Object { -not $definition.ContainsKey($_) -or -not $definition[$_] })
            if ($missing.Count -gt 0) {
                Write-Host "    WARN: $($file.Name) missing fields: $($missing -join ', ')" -ForegroundColor Yellow
                continue
            }
            $definition['_sourceFile'] = $file.FullName
            $AllCollectors.Add($definition)
        }
        else {
            Write-Host "    WARN: $($file.Name) did not return a hashtable" -ForegroundColor Yellow
        }
    }
    catch {
        $loadErrors++
        Write-Host "    ERROR loading $($file.Name): $_" -ForegroundColor Red
    }
}

Write-Host "  Discovered $($AllCollectors.Count) collectors ($loadErrors errors)" -ForegroundColor $(if ($loadErrors -eq 0) { 'Green' } else { 'Yellow' })

# Group by API type for display
$rgCount    = @($AllCollectors | Where-Object { $_.ApiType -eq 'ResourceGraph' }).Count
$graphCount = @($AllCollectors | Where-Object { $_.ApiType -eq 'MicrosoftGraph' }).Count
$kvCount    = @($AllCollectors | Where-Object { $_.ApiType -eq 'KeyVault' }).Count
Write-Host "    ResourceGraph: $rgCount  |  MicrosoftGraph: $graphCount  |  KeyVault: $kvCount" -ForegroundColor Gray


if ($ListCollectors) {
    Write-Host ""
    Write-Host "  Available Collectors:" -ForegroundColor Cyan
    Write-Host "  $('-' * 70)" -ForegroundColor Gray

    $grouped = $AllCollectors | Group-Object { $_.ApiType } | Sort-Object Name
    foreach ($group in $grouped) {
        Write-Host ""
        Write-Host "  [$($group.Name)]" -ForegroundColor Yellow
        foreach ($c in ($group.Group | Sort-Object { $_.Name })) {
            $nameCol = $c.Name.PadRight(28)
            $fileCol = $c.FileName.PadRight(25)
            Write-Host "    $nameCol $fileCol $($c.Label)" -ForegroundColor Gray
        }
    }
    Write-Host ""
    Write-Host "  Usage: -Collector VirtualMachine" -ForegroundColor Gray
    Write-Host "         -Collector VirtualMachine, NSG, StorageAccount" -ForegroundColor Gray
    Write-Host "         -Collector All  (default)" -ForegroundColor Gray
    Write-Host ""
    return
}


$validNames = @("All") + @($AllCollectors | ForEach-Object { $_.Name })
foreach ($c in $Collector) {
    if ($c -notin $validNames) {
        $suggestions = @($validNames | Where-Object { $_ -like "*$c*" -and $_ -ne 'All' })
        $msg = "Unknown collector '$c'. Valid names: $($validNames -join ', ')"
        if ($suggestions.Count -gt 0) {
            $msg += "`n  Did you mean: $($suggestions -join ', ')?"
        }
        throw $msg
    }
}

$selected = if ($Collector -contains "All") {
    @($AllCollectors | ForEach-Object { $_.Name })
} else {
    @($Collector)
}

# Partition by API type
$rgCollectors    = @($AllCollectors | Where-Object { $_.Name -in $selected -and $_.ApiType -eq 'ResourceGraph' })
$graphCollectors = @($AllCollectors | Where-Object { $_.Name -in $selected -and $_.ApiType -eq 'MicrosoftGraph' })
$kvCollectors    = @($AllCollectors | Where-Object { $_.Name -in $selected -and $_.ApiType -eq 'KeyVault' })

if ($SkipGraph)    { $graphCollectors = @() }
if ($SkipKeyVault) { $kvCollectors    = @() }

$totalSelected = $rgCollectors.Count + $graphCollectors.Count + $kvCollectors.Count
Write-Host ""
Write-Host "  Selected $totalSelected collectors to run" -ForegroundColor Green
Write-Host "    ResourceGraph: $($rgCollectors.Count)  |  MicrosoftGraph: $($graphCollectors.Count)  |  KeyVault: $($kvCollectors.Count)" -ForegroundColor Gray

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$usingDefaultPath = -not $PSBoundParameters.ContainsKey('OutputPath')
if ($usingDefaultPath -and (Test-Path $OutputPath)) {
    Remove-Item -Path $OutputPath -Recurse -Force -ErrorAction SilentlyContinue
}
$null = New-Item -Path $OutputPath -ItemType Directory -Force
$script:logFile = Join-Path $OutputPath "ExportLog_$timestamp.txt"


$TenantId = $script:_ArTenantId


Write-Information '  Checking permissions...' -InformationAction Continue

# ARM access
try {
    $armToken = Get-ArMarshaledToken -Store $script:_ArSession -Scope $script:_ArScopes.Arm
    $subHeaders = @{ Authorization = "Bearer $armToken"; 'Content-Type' = 'application/json' }
    $subResp = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions?api-version=2022-12-01" -Headers $subHeaders -Method GET
}
catch {
    $msg = $_.Exception.Message
    if ($msg -match '401|Unauthorized') {
        Write-Warning "ARM token expired or invalid. Run Connect-ArSession to re-authenticate."
        return
    }
    if ($msg -match '403|Forbidden') {
        Write-Warning "No access to Azure subscriptions. The account needs at least Reader role on one subscription."
        return
    }
    Write-Warning "Failed to list subscriptions: $msg"
    return
}

$allSubs = @($subResp.value | Where-Object { $_.state -eq 'Enabled' } | ForEach-Object {
    [PSCustomObject]@{ subscriptionId = $_.subscriptionId; displayName = $_.displayName }
})

if ($SubscriptionId) {
    $allSubs = @($allSubs | Where-Object { $_.subscriptionId -in $SubscriptionId })
}

if ($allSubs.Count -eq 0) {
    Write-Warning "No accessible subscriptions found. The account needs Reader role on at least one Azure subscription.`n`n  Check role assignments in the Azure portal under Subscriptions > Access control (IAM).`n"
    return
}

Write-Information "  $($allSubs.Count) subscription(s) accessible" -InformationAction Continue

# Graph access (if Graph collectors selected)
if ($graphCollectors.Count -gt 0) {
    try {
        $graphToken = Get-ArMarshaledToken -Store $script:_ArSession -Scope $script:_ArScopes.Graph
        $gHeaders = @{ Authorization = "Bearer $graphToken" }
        $null = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/organization?$top=1' -Headers $gHeaders -Method GET
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '401|Unauthorized') {
            Write-Warning "Graph token expired. Run Connect-ArSession to re-authenticate."
            return
        }
        if ($msg -match '403|Forbidden|Insufficient') {
            Write-Warning "Graph permissions insufficient. Skipping Microsoft Graph collectors.`n  The account needs User.Read.All, Policy.Read.All, and Directory.Read.All.`n  Ask a Global Administrator to grant consent for the application.`n"
            $graphCollectors = @()
        }
    }
}

Write-Information '' -InformationAction Continue

# Batch subscriptions for Resource Graph
$subBatches = @()
for ($i = 0; $i -lt $allSubs.Count; $i += $SubscriptionBatchSize) {
    $batch = @($allSubs[$i..([Math]::Min($i + $SubscriptionBatchSize - 1, $allSubs.Count - 1))] | ForEach-Object { $_.subscriptionId })
    $subBatches += ,@($batch)
}


$collectorStatus = [ordered]@{}

# Resource Graph
if ($rgCollectors.Count -gt 0 -and $subBatches.Count -gt 0) {
    Write-Host ""
    Write-Log "Running $($rgCollectors.Count) Resource Graph collectors..." -Level STEP

    $accessToken = Get-ArMarshaledToken -Store $script:_ArSession -Scope $script:_ArScopes.Arm
    Invoke-ResourceGraphCollection `
        -Collectors $rgCollectors `
        -SubscriptionBatches $subBatches `
        -AccessToken $accessToken `
        -MaxThreads $MaxThreads `
        -CollectorStatus $collectorStatus
}

# Microsoft Graph
if ($graphCollectors.Count -gt 0) {
    Write-Host ""
    Write-Log "Running $($graphCollectors.Count) Microsoft Graph collectors..." -Level STEP

    $graphToken = Get-ArMarshaledToken -Store $script:_ArSession -Scope $script:_ArScopes.Graph
    Invoke-GraphCollection `
        -Collectors $graphCollectors `
        -GraphToken $graphToken `
        -CollectorStatus $collectorStatus
}

# Key Vault
if ($kvCollectors.Count -gt 0) {
    $vaultCount = 0
    if ($collectorStatus.Contains('KeyVault') -and $collectorStatus['KeyVault'].ContainsKey('_results')) {
        $vaultCount = $collectorStatus['KeyVault']['_results'].Count
    }

    if ($vaultCount -eq 0) {
        Write-Host ""
        Write-Log "No vaults found, skipping Key Vault data plane collectors" -Level WARN
    }
    else {
        Write-Host ""
        Write-Log "Running $($kvCollectors.Count) Key Vault collectors against $vaultCount vault(s)..." -Level STEP
        Invoke-KeyVaultCollection `
            -Collectors $kvCollectors `
            -CollectorStatus $collectorStatus `
            -OutputPath $OutputPath
    }
}


Write-Host ""
Write-Log "Writing output files..." -Level STEP

$collectorNames = @($collectorStatus.Keys)
foreach ($name in $collectorNames) {
    try {
        $s = $collectorStatus[$name]

        $resultCount = 0
        $results = @()
        if ($s.ContainsKey('_results') -and $null -ne $s['_results']) {
            $rawList = $s['_results']
            $resultCount = $rawList.Count
            if ($resultCount -gt 0) { $results = @($rawList) }
        }

        
        $coll = @($AllCollectors | Where-Object { $_.Name -eq $name }) | Select-Object -First 1
        $uf = if ($coll) { $coll.UniqueField } else { $null }
        $uniqueCount = 0
        if ($uf -and $resultCount -gt 0) {
            $seen = @{}
            foreach ($r in $results) {
                if ($r.PSObject.Properties[$uf]) {
                    $key = "$($r.$uf)"
                    if ($r.PSObject.Properties['subscriptionId']) { $key = "$($r.subscriptionId)/$key" }
                    $seen[$key] = $true
                }
            }
            $uniqueCount = $seen.Count
        } else {
            $uniqueCount = $resultCount
        }
        $s['uniqueResourceCount'] = $uniqueCount

        # Write JSON
        $output = [ordered]@{
            metadata = [ordered]@{
                collector           = $name
                timestamp           = (Get-Date -Format "o")
                tenantId            = $TenantId
                rowCount            = $resultCount
                uniqueResourceCount = $uniqueCount
            }
            data = $results
        }
        $filePath = Join-Path $OutputPath "$($s['fileName'])_$timestamp.json"
        $output | ConvertTo-Json -Depth 20 | Set-Content -Path $filePath -Encoding UTF8
        $s['filePath'] = $filePath

        if ($s.ContainsKey('_results')) { $s.Remove('_results') }
        $countDisplay = $uniqueCount.ToString().PadLeft(5)
        Write-Host "  $($name.PadRight(25)) $countDisplay" -ForegroundColor Gray
    }
    catch {
        Write-Host "  $($name.PadRight(25)) ERROR" -ForegroundColor Red
    }
}

# Write manifest
$statusValues = @($collectorStatus.Values)
$totalUniqueCalc = 0
$totalRowCalc    = 0
foreach ($sv in $statusValues) {
    $totalRowCalc    += [int]$sv['rowCount']
    $totalUniqueCalc += [int]$sv['uniqueResourceCount']
}

$manifest = [ordered]@{
    exportTimestamp    = (Get-Date -Format "o")
    tenantId          = $TenantId
    subscriptionCount = $allSubs.Count
    subscriptions     = @($allSubs | ForEach-Object { [ordered]@{ id = $_.subscriptionId; name = $_.displayName } })
    collectors        = $collectorStatus
    resourceSummary   = [ordered]@{
        totalUniqueResources = $totalUniqueCalc
        byCollector          = [ordered]@{}
    }
}
foreach ($name in $collectorNames) {
    $manifest.resourceSummary.byCollector[$name] = [int]$collectorStatus[$name]['uniqueResourceCount']
}

$manifestPath = Join-Path $OutputPath "Manifest_$timestamp.json"
$manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestPath -Encoding UTF8

# Summary
$errCount = @($statusValues | Where-Object { $_['status'] -eq 'Error' }).Count
Write-Host ""
Write-Host "  Done. $($collectorNames.Count) collectors, $totalUniqueCalc resources." -ForegroundColor Green
if ($errCount -gt 0) { Write-Host "  $errCount errors." -ForegroundColor Yellow }
Write-Host "  Output: $OutputPath" -ForegroundColor Gray
Write-Host ""

}

# SIG # Begin signature block
# MII9FwYJKoZIhvcNAQcCoII9CDCCPQQCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAwOQr+XiZ7IHX9
# qH0VKbXY7P0pwqEsk0c587IONoCmu6CCIdwwggXMMIIDtKADAgECAhBUmNLR1FsZ
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
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggabMIIEg6ADAgECAhMzAAFKynTD
# 32l/wWVjAAAAAUrKMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDQwHhcNMjYwNTIyMTg0NjAwWhcNMjYwNTI1
# MTg0NjAwWjBfMQswCQYDVQQGEwJDQTEQMA4GA1UECBMHQWxiZXJ0YTEQMA4GA1UE
# BxMHQ2FsZ2FyeTEVMBMGA1UEChMMRGFycmVuIE1heWVzMRUwEwYDVQQDEwxEYXJy
# ZW4gTWF5ZXMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCkZwmcQMXn
# +D7c3CZDJIY60kPXr6G/+R80J6b8AfQ59+KS7LpbCoo8qTlQmMdE9KBz8OVpBZl+
# fGeunRaYE11tRzfNDUNRo47bUXn9WLC9ppHR7fD1rBa0M2/4CHSF8XmpGMhchi78
# 8GTxSvo8PVbeQmcWu1OZc6c0v7VTa+WMn8pPxBadjuBzQLfu8W7ZM93yk9gM3zgY
# w7rpOXTK88g9hgAqa44c2hawBH+x+YOzex/pN/ANevNKyMukAhKGTDSrdT1gA/zu
# spyhqBY3/3mQGPJw1vDoE6dtaCEqEP4zA58O/33WbG5N89Ux5VULO2xqf2KBrT9k
# QQ5WJqqMkCEyVMATF1Yw6xrDybkTantakYrOu8WVCQu1yVTQK4Phkp9jSd7Wi6KO
# RhArBg/PVPD/Az0Vk5k2x9RFYGD8a3LZGNZJW007eCAsuvM6yiNTNhMefekgQIhD
# cV1FOpcHdIX1CG9jArNoWrJv1JcwRp0tdliqwqzCzgD6u6QzqlEoyNMCAwEAAaOC
# AdMwggHPMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMDoGA1UdJQQzMDEG
# CisGAQQBgjdhAQAGCCsGAQUFBwMDBhkrBgEEAYI3YYuPpXGB3qaBQNv/tAST5rkV
# MB0GA1UdDgQWBBR8+HgjLac+sCuRRa+VLYY9BnDgbTAfBgNVHSMEGDAWgBSa8VR3
# dQyHFjdGoKzeefn0f8F46TBnBgNVHR8EYDBeMFygWqBYhlZodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBJRCUyMFZlcmlmaWVk
# JTIwQ1MlMjBFT0MlMjBDQSUyMDA0LmNybDB0BggrBgEFBQcBAQRoMGYwZAYIKwYB
# BQUHMAKGWGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWlj
# cm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAwNC5jcnQw
# VAYDVR0gBE0wSzBJBgRVHSAAMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTANBgkqhkiG9w0B
# AQwFAAOCAgEAJblhyAPmRmpYbfdjQC/PjC8rC2crvirs/FxHLmkL8b3wHRS1LVXb
# f4Jb8tw/z2aRLnA41qHH2HE+uwgq1zLLUJBMvP8V8ypcSFuhmq60RMo3Fh2XhdrH
# ZTkfv0rrz1wYSjtZOyNXfapK+8aox/eETeDPd4XuiIGSn2ReDTETvoJc9VOcGH1F
# CF7Z0OaB1yMyEfEF6LrqmlvFvFD9RGX0wt/lCn0MObH0x+1gIAtdb/8tL3uZ5IW1
# kCig5zD7LTOAbZY55IKPY0ivNThclR9M2psbZxSFKx+I9awnneooDmTOKFQcp6/8
# VMp62/EGCJUB1NVMGmZ1Cz7pMREwIj9svI9Bsa9ZnG2HFpdV9cmsw+Hjjr+Dy/nj
# n5cH41ols2TrnZtj1zz2bUplpU/GRPPl4lf+kBEIgf4Ds46T8AFKcxHdN9hr0oLA
# MKlhTEvUEkTL1yq5AhTOI0aqdBwUHVyOQDMsrZVY0zUaZF4YBr8PzW+QE5YF/oOv
# P5+GSYzjcTArJlIvk/RAjxy2p0YKuZXNMG3vG+z9q+D4hJbM9YRvfPpdlWvtBovn
# 5TgHGKUX4Qo+ovMLcR1YoBwPlNgXN9I3VjvjpaY7/moRqjt7sw3RekZtYeWRmnFn
# joIkoZUP1fb94LlojFPXIhLKePZdH1WuMBS5dtndYNZVS14Zf098bvkwggabMIIE
# g6ADAgECAhMzAAFKynTD32l/wWVjAAAAAUrKMA0GCSqGSIb3DQEBDAUAMFoxCzAJ
# BgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNV
# BAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBFT0MgQ0EgMDQwHhcNMjYwNTIy
# MTg0NjAwWhcNMjYwNTI1MTg0NjAwWjBfMQswCQYDVQQGEwJDQTEQMA4GA1UECBMH
# QWxiZXJ0YTEQMA4GA1UEBxMHQ2FsZ2FyeTEVMBMGA1UEChMMRGFycmVuIE1heWVz
# MRUwEwYDVQQDEwxEYXJyZW4gTWF5ZXMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAw
# ggGKAoIBgQCkZwmcQMXn+D7c3CZDJIY60kPXr6G/+R80J6b8AfQ59+KS7LpbCoo8
# qTlQmMdE9KBz8OVpBZl+fGeunRaYE11tRzfNDUNRo47bUXn9WLC9ppHR7fD1rBa0
# M2/4CHSF8XmpGMhchi788GTxSvo8PVbeQmcWu1OZc6c0v7VTa+WMn8pPxBadjuBz
# QLfu8W7ZM93yk9gM3zgYw7rpOXTK88g9hgAqa44c2hawBH+x+YOzex/pN/ANevNK
# yMukAhKGTDSrdT1gA/zuspyhqBY3/3mQGPJw1vDoE6dtaCEqEP4zA58O/33WbG5N
# 89Ux5VULO2xqf2KBrT9kQQ5WJqqMkCEyVMATF1Yw6xrDybkTantakYrOu8WVCQu1
# yVTQK4Phkp9jSd7Wi6KORhArBg/PVPD/Az0Vk5k2x9RFYGD8a3LZGNZJW007eCAs
# uvM6yiNTNhMefekgQIhDcV1FOpcHdIX1CG9jArNoWrJv1JcwRp0tdliqwqzCzgD6
# u6QzqlEoyNMCAwEAAaOCAdMwggHPMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQD
# AgeAMDoGA1UdJQQzMDEGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhkrBgEEAYI3YYuP
# pXGB3qaBQNv/tAST5rkVMB0GA1UdDgQWBBR8+HgjLac+sCuRRa+VLYY9BnDgbTAf
# BgNVHSMEGDAWgBSa8VR3dQyHFjdGoKzeefn0f8F46TBnBgNVHR8EYDBeMFygWqBY
# hlZodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQl
# MjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBFT0MlMjBDQSUyMDA0LmNybDB0BggrBgEF
# BQcBAQRoMGYwZAYIKwYBBQUHMAKGWGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENTJTIwRU9D
# JTIwQ0ElMjAwNC5jcnQwVAYDVR0gBE0wSzBJBgRVHSAAMEEwPwYIKwYBBQUHAgEW
# M2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5
# Lmh0bTANBgkqhkiG9w0BAQwFAAOCAgEAJblhyAPmRmpYbfdjQC/PjC8rC2crvirs
# /FxHLmkL8b3wHRS1LVXbf4Jb8tw/z2aRLnA41qHH2HE+uwgq1zLLUJBMvP8V8ypc
# SFuhmq60RMo3Fh2XhdrHZTkfv0rrz1wYSjtZOyNXfapK+8aox/eETeDPd4XuiIGS
# n2ReDTETvoJc9VOcGH1FCF7Z0OaB1yMyEfEF6LrqmlvFvFD9RGX0wt/lCn0MObH0
# x+1gIAtdb/8tL3uZ5IW1kCig5zD7LTOAbZY55IKPY0ivNThclR9M2psbZxSFKx+I
# 9awnneooDmTOKFQcp6/8VMp62/EGCJUB1NVMGmZ1Cz7pMREwIj9svI9Bsa9ZnG2H
# FpdV9cmsw+Hjjr+Dy/njn5cH41ols2TrnZtj1zz2bUplpU/GRPPl4lf+kBEIgf4D
# s46T8AFKcxHdN9hr0oLAMKlhTEvUEkTL1yq5AhTOI0aqdBwUHVyOQDMsrZVY0zUa
# ZF4YBr8PzW+QE5YF/oOvP5+GSYzjcTArJlIvk/RAjxy2p0YKuZXNMG3vG+z9q+D4
# hJbM9YRvfPpdlWvtBovn5TgHGKUX4Qo+ovMLcR1YoBwPlNgXN9I3VjvjpaY7/moR
# qjt7sw3RekZtYeWRmnFnjoIkoZUP1fb94LlojFPXIhLKePZdH1WuMBS5dtndYNZV
# S14Zf098bvkwggcoMIIFEKADAgECAhMzAAAAFydFCQuLh6/GAAAAAAAXMA0GCSqG
# SIb3DQEBDAUAMGMxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xNDAyBgNVBAMTK01pY3Jvc29mdCBJRCBWZXJpZmllZCBDb2RlIFNp
# Z25pbmcgUENBIDIwMjEwHhcNMjYwMzI2MTgxMTMxWhcNMzEwMzI2MTgxMTMxWjBa
# MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSsw
# KQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1MgRU9DIENBIDA0MIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgsdk/gMPZioBlcyfk6tDzJ+PRt4r
# SLGKW8ewpS0kRxXtURC3T3GdbCKljobEn8ussqhGqQpRh/SXvRVwNXEIGb76UG5I
# PkCJ1S6/9BD61QQsKzPepW0SNj8TXgsFxvS7MltoRuikIIp7Q5jQgaOM6QyK9++6
# ZVXUpYmZulAe6x8JrwZ0dNkE+rZ66lqtoocwepUSVUxM7odDmn8yDHjJ2DNPsfr3
# uRDix3X4qvh14jH/SW+2Cx7WIMhyIiQO201i6hUixmk4e2ZW8W7C1wPdTjq6BKb+
# zo8xbrt7ZKQvRX5QOA6dhLquPqj5sVKnxqfk19IC0SafTSTs8yC43Ew965BRRW8V
# L9ccoOmr4rxQy7aCgYTNk3dd/LphNaTTmnGp7kmLTxyHkB5geoWhYuuGrywS8E0w
# Jv0W4rfOtHBV0e9sKvuUIeIUpnsx6ilxEVj6VQXvgD6yeCKnPmj3jJiJKAlmUDtt
# h5yzRVBUl44sMiG4L5R/yyACRKk2n088Q2YCoZS1O86+oMLKt1jaXGECOjbsVp8I
# d1VQw8he6J0KirOS5e25XlTdGPFb6oBOOaacgW78Kjf0bp+XzAgkc92mDGNJGYSj
# vdnj+7eMx6meW0DAIGdLRNj8/429MIspFBfz3KDqqpN71S4kQ2LLer3dxhDDczKV
# FL0HLwRuOvgjiG8CAwEAAaOCAdwwggHYMA4GA1UdDwEB/wQEAwIBhjAQBgkrBgEE
# AYI3FQEEAwIBADAdBgNVHQ4EFgQUmvFUd3UMhxY3RqCs3nn59H/BeOkwVAYDVR0g
# BE0wSzBJBgRVHSAAMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTAZBgkrBgEEAYI3FAIEDB4K
# AFMAdQBiAEMAQTASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFNlBKbAP
# D2Ns72nX9c0pnqRIajDmMHAGA1UdHwRpMGcwZaBjoGGGX2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQl
# MjBDb2RlJTIwU2lnbmluZyUyMFBDQSUyMDIwMjEuY3JsMH0GCCsGAQUFBwEBBHEw
# bzBtBggrBgEFBQcwAoZhaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBJRCUyMFZlcmlmaWVkJTIwQ29kZSUyMFNpZ25pbmcl
# MjBQQ0ElMjAyMDIxLmNydDANBgkqhkiG9w0BAQwFAAOCAgEAkHVaGf1NJt/Jdoim
# mRZbMWr6baaDi8mkdWvWStk0hdZDpxSYTA7HuipAoLL3qIhI101XOl7fOiCh5++j
# ZOamQdAV79ojEUNoIgCZmL2XJrLaGanwdjNynecJyYVCTrRf2+h7KknpWOp4axdO
# s6K9ZQ5g0IsQWXCwfc0dfkSkLKNY3pDcWLlJPh2jd5NUue6pNDv/2G5MFNJhCwlt
# ODebyAjGceU+XOzav+7i721YQnQ+39m2aQOFO7zpAdaKAeAGhEd6Y6CdDGneSxco
# ujWvafWbv4ay3jo1ORSLUuWMbKr5X18QE4Sde+gppGLLSkZsrUh2eyYSkX1envWX
# 7ZPzg2/wiuKRlQFarDn+N9+20BqzhxwkNyLzfYJp1Lg4fCXb24XqFjx8SDdRgebF
# ImOfOLVze8XQ/CwkrEaib0PHu2t4GVk4FYroEbNUFqvjdBvTY3uiR5TdQoyXoYHv
# h+TxpLSY2vo7hhK9D/rpEpHC+qmmcRUE4d0gyO9Zb1vvt25fxM3ekjvDfVHcPq3q
# Mr0Rwsk4krKZWUEgU1SXT5qN6gqRrshxbT6OQgZ9/xT04qiXdzPQR6KindBvSpoO
# nxnALxcJyzVwNpKL+9u8EZYy98qX6i+4gE/2J6cbpekcB0ZXDn/XQxoNUUb6/djT
# /wllVyG+vIHkdq71PzbH5rYxdcAwggeeMIIFhqADAgECAhMzAAAAB4ejNKN7pY4c
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
# 4WrxSK5nMYIakTCCGo0CAQEwcTBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZp
# ZWQgQ1MgRU9DIENBIDA0AhMzAAFKynTD32l/wWVjAAAAAUrKMA0GCWCGSAFlAwQC
# AQUAoF4wEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwLwYJKoZIhvcNAQkEMSIEICTk2bloYfnj7WYHfNRH+1fAEg2Fbq/W4kyI4eWY
# eARvMA0GCSqGSIb3DQEBAQUABIIBgHAeYD81SKpk9B7OhLnnfE45d7ktFHXZRrmG
# lFSn9CkSkIIPsw2yHIi7i3DSimFzS9XgtnvTZs8o+xIqaw1AlCZi0+58EuEURfEq
# Yc32dSwxUnP810UsJ9GmgPH8lO7mXgjtN84nbTa0TTsG+dz4hdelr7tWvXENIEou
# mRRkdKIIp64OMLjqYFBG9CeLi3uN0NpgcWgDivKjuIoDt3RP+W7Rsh+GLIhKDmeS
# dKtqS4nWPWLe/jh4gZV0SXo7V1ke//VW4PQ2RWqkZfygJ8swUXIfuNZXdeWKKwxO
# Tt4O1NFtRM4GtOmk3ebxIf92iL7Hdf2dLhspxNHe0y8wI3njW3HTeSfS7hPGayUf
# GDoIC6x8/9YB8owghDxoQGjX95se/ONyoU0uBDsq3msAa28u2mjg5w6JfljL3SQL
# +icjkxIfSj9kPefPLj0BnYnovrqsHYMJ/rwdLekjJ1dfAHedC9jEFpAVGjLhc2po
# UqDjSL0IoFRpTGs0M+o12Law3781RaGCGBEwghgNBgorBgEEAYI3AwMBMYIX/TCC
# F/kGCSqGSIb3DQEHAqCCF+owghfmAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFiBgsq
# hkiG9w0BCRABBKCCAVEEggFNMIIBSQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCt4QngnDwaq7dahwHnPDWuQ6laPjBkN2kYwIg25n6xswIGaeiBPwuD
# GBMyMDI2MDUyMzAzMDg0MC43ODRaMASAAgH0oIHhpIHeMIHbMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046N0QwMC0w
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
# qIGEjolCK9F6nK9ZyX4lhthsGHumaABdWzCCB5cwggV/oAMCAQICEzMAAABV2d1p
# Jij5+OIAAAAAAFUwDQYJKoZIhvcNAQEMBQAwYTELMAkGA1UEBhMCVVMxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1
# YmxpYyBSU0EgVGltZXN0YW1waW5nIENBIDIwMjAwHhcNMjUxMDIzMjA0NjQ5WhcN
# MjYxMDIyMjA0NjQ5WjCB2zELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUG
# A1UECxMeblNoaWVsZCBUU1MgRVNOOjdEMDAtMDVFMC1EOTQ3MTUwMwYDVQQDEyxN
# aWNyb3NvZnQgUHVibGljIFJTQSBUaW1lIFN0YW1waW5nIEF1dGhvcml0eTCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL25H5IeWUiz9DAlFmn2sPymaFWb
# vYkMfK+ScIWb3a1IvOlIwghUDjY0Gp6yMRhfYURiGS0GedIB6ywvuH6VBCX3+bdO
# FcAclgtv21jrpOjZmk4fSaT2Q3BszUfeUJa8o3xI7ZfoMY9dszTxHQAz6ZVX87fH
# GEVhQcfxW33IdPJOj/ae419qtYxT21MVmCfsTshgtWioQxmOW/vMC9/b+qgtBxSM
# f798vm3qfmhF6KCvFaHlivrM32hY16PGE3L0PFC+LM7vRxU7mTb+r76CeybvqOWk
# 4+dbKYftPhV1t/E5S/6wwXeYmu/Y7JC7Tnh2w45G5Y4pcM3oHMb/YuPRdOWa0v+R
# C2QgmNVWqjuxDiylWscXQDuaMtb29AcdGUVV9ZsRY2M2sthAtOdZOshiR5ufMtaH
# tiCkWv0jNfgUxrHurxzYuUNneWZ6EfQDgFAw8CSCKkSOK2c9jEop4ddVq10xvbqx
# drqMneVXvvIcXrPQAXj9j2ECpV2EwMb3Wnmpw00P78JpzPsk3Fs61ZvOGd/F1RcO
# Bu6f2TWdp7HL7+rq7tgHr13MldbfIWu4lpoYYE1gTQa1Yrg5XN4j7zs9klT2z3qo
# cmPzV8DWQgIHNh+aTs7bujMEMQyI7Xt1zPxZCgcR6H0tmmzU/9BxvsWbRalCQ2sY
# GyWupTdc4e7KY7kPAgMBAAGjggHLMIIBxzAdBgNVHQ4EFgQUVgRfEG3cCAPwyL+p
# yRbKwdesZbYwHwYDVR0jBBgwFoAUa2koOjUvSGNAz3vYr0npPtk92yEwbAYDVR0f
# BGUwYzBhoF+gXYZbaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwv
# TWljcm9zb2Z0JTIwUHVibGljJTIwUlNBJTIwVGltZXN0YW1waW5nJTIwQ0ElMjAy
# MDIwLmNybDB5BggrBgEFBQcBAQRtMGswaQYIKwYBBQUHMAKGXWh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwUHVibGljJTIw
# UlNBJTIwVGltZXN0YW1waW5nJTIwQ0ElMjAyMDIwLmNydDAMBgNVHRMBAf8EAjAA
# MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDBmBgNVHSAE
# XzBdMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wCAYGZ4EMAQQC
# MA0GCSqGSIb3DQEBDAUAA4ICAQBSHuGSVHvalCnFnlsqXIQefH1xP2SFr9g+Vz+f
# 5P7QeywjfQb5jUlSmd1XnJUDPe/MHxL7r3TEElL+mNtG6CDPAytStSFPXD9tTBtB
# MYh8Wqo64pH9qm361yIqeBH979mzWCkMQsTd0nM6dUl9B+7qiti+ToXwxIl39eYq
# LuYYfhD2mqqePXMzUKSQzkf73yYIVHP6nLJQz4aAmaWcfG9jg78sBkDV8KpW7Jgk
# tuLhphJEN1B+SVHjenPdcmrFXIUu/K4jK5ukfWaQIjuaXzSjBlNjC5tQN6adPfA3
# GxUwHPeR4ekL5If/9vBf13tmzBW+gy+0sNGTveb9IL9GU8iX8UvywsX62nhCCPRU
# hTigDBKdczRUrNrntBhowbfchBDFML8avRMRc9Gmc2JvIryX336SFQ51//q1UU2H
# MSJEMhWLJSIWJVhfUowsOa+PampIzETYfFvTu2mqKJUlWZXkGYxrdCvCczJcqeoa
# dpW1ul6kcdnDh228SQ8ZhDc6IRlM4iNd5SNoNgX+aom3wuGyjUaSaPZWxPB1G2NK
# iYhPLt0lPHg0Gskj1zhISY8UQkMMDr3o2JgRuT+wnJEDQUp55ddvhSkSoD6I9DL/
# s+TjIY/c9jLaW5xywJHqdKHUApRMsghv7kebSua1upmR+TquelFktDSOjVdSRkuy
# a4uoxTGCB0Mwggc/AgEBMHgwYTELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1YmxpYyBSU0Eg
# VGltZXN0YW1waW5nIENBIDIwMjACEzMAAABV2d1pJij5+OIAAAAAAFUwDQYJYIZI
# AWUDBAIBBQCgggScMBEGCyqGSIb3DQEJEAIPMQIFADAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MDUyMzAzMDg0MFowLwYJKoZI
# hvcNAQkEMSIEIPQHTZJ2ipuLcFaXnBqzGpla4WE7gSFKe1ZoqVIJkGNbMIG5Bgsq
# hkiG9w0BCRACLzGBqTCBpjCBozCBoAQg2Lk8l2SGYru/ff7+D2qrJnkswcYdK6pG
# Ku7GGGr4/s0wfDBlpGMwYTELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1YmxpYyBSU0EgVGlt
# ZXN0YW1waW5nIENBIDIwMjACEzMAAABV2d1pJij5+OIAAAAAAFUwggNeBgsqhkiG
# 9w0BCRACEjGCA00wggNJoYIDRTCCA0EwggIpAgEBMIIBCaGB4aSB3jCB2zELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9z
# b2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNO
# OjdEMDAtMDVFMC1EOTQ3MTUwMwYDVQQDEyxNaWNyb3NvZnQgUHVibGljIFJTQSBU
# aW1lIFN0YW1waW5nIEF1dGhvcml0eaIjCgEBMAcGBSsOAwIaAxUAHTtUAYJlv7bg
# WVeRBo4X7FeHDeqgZzBlpGMwYTELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1YmxpYyBSU0Eg
# VGltZXN0YW1waW5nIENBIDIwMjAwDQYJKoZIhvcNAQELBQACBQDtuzUwMCIYDzIw
# MjYwNTIyMjAwNDAwWhgPMjAyNjA1MjMyMDA0MDBaMHQwOgYKKwYBBAGEWQoEATEs
# MCowCgIFAO27NTACAQAwBwIBAAICGHcwBwIBAAICErgwCgIFAO28hrACAQAwNgYK
# KwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQAC
# AwGGoDANBgkqhkiG9w0BAQsFAAOCAQEAbBmjkAE+36J5CJp24JpY0PU8rfLXYOs+
# EYEqvNojdE9645WYDnpz3n6YQz03isy2cdwkk4Bto+7UcFVFDrJQzoSrSyt7rruY
# +Qb39SefpkZYfO6Wy48XKKVXnKtfqYjWgI0MBZquogiS0PDDkWq5YgVYYtLwGVRr
# 3v4gOE/nH1wRzX9nxTM187hVtEdJPFYPuXrK+nBvdG9jz4xGdZlBciI2I3dP5Tbv
# wBa9AaxVDa7alGjaWmPu7JzzAE4paORz0k3nerXs6z/SVz5imgGMO/L8y7xXx+f0
# SbeXOCQCHmxunOI0RbzXag/80quDzrZ/buP9/P5roqEPWcn0tX5mCjANBgkqhkiG
# 9w0BAQEFAASCAgBbt9tfQdsVO47EXuLtBuJ4KaJ3OHf1Xjy8SiCVfheF7Ik+BuxD
# GzxnOpqlBZRnO0qnC35k03Ct8nEambzNVLKv+cdLUS0faQ0ocugaRE5dttfVNIiP
# EMaGTaCAGL2oDKXN1GHXOkD6/N+nNny+Lucf7zx7pZE3Z6wHJ5DoiLvyMOkAf2tu
# Oi+vwuC288iqZlrJeoi25N/+vYR+APETKQzUGcj9lprh3TuzPZKwt8FAj0cEXLGl
# NCk9vOc+OlJiqt1v+9v0p+YcSqB7nrLIIPeLykKO4/MZBagVcW2OSmZn3X+oVGmx
# vlj2lGeMPbC66BR2voumjxlM+9sEWcrtuDOE+2/wW/1p81BQ7WNHx8Ff8dj58A4p
# TSxnCggK4Slk+sXeqbMnt3wq1oF9mEeRGs3L+pK0t7NgvJ7pywcSGoDN3r+Fer0S
# 9Tbqxzi9nBkCoWWl9o+WEwfm9PgrQeAvjVIbMQGMzvjpm0DVfYLKPXVKqpCIJCNJ
# 2soNvsHmhVtUiQfVlM+RzudpXEW8R3KfkZJfZ6REl6PkSuAZeTajwgAIbDcRZEit
# tSdT02qhAHGCsw+rpX5ah2ZAiE13Qb+LeYUuFmbKS4oY+mgkKEiRK1Ree99gqY7S
# UZvS4F9nwuIHKTk5xfEHvabnm659u8wkgljVWhIx+bpIo7iHpdj3sZztDg==
# SIG # End signature block
