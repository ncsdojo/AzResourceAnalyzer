# Environment, permission, and license checks — Copyright (c) NCS Dojo. All Rights Reserved.

function Test-ArConstrainedLanguage {
    if ($ExecutionContext.SessionState.LanguageMode -eq 'ConstrainedLanguage') {
        Write-Warning "PowerShell is running in Constrained Language Mode."
        Write-Warning "Some features may be limited. If the module fails to load, deploy it to a WDAC-trusted path or sign all .ps1 files."
        return $true
    }
    return $false
}

function Test-ArPermissions {
    param([hashtable]$Store)

    $results = @{
        User           = $null
        Subscriptions  = @()
        GraphAccess    = $false
        VaultAccess    = $false
        Roles          = @()
        Warnings       = @()
    }

    # Identify signed-in user
    try {
        $graphToken = Get-ArMarshaledToken -Store $Store -Scope $script:_ArScopes.Graph
        $headers = @{ Authorization = "Bearer $graphToken" }
        $me = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/me?$select=userPrincipalName,displayName' -Headers $headers -Method GET
        $results.User = $me
    }
    catch {
        $results.Warnings += 'Could not identify signed-in user.'
    }

    # Check ARM access — list subscriptions
    try {
        $armToken = Get-ArMarshaledToken -Store $Store -Scope $script:_ArScopes.Arm
        $subHeaders = @{ Authorization = "Bearer $armToken"; 'Content-Type' = 'application/json' }
        $subResp = Invoke-RestMethod -Uri 'https://management.azure.com/subscriptions?api-version=2022-12-01' -Headers $subHeaders -Method GET
        $results.Subscriptions = @($subResp.value | Where-Object { $_.state -eq 'Enabled' } | ForEach-Object {
            [PSCustomObject]@{ subscriptionId = $_.subscriptionId; displayName = $_.displayName }
        })
        if ($results.Subscriptions.Count -eq 0) {
            $results.Warnings += 'No accessible subscriptions. Assign Reader role on target subscriptions.'
        }
    }
    catch {
        $results.Warnings += "ARM access failed: $($_.Exception.Message)"
    }

    # Check Graph access
    try {
        $graphToken = Get-ArMarshaledToken -Store $Store -Scope $script:_ArScopes.Graph
        $headers = @{ Authorization = "Bearer $graphToken" }
        $null = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/organization?$top=1' -Headers $headers -Method GET
        $results.GraphAccess = $true
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '403|Forbidden|Insufficient') {
            $results.Warnings += 'Graph permissions insufficient. Need User.Read.All, Policy.Read.All, Directory.Read.All, UserAuthenticationMethod.Read.All, AuditLog.Read.All.'
        } else {
            $results.Warnings += "Graph access failed: $msg"
        }
    }

    # Check directory roles
    if ($results.GraphAccess -and $results.User) {
        try {
            $headers = @{ Authorization = "Bearer $graphToken" }
            $rolesResp = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/me/memberOf/microsoft.graph.directoryRole?$select=displayName,roleTemplateId' -Headers $headers -Method GET
            if ($rolesResp.PSObject.Properties['value']) {
                $results.Roles = @($rolesResp.value | ForEach-Object { $_.displayName })
            }
        }
        catch {}
    }

    # Check Vault token validity
    try {
        $null = Get-ArMarshaledToken -Store $Store -Scope $script:_ArScopes.Vault
        $results.VaultAccess = $true
    }
    catch {
        $results.Warnings += 'Vault token not available. Key Vault data plane collectors will be skipped.'
    }

    return $results
}

function Get-ArTenantLicenses {
    param([hashtable]$Store)

    $licenses = @{
        Plans    = @()
        HasP1    = $false
        HasP2    = $false
        HasE5    = $false
        Warnings = @()
    }

    try {
        $graphToken = Get-ArMarshaledToken -Store $Store -Scope $script:_ArScopes.Graph
        $headers = @{ Authorization = "Bearer $graphToken" }
        $skuResp = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuPartNumber,capabilityStatus,prepaidUnits,consumedUnits' -Headers $headers -Method GET

        if ($skuResp.PSObject.Properties['value']) {
            $licenses.Plans = @($skuResp.value | Where-Object { $_.capabilityStatus -eq 'Enabled' } | ForEach-Object {
                $_.skuPartNumber
            })

            $p2Skus = @('AAD_PREMIUM_P2','IDENTITY_THREAT_PROTECTION','EMSPREMIUM','Microsoft_Entra_ID_P2','SPE_E5')
            $p1Skus = @('AAD_PREMIUM','AAD_PREMIUM_P1','EMSPREMIUM','Microsoft_Entra_ID_P1','SPE_E3','SPE_E5')
            $e5Skus = @('SPE_E5','ENTERPRISEPREMIUM','Microsoft_365_E5')

            foreach ($plan in $licenses.Plans) {
                if ($plan -in $p2Skus) { $licenses.HasP2 = $true; $licenses.HasP1 = $true }
                if ($plan -in $p1Skus) { $licenses.HasP1 = $true }
                if ($plan -in $e5Skus) { $licenses.HasE5 = $true }
            }
        }

        if (-not $licenses.HasP1) {
            $licenses.Warnings += 'No Entra ID P1/P2 license detected. Conditional Access and MFA registration checks may return incomplete data.'
        }
    }
    catch {
        $licenses.Warnings += "Could not read tenant licenses: $($_.Exception.Message)"
    }

    return $licenses
}


# SIG # Begin signature block
# MII9GgYJKoZIhvcNAQcCoII9CzCCPQcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCS4rLN4SulMqzr
# +V9LTKJY5j/n+doVrbJajmjrnZLuBqCCIdwwggXMMIIDtKADAgECAhBUmNLR1FsZ
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
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggabMIIEg6ADAgECAhMzAAFjK/Pt
# ydGY9KIdAAAAAWMrMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDMwHhcNMjYwNTI1MTgyODExWhcNMjYwNTI4
# MTgyODExWjBfMQswCQYDVQQGEwJDQTEQMA4GA1UECBMHQWxiZXJ0YTEQMA4GA1UE
# BxMHQ2FsZ2FyeTEVMBMGA1UEChMMRGFycmVuIE1heWVzMRUwEwYDVQQDEwxEYXJy
# ZW4gTWF5ZXMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC3VRg35weQ
# YA+uwkMEDwJpHkr/wXTiS0Kd/LwVOIRQCA6VyR1iYynr6WwG6MGiBq2vjVyUvN61
# 7wNPGF2AAqKmopPXsnmkPKPAWsUHgZevXtmRnN5B8n4HjJ+12QCcKXStmmx8acGB
# Pc4MKo0jHnZfXyYhrl0jiUhkTZTQeEupu979ElMwEIJWtuYe+IfcK1Pl9AHzu5R8
# BIna+i7jnQa/O6zM9CQaUsp0O8Jbr0UWAWUbyDjp4IVQLRYM+wckN1zugT3m6YRz
# umvDWR7jRlWMPOdXEiSKB1O3oYwV18iBhldtAG8GgmC7WhU0+YR6OEdv+R4M/Yvp
# it8udxQrBAUPC2iNXEH7yyRtkZAPQGNXHWknkR/kODNn8e/eV0NjWiVkRNdpfJsT
# Ym9uM2YHevVQAtPqMk3s5S5ICWeAix3pc6cfg/3iThhSmVmEMhpt3AVpeaFqCYJm
# aN3uv29zbejvGftLN5PVoH2zuH2SZiZ04rj8SwkRAb2v08nrl/BEpWcCAwEAAaOC
# AdMwggHPMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMDoGA1UdJQQzMDEG
# CisGAQQBgjdhAQAGCCsGAQUFBwMDBhkrBgEEAYI3YYuPpXGB3qaBQNv/tAST5rkV
# MB0GA1UdDgQWBBT+539SN0UnemojGpbzi3tO4ien0TAfBgNVHSMEGDAWgBRrXqU0
# wwXFYkohWo6rc2Bi1KxjhTBnBgNVHR8EYDBeMFygWqBYhlZodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBJRCUyMFZlcmlmaWVk
# JTIwQ1MlMjBFT0MlMjBDQSUyMDAzLmNybDB0BggrBgEFBQcBAQRoMGYwZAYIKwYB
# BQUHMAKGWGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWlj
# cm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAwMy5jcnQw
# VAYDVR0gBE0wSzBJBgRVHSAAMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTANBgkqhkiG9w0B
# AQwFAAOCAgEAwraGUBaYWTbHLjmTQdQqypcgGUtbM/gUCAiRDIftJokxiWsJjJ0m
# asIGe3v7DHTQKj09rvQ5sSjnTI7/ebq1YtUEUmgnK7pZC3S8eHzUnDArSYTptqcT
# stAmRbsOT1xggmg7FvIwd/dAqRf5Ix9NB3Etdkw3bJeEVePlxqE/a3HNm+nXn0o6
# MfzhWyTJAmo1iktowb2/MQZOXmHKdOBBicIowyOACjlIPB1UNZrzUbLk/csZjjNV
# g0a1IpkCps9bMsdNzAfAvD2f/d7wecce1qvPqqlfp38CPJnj3UxcLDH72KpEq/0I
# S7Wj+57A3DzpbC/uq7lsENS0ZC3iQlBYYB/KNtlSPV73RyZU4ZcqPPLZYtR+Gtf9
# QFbBGW+fbI1EXZk00n+zu8D+EG1q8zRcm56o0XXkdZAhjN9lWe4nJ/e1ZLdEQmZK
# eMBnw1KOZiBEgBlLON4UMDxJlMTgpeXh3IWJPuAc9+QmhPQT5keKnOgpV5iuxSue
# AaAPaRw0BuHCt0UnY/MX2jVgLN/ONtf0wVGy8YrLqIy2WRCs8UYqTEDK3ajfPR5l
# LlNHyc3a32fZs8EAzCBU30MBAoHlW30ul16m08Z3mw8LuINvKbVzAL47fVQMzvSN
# ZBteFgUg3wSuINAZNBnafLc2tuyHL48uDUIDY0oS3DkNztEu/EF3n1gwggabMIIE
# g6ADAgECAhMzAAFjK/PtydGY9KIdAAAAAWMrMA0GCSqGSIb3DQEBDAUAMFoxCzAJ
# BgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNV
# BAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBFT0MgQ0EgMDMwHhcNMjYwNTI1
# MTgyODExWhcNMjYwNTI4MTgyODExWjBfMQswCQYDVQQGEwJDQTEQMA4GA1UECBMH
# QWxiZXJ0YTEQMA4GA1UEBxMHQ2FsZ2FyeTEVMBMGA1UEChMMRGFycmVuIE1heWVz
# MRUwEwYDVQQDEwxEYXJyZW4gTWF5ZXMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAw
# ggGKAoIBgQC3VRg35weQYA+uwkMEDwJpHkr/wXTiS0Kd/LwVOIRQCA6VyR1iYynr
# 6WwG6MGiBq2vjVyUvN617wNPGF2AAqKmopPXsnmkPKPAWsUHgZevXtmRnN5B8n4H
# jJ+12QCcKXStmmx8acGBPc4MKo0jHnZfXyYhrl0jiUhkTZTQeEupu979ElMwEIJW
# tuYe+IfcK1Pl9AHzu5R8BIna+i7jnQa/O6zM9CQaUsp0O8Jbr0UWAWUbyDjp4IVQ
# LRYM+wckN1zugT3m6YRzumvDWR7jRlWMPOdXEiSKB1O3oYwV18iBhldtAG8GgmC7
# WhU0+YR6OEdv+R4M/Yvpit8udxQrBAUPC2iNXEH7yyRtkZAPQGNXHWknkR/kODNn
# 8e/eV0NjWiVkRNdpfJsTYm9uM2YHevVQAtPqMk3s5S5ICWeAix3pc6cfg/3iThhS
# mVmEMhpt3AVpeaFqCYJmaN3uv29zbejvGftLN5PVoH2zuH2SZiZ04rj8SwkRAb2v
# 08nrl/BEpWcCAwEAAaOCAdMwggHPMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQD
# AgeAMDoGA1UdJQQzMDEGCisGAQQBgjdhAQAGCCsGAQUFBwMDBhkrBgEEAYI3YYuP
# pXGB3qaBQNv/tAST5rkVMB0GA1UdDgQWBBT+539SN0UnemojGpbzi3tO4ien0TAf
# BgNVHSMEGDAWgBRrXqU0wwXFYkohWo6rc2Bi1KxjhTBnBgNVHR8EYDBeMFygWqBY
# hlZodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQl
# MjBJRCUyMFZlcmlmaWVkJTIwQ1MlMjBFT0MlMjBDQSUyMDAzLmNybDB0BggrBgEF
# BQcBAQRoMGYwZAYIKwYBBQUHMAKGWGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENTJTIwRU9D
# JTIwQ0ElMjAwMy5jcnQwVAYDVR0gBE0wSzBJBgRVHSAAMEEwPwYIKwYBBQUHAgEW
# M2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5
# Lmh0bTANBgkqhkiG9w0BAQwFAAOCAgEAwraGUBaYWTbHLjmTQdQqypcgGUtbM/gU
# CAiRDIftJokxiWsJjJ0masIGe3v7DHTQKj09rvQ5sSjnTI7/ebq1YtUEUmgnK7pZ
# C3S8eHzUnDArSYTptqcTstAmRbsOT1xggmg7FvIwd/dAqRf5Ix9NB3Etdkw3bJeE
# VePlxqE/a3HNm+nXn0o6MfzhWyTJAmo1iktowb2/MQZOXmHKdOBBicIowyOACjlI
# PB1UNZrzUbLk/csZjjNVg0a1IpkCps9bMsdNzAfAvD2f/d7wecce1qvPqqlfp38C
# PJnj3UxcLDH72KpEq/0IS7Wj+57A3DzpbC/uq7lsENS0ZC3iQlBYYB/KNtlSPV73
# RyZU4ZcqPPLZYtR+Gtf9QFbBGW+fbI1EXZk00n+zu8D+EG1q8zRcm56o0XXkdZAh
# jN9lWe4nJ/e1ZLdEQmZKeMBnw1KOZiBEgBlLON4UMDxJlMTgpeXh3IWJPuAc9+Qm
# hPQT5keKnOgpV5iuxSueAaAPaRw0BuHCt0UnY/MX2jVgLN/ONtf0wVGy8YrLqIy2
# WRCs8UYqTEDK3ajfPR5lLlNHyc3a32fZs8EAzCBU30MBAoHlW30ul16m08Z3mw8L
# uINvKbVzAL47fVQMzvSNZBteFgUg3wSuINAZNBnafLc2tuyHL48uDUIDY0oS3DkN
# ztEu/EF3n1gwggcoMIIFEKADAgECAhMzAAAAFQU+bhmOkynZAAAAAAAVMA0GCSqG
# SIb3DQEBDAUAMGMxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xNDAyBgNVBAMTK01pY3Jvc29mdCBJRCBWZXJpZmllZCBDb2RlIFNp
# Z25pbmcgUENBIDIwMjEwHhcNMjYwMzI2MTgxMTI4WhcNMzEwMzI2MTgxMTI4WjBa
# MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSsw
# KQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1MgRU9DIENBIDAzMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA4PTLPQKqLw5zHj7zDnvism4QnfPp
# aJM2DkZUt5AVV7HnnG8hsAXLHp5ZuWy7TBj44iBS8wUBfoIZVVf1NvauRnHXhBAQ
# h00xoS9pKCKy3OFK5YjEXG7/ZjjLUf5e/8QJr9BceASR59XR7d+376wal5ioynxn
# +Q6cjv/oZ1e0xK3jLUtfYjvm42f/R56YNzwpNHu2Em0UxZMfexWcEVqQuLNzXqUX
# 0V0If1jAI+yZrGHlWaIYuExecltiTKyWasB3MsyWWLQ9h5Z6OWRCZHYmXBGsRzqG
# 5sDtOmdSfXNt6bPTxiIRmqtbCixAM/Q6HOay5GFhrXg67HCoQKdpCHP6GJR/SI+g
# ZDqqoFiDRJBLQvGTRtTGpPod6OuWo9IkCpncVuyGWhzuXLsqDIvirWH13iCIN7FS
# G0thC/JFLbAxnRKjagKv4rKk4tY16i3uoiqdZ4tUj3bz1vRtNwk7GBevG/8riEEc
# G3aAQl3pjDSQktHaKwkWOG9lgAMuJ4O0gDXBIKwYGX+d+fkHy1OYRs6yoyKWzGm2
# rlm+RSllCpDLD3FxZF0VjuJ6Cj5uClpRcqajqWyfyjjVUXiJcR0EXoADgcyIUQe4
# K/SA0NbHNjIDoEPsVRluKKuBw9JnwIsIsi7JGa5GkOyaGp2IwTXEfUUtumMQFW3A
# bS4rRU8wiBIOWXUCAwEAAaOCAdwwggHYMA4GA1UdDwEB/wQEAwIBhjAQBgkrBgEE
# AYI3FQEEAwIBADAdBgNVHQ4EFgQUa16lNMMFxWJKIVqOq3NgYtSsY4UwVAYDVR0g
# BE0wSzBJBgRVHSAAMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTAZBgkrBgEEAYI3FAIEDB4K
# AFMAdQBiAEMAQTASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFNlBKbAP
# D2Ns72nX9c0pnqRIajDmMHAGA1UdHwRpMGcwZaBjoGGGX2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQl
# MjBDb2RlJTIwU2lnbmluZyUyMFBDQSUyMDIwMjEuY3JsMH0GCCsGAQUFBwEBBHEw
# bzBtBggrBgEFBQcwAoZhaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBJRCUyMFZlcmlmaWVkJTIwQ29kZSUyMFNpZ25pbmcl
# MjBQQ0ElMjAyMDIxLmNydDANBgkqhkiG9w0BAQwFAAOCAgEAXW4iPM8Fy1/IJSRI
# f/ENtlDAlIVgTuOmfRT4cDkd5nZakVS5GDqJ/zHM1MK4w4cd1/fUjx+T0n5ZBqE7
# 5zvWVhzOWBVWKTuzWLgfpn1UhgBmcIhjgElpNItge75/ZxJSSZqIl8boHx+WHQbK
# 1IE7dABTV5M5qk4JPktR8W9bv9BwqhB1WT5NgP+niV2G7aUTORXM9NI4rFJfQUWY
# Enmzg1fOWwczr3qsgt39D5xwsUSTYTG/MT/7Af1SO6X9q4Xkle86lEr/L5/3yDG5
# V3mlSJaaqKvEj/QSTIxPwqFVycZ5GUETNRWu5Dfcs7b0XjocUoD4KWcf15f45MMh
# BVSUwXwad7E4HyHP6Zqr9nobWpC9gBI+/BJjj0KIcSU98Ml/j+/BgNubS6QL8490
# TDB3fM9fGbrlYvutDAMxqTgEh9S/DZa932UWZ0Dvqcsntgwr2Jh2iH3VIGCap+56
# McRlb/PfkWhE4dbYAg78DaRQkhu75eQOGpKPtn8eNPa/U1o1wuzon9SEOWScweEX
# /BrwYh2I7zJh6ZXnadRRkS3UkRVaQt/ziqWWOmryKmae/vKT/1kD/dNw3YK7wE+l
# uMTzgcVz2uLRpLDd0rqiWohWB0jcngbn5/IrHro1uCGwUmxw+AT6mxd6mfu5xvXf
# 3fxtvy8eJB/XApgX5rGXUpB5rpAwggeeMIIFhqADAgECAhMzAAAAB4ejNKN7pY4c
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
# ZWQgQ1MgRU9DIENBIDAzAhMzAAFjK/PtydGY9KIdAAAAAWMrMA0GCWCGSAFlAwQC
# AQUAoF4wEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwLwYJKoZIhvcNAQkEMSIEIA+uM7CmSLs3SQA9zewbvIF9QS7MIhGHu0vutSsp
# xGxYMA0GCSqGSIb3DQEBAQUABIIBgHto8jwbAElH2MbIOGNu+Dai8TIpDokSao9F
# ldUDEb3h+GUQbRjL2qSdvN9gydiJIzTI2e5fn+QjwDQtzpUdgSgwuv4RJDTvtejc
# TY1cDa6jqnJoNU35W9Zeh/SUte5JyZPbjRnXvkFVERJn7DxSdwlkkQ7e2fffaR9R
# kAZbPSDRWfcspaJWKAbnXsaAJdkh7iCAIJ9k+bU48PdBnPC9InDuTboEqAnyRR+v
# iiEUBuPLJIcx+rVyCOL/1v18Ut8znLSyR+Uv7MBxbq6PO+huj9fysLSpTpMU8YCp
# k42JBUwpJ/wFQ2apnocMITBcYYAD5A7p5ZVHJCjTdNeyHG6ZdBjP31NhG6lY5AQN
# WEosmUTxFSZtUnpwasdwIBIVpvTwNeNqR8NIuexe5OnbHjWgZ6rhZNtShJ5BznH2
# ielQwH2ywgFu1/7HatQ8GN1Bj2pV4ayifGAk8JBtLS1yw8Kw4LaveNCynoiQigrT
# 6QtWp+KOeQbiPDioi6wN1Y5dP4mhSaGCGBQwghgQBgorBgEEAYI3AwMBMYIYADCC
# F/wGCSqGSIb3DQEHAqCCF+0wghfpAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFiBgsq
# hkiG9w0BCRABBKCCAVEEggFNMIIBSQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCBZj9LzTJoLJANvxz/2d6cU0hidjwHkr7YPggUHHy4p5gIGagxE38Pk
# GBMyMDI2MDUyNTIyNDMzMS4xNzNaMASAAgH0oIHhpIHeMIHbMQswCQYDVQQGEwJV
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
# KoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MDUyNTIyNDMzMVowLwYJKoZI
# hvcNAQkEMSIEIHIBRKYlCdWRe7urUXri1/5zWcxTDe7nWFjdGq4VBkYyMIG5Bgsq
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
# VGltZXN0YW1waW5nIENBIDIwMjAwDQYJKoZIhvcNAQELBQACBQDtvqxPMCIYDzIw
# MjYwNTI1MTEwOTAzWhgPMjAyNjA1MjYxMTA5MDNaMHcwPQYKKwYBBAGEWQoEATEv
# MC0wCgIFAO2+rE8CAQAwCgIBAAICCt4CAf8wBwIBAAICE0swCgIFAO2//c8CAQAw
# NgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgC
# AQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEAXQ+AKomzjkJtSGyKtgux1ep32gla
# V1Il8SxvnXn8BlGXIM4V7dDDFVE+gO3/T+ynS3U03pJuQFNICngPYuvFIO0nHXRl
# lnU0m8wqzTnZio17gZWGpwxu8KvCjnSYjKEMkAv4iHXi9hoq9d+AiAQ6S/ih10O+
# lXGSFLVwHvPHxGRn2tQxy9dcRv5s7HgP0mEQhbYpBjJ2Sdap24wO4ZrQ1ZGiJxeT
# YQBSvCusTj14kzvWq+hdkL4Sax135Fkzbp739JwPHoOc38GnwWgOqtQsZAuSyh7K
# u7ZbSflkbY1GZ5bajqOFYmRceYOrU4Uos26mWQTdEMH/CCpaR7HWv9hBxjANBgkq
# hkiG9w0BAQEFAASCAgCba87wS/ZsO/LbO6W0sp2+e8VA3CLG8/YwxhMCcXv0uPIL
# 9bOFcekXjpJKv6USJiwLakOQG37hwdcxqjDyxcsulc+LUGOZPE7k5fBNkkXvmiQ6
# GFuCp+1q37E5uONM/O7zzrSlpRR1HMoeRvdMdOqczFA9adY7WHVhup2SH7WEboer
# YSEho6SWydoo6UgEiBFh8Ym8uArwrh8EspzfT9Vr4zrkeiZR9GlhwXBd1auCmX0j
# JhRq4Nz7ItdjAp6cJfF20OqvjzvDnha6RWEnogcwvPecPByQfFxp06qd525Mlpjq
# G8QvquwUzp6aClQF6vqVQ8sTWcgwsbd/rSjaTqk4TPrs1PKRclFmJK/jMd8JwRRP
# z19Z5KMoPPInCjeA5cyuBFx5jPrhzE68V9xs4TV4e3g2rYyHrgrVfl6vJK+5JVhC
# gGUeC7E22CljkzavMKZwYqoJa0Xdr6mCw5hX+G3TvkA+Srdv4QiJ2YGxYzDFkzLR
# RDMWzI8pC1gyxLw1dsZj+P2woj4Cs16LS4zrKuRPTmXIP7CliS01uue29V0q2bIr
# uW3MdBL0BC3XtiTaML4UqGS/nwW+csPc+nuqHyO8dlG/zJbrMn250Gy4A42UBP6P
# XsAJTPsFcywS8SfaDTMIPszZ/bOtJ4zj/doCa789Z7wE7Jy4t27EFcc/860a5A==
# SIG # End signature block
