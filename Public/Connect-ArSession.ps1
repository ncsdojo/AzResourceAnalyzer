function Connect-ArSession {
    <#
    .SYNOPSIS
        Authenticates to Azure via browser sign-in.
    .PARAMETER TenantId
        Tenant domain or GUID.
    .PARAMETER AuthTimeout
        Browser sign-in timeout in seconds. Default: 120.
    .EXAMPLE
        Connect-ArSession -TenantId 'contoso.onmicrosoft.com'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$TenantId,

        [int]$AuthTimeout = 120
    )

    if ($script:_ArSession) { Write-Verbose 'Disposing previous session'; Remove-ArTokenStore $script:_ArSession }

    $session = New-ArTokenStore -TenantId $TenantId
    $script:_ArSession  = $null
    $script:_ArTenantId = $null

    try {
        Write-Information "`n  NCS Dojo — Connecting to $TenantId" -InformationAction Continue

        Write-Information '  Acquiring ARM token...' -InformationAction Continue
        Invoke-ArInteractiveAuth -Store $session -Scope $script:_ArScopes.Arm -ClientId $script:_ArClients.Arm -TimeoutSeconds $AuthTimeout

        Write-Information '  Acquiring Graph token...' -InformationAction Continue
        Invoke-ArInteractiveAuth -Store $session -Scope $script:_ArScopes.Graph -ClientId $script:_ArClients.Graph -TimeoutSeconds $AuthTimeout

        Write-Information '  Acquiring Vault token...' -InformationAction Continue
        Invoke-ArInteractiveAuth -Store $session -Scope $script:_ArScopes.Vault -ClientId $script:_ArClients.Arm -TimeoutSeconds $AuthTimeout
    }
    catch {
        Remove-ArTokenStore $session
        Write-Warning "$($_.Exception.Message) Run Connect-ArSession to try again."
        return
    }

    # Permission checks
    Write-Information '  Checking permissions...' -InformationAction Continue
    $perms = Test-ArPermissions -Store $session

    $user = if ($perms.User) { $perms.User.userPrincipalName } else { '(unknown)' }
    $subCount = $perms.Subscriptions.Count
    $roles = if ($perms.Roles.Count -gt 0) { $perms.Roles -join ', ' } else { '(none)' }
    $readerCount = $perms.SubsWithReader.Count
    $mgCount = $perms.ManagementGroups.Count

    # License checks
    Write-Information '  Checking licenses...' -InformationAction Continue
    $lic = Get-ArTenantLicenses -Store $session

    # Display
    Write-Information '' -InformationAction Continue
    Write-Host "  User:           $user" -ForegroundColor Gray
    Write-Host "  Roles:          $roles" -ForegroundColor Gray
    Write-Host "  Mgmt groups:    $mgCount" -ForegroundColor $(if ($mgCount -gt 0) { 'Gray' } else { 'Yellow' })
    Write-Host "  Subscriptions:  $subCount" -ForegroundColor $(if ($subCount -gt 0) { 'Gray' } else { 'Red' })
    Write-Host "  Reader access:  $readerCount of $subCount subscription(s)" -ForegroundColor $(if ($readerCount -eq $subCount -and $subCount -gt 0) { 'Gray' } elseif ($readerCount -gt 0) { 'Yellow' } else { 'Red' })
    Write-Host "  Graph access:   $($perms.GraphAccess)" -ForegroundColor $(if ($perms.GraphAccess) { 'Gray' } else { 'Red' })
    Write-Host "  Vault access:   $($perms.VaultAccess)" -ForegroundColor $(if ($perms.VaultAccess) { 'Gray' } else { 'Yellow' })

    if ($lic.HasP2) { Write-Host "  License:        Entra ID P2" -ForegroundColor Gray }
    elseif ($lic.HasP1) { Write-Host "  License:        Entra ID P1" -ForegroundColor Gray }
    else { Write-Host "  License:        No P1/P2 detected" -ForegroundColor Red }

    Write-Host '' -ForegroundColor Gray

    # Gate: block if minimum requirements not met
    $blocked = $false

    if ($subCount -eq 0) {
        Write-Warning "No accessible subscriptions. The account needs Reader role on at least one subscription."
        $blocked = $true
    }

    if ($subCount -gt 0 -and $readerCount -lt $subCount) {
        Write-Warning "$($subCount - $readerCount) of $subCount subscription(s) missing Reader role. Assign Reader on all target subscriptions and run Connect-ArSession again."
        $blocked = $true
    }

    if ($mgCount -eq 0) {
        Write-Warning "No management group access. The account cannot see the management group hierarchy."
    }

    if (-not $perms.GraphAccess) {
        Write-Warning "Graph access denied. The account needs User.Read.All, Policy.Read.All, Directory.Read.All, UserAuthenticationMethod.Read.All, AuditLog.Read.All. Ask a tenant admin to grant consent."
        $blocked = $true
    }

    if (-not $lic.HasP1) {
        Write-Warning "No Entra ID P1 or P2 license. Conditional Access policies and MFA registration data require at least P1."
        $blocked = $true
    }

    if ($blocked) {
        Remove-ArTokenStore $session
        Write-Host ''
        Write-Warning "Session not established. Resolve the issues above and run Connect-ArSession again."
        return
    }

    # Vault is optional — warn but don't block
    if (-not $perms.VaultAccess) {
        Write-Warning "Vault access not available. Key Vault data plane collectors will be skipped."
    }

    # All gates passed — store session
    $session['Permissions'] = $perms
    $session['Licenses'] = $lic
    $session['User'] = $user

    $script:_ArSession  = $session
    $script:_ArTenantId = $TenantId

    Write-Information "  Connected.`n" -InformationAction Continue
}


# SIG # Begin signature block
# MII9GQYJKoZIhvcNAQcCoII9CjCCPQYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBhZ/DkvE5NCjPv
# xJEcBkYK+RtPsi71DrFAzeVhzZr7fKCCIdwwggXMMIIDtKADAgECAhBUmNLR1FsZ
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
# 4WrxSK5nMYIakzCCGo8CAQEwcTBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZp
# ZWQgQ1MgRU9DIENBIDAzAhMzAAFjK/PtydGY9KIdAAAAAWMrMA0GCWCGSAFlAwQC
# AQUAoF4wEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwLwYJKoZIhvcNAQkEMSIEIF2Idks7vu1I3QL6slg2fIYh26fmjCdUfD7n7+Ms
# 1JZjMA0GCSqGSIb3DQEBAQUABIIBgJE8bQEZATulRWtVyFPMxBB7itCQf4SRRG+B
# T8Aq/emG3V70AZdo+1TbVDlVJ8chkrU16uy7hYbY3kOX6AhJxQzz4C9tK+yJ0Yk8
# zo5m/zuUlu+gwtY8qDkzsUqhpHdZuOaLaBb+twN44SNPwUh79000ZC/DPb2XOfSa
# l9YtEsWrvOV7Z4MhRWQOrZWkIGAojEX12negIoGEu8SOmW9WOwkEhsovfeEwxu78
# IGifuETLuWzJAk0JUKF6hfS/yeB+NtUdXIacM0BgeO6J7XuD/b0XLGTQmUaW2F9b
# FRDoGvXQpvnzCTU/em8ArfBpH5GGmgTjt/eV4OuyxvAVAL4/cBnjFRC3tu8lFHK2
# loAeOKvwsprAOXkoihdx4wFBL5mEen1JPp9HbscZ+5mLK6aeR6rkhaU9jzSNE8ZX
# iyjmEy2L9sJi8tLBf6pf9Uv3F88bxSqa0WA4IQRCGfGxo465DHxMe14WQUadkRdX
# oUgrd0pGF/IYrS9RLzzKvJwc3JVKjKGCGBMwghgPBgorBgEEAYI3AwMBMYIX/zCC
# F/sGCSqGSIb3DQEHAqCCF+wwghfoAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFhBgsq
# hkiG9w0BCRABBKCCAVAEggFMMIIBSAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCgdM9b7pzX+8ymjve3FMLjbr4L9TpQNnfLOSTElIiVugIGaeiBRQr2
# GBIyMDI2MDUyNTIzMTIwMS4xNVowBIACAfSggeGkgd4wgdsxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo3RDAwLTA1
# RTAtRDk0NzE1MDMGA1UEAxMsTWljcm9zb2Z0IFB1YmxpYyBSU0EgVGltZSBTdGFt
# cGluZyBBdXRob3JpdHmggg8hMIIHgjCCBWqgAwIBAgITMwAAAAXlzw//Zi7JhwAA
# AAAABTANBgkqhkiG9w0BAQwFADB3MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMUgwRgYDVQQDEz9NaWNyb3NvZnQgSWRlbnRpdHkg
# VmVyaWZpY2F0aW9uIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMjAwHhcN
# MjAxMTE5MjAzMjMxWhcNMzUxMTE5MjA0MjMxWjBhMQswCQYDVQQGEwJVUzEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQg
# UHVibGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAJ5851Jj/eDFnwV9Y7UGIqMcHtfnlzPREwW9ZUZHd5HB
# XXBvf7KrQ5cMSqFSHGqg2/qJhYqOQxwuEQXG8kB41wsDJP5d0zmLYKAY8Zxv3lYk
# uLDsfMuIEqvGYOPURAH+Ybl4SJEESnt0MbPEoKdNihwM5xGv0rGofJ1qOYSTNcc5
# 5EbBT7uq3wx3mXhtVmtcCEr5ZKTkKKE1CxZvNPWdGWJUPC6e4uRfWHIhZcgCsJ+s
# ozf5EeH5KrlFnxpjKKTavwfFP6XaGZGWUG8TZaiTogRoAlqcevbiqioUz1Yt4FRK
# 53P6ovnUfANjIgM9JDdJ4e0qiDRm5sOTiEQtBLGd9Vhd1MadxoGcHrRCsS5rO9yh
# v2fjJHrmlQ0EIXmp4DhDBieKUGR+eZ4CNE3ctW4uvSDQVeSp9h1SaPV8UWEfyTxg
# GjOsRpeexIveR1MPTVf7gt8hY64XNPO6iyUGsEgt8c2PxF87E+CO7A28TpjNq5eL
# iiunhKbq0XbjkNoU5JhtYUrlmAbpxRjb9tSreDdtACpm3rkpxp7AQndnI0Shu/fk
# 1/rE3oWsDqMX3jjv40e8KN5YsJBnczyWB4JyeeFMW3JBfdeAKhzohFe8U5w9Wuvc
# P1E8cIxLoKSDzCCBOu0hWdjzKNu8Y5SwB1lt5dQhABYyzR3dxEO/T1K/BVF3rV69
# AgMBAAGjggIbMIICFzAOBgNVHQ8BAf8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAw
# HQYDVR0OBBYEFGtpKDo1L0hjQM972K9J6T7ZPdshMFQGA1UdIARNMEswSQYEVR0g
# ADBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYB
# BAGCNxQCBAweCgBTAHUAYgBDAEEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAW
# gBTIftJqhSobyhmYBAcnz1AQT2ioojCBhAYDVR0fBH0wezB5oHegdYZzaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwSWRlbnRp
# dHklMjBWZXJpZmljYXRpb24lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3Jp
# dHklMjAyMDIwLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwgYEGCCsGAQUFBzAChnVo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUy
# MElkZW50aXR5JTIwVmVyaWZpY2F0aW9uJTIwUm9vdCUyMENlcnRpZmljYXRlJTIw
# QXV0aG9yaXR5JTIwMjAyMC5jcnQwDQYJKoZIhvcNAQEMBQADggIBAF+Idsd+bbVa
# FXXnTHho+k7h2ESZJRWluLE0Oa/pO+4ge/XEizXvhs0Y7+KVYyb4nHlugBesnFqB
# GEdC2IWmtKMyS1OWIviwpnK3aL5JedwzbeBF7POyg6IGG/XhhJ3UqWeWTO+Czb1c
# 2NP5zyEh89F72u9UIw+IfvM9lzDmc2O2END7MPnrcjWdQnrLn1Ntday7JSyrDvBd
# mgbNnCKNZPmhzoa8PccOiQljjTW6GePe5sGFuRHzdFt8y+bN2neF7Zu8hTO1I64X
# NGqst8S+w+RUdie8fXC1jKu3m9KGIqF4aldrYBamyh3g4nJPj/LR2CBaLyD+2BuG
# ZCVmoNR/dSpRCxlot0i79dKOChmoONqbMI8m04uLaEHAv4qwKHQ1vBzbV/nG89LD
# KbRSSvijmwJwxRxLLpMQ/u4xXxFfR4f/gksSkbJp7oqLwliDm/h+w0aJ/U5ccnYh
# Yb7vPKNMN+SZDWycU5ODIRfyoGl59BsXR/HpRGtiJquOYGmvA/pk5vC1lcnbeMrc
# WD/26ozePQ/TWfNXKBOmkFpvPE8CH+EeGGWzqTCjdAsno2jzTeNSxlx3glDGJgcd
# z5D/AAxw9Sdgq/+rY7jjgs7X6fqPTXPmaCAJKVHAP19oEjJIBwD1LyHbaEgBxFCo
# gYSOiUIr0Xqcr1nJfiWG2GwYe6ZoAF1bMIIHlzCCBX+gAwIBAgITMwAAAFXZ3Wkm
# KPn44gAAAAAAVTANBgkqhkiG9w0BAQwFADBhMQswCQYDVQQGEwJVUzEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVi
# bGljIFJTQSBUaW1lc3RhbXBpbmcgQ0EgMjAyMDAeFw0yNTEwMjMyMDQ2NDlaFw0y
# NjEwMjIyMDQ2NDlaMIHbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYD
# VQQLEx5uU2hpZWxkIFRTUyBFU046N0QwMC0wNUUwLUQ5NDcxNTAzBgNVBAMTLE1p
# Y3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3RhbXBpbmcgQXV0aG9yaXR5MIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvbkfkh5ZSLP0MCUWafaw/KZoVZu9
# iQx8r5JwhZvdrUi86UjCCFQONjQanrIxGF9hRGIZLQZ50gHrLC+4fpUEJff5t04V
# wByWC2/bWOuk6NmaTh9JpPZDcGzNR95QlryjfEjtl+gxj12zNPEdADPplVfzt8cY
# RWFBx/Fbfch08k6P9p7jX2q1jFPbUxWYJ+xOyGC1aKhDGY5b+8wL39v6qC0HFIx/
# v3y+bep+aEXooK8VoeWK+szfaFjXo8YTcvQ8UL4szu9HFTuZNv6vvoJ7Ju+o5aTj
# 51sph+0+FXW38TlL/rDBd5ia79jskLtOeHbDjkbljilwzegcxv9i49F05ZrS/5EL
# ZCCY1VaqO7EOLKVaxxdAO5oy1vb0Bx0ZRVX1mxFjYzay2EC051k6yGJHm58y1oe2
# IKRa/SM1+BTGse6vHNi5Q2d5ZnoR9AOAUDDwJIIqRI4rZz2MSinh11WrXTG9urF2
# uoyd5Ve+8hxes9ABeP2PYQKlXYTAxvdaeanDTQ/vwmnM+yTcWzrVm84Z38XVFw4G
# 7p/ZNZ2nscvv6uru2AevXcyV1t8ha7iWmhhgTWBNBrViuDlc3iPvOz2SVPbPeqhy
# Y/NXwNZCAgc2H5pOztu6MwQxDIjte3XM/FkKBxHofS2abNT/0HG+xZtFqUJDaxgb
# Ja6lN1zh7spjuQ8CAwEAAaOCAcswggHHMB0GA1UdDgQWBBRWBF8QbdwIA/DIv6nJ
# FsrB16xltjAfBgNVHSMEGDAWgBRraSg6NS9IY0DPe9ivSek+2T3bITBsBgNVHR8E
# ZTBjMGGgX6BdhltodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9N
# aWNyb3NvZnQlMjBQdWJsaWMlMjBSU0ElMjBUaW1lc3RhbXBpbmclMjBDQSUyMDIw
# MjAuY3JsMHkGCCsGAQUFBwEBBG0wazBpBggrBgEFBQcwAoZdaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBQdWJsaWMlMjBS
# U0ElMjBUaW1lc3RhbXBpbmclMjBDQSUyMDIwMjAuY3J0MAwGA1UdEwEB/wQCMAAw
# FgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMGYGA1UdIARf
# MF0wUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTAIBgZngQwBBAIw
# DQYJKoZIhvcNAQEMBQADggIBAFIe4ZJUe9qUKcWeWypchB58fXE/ZIWv2D5XP5/k
# /tB7LCN9BvmNSVKZ3VeclQM978wfEvuvdMQSUv6Y20boIM8DK1K1IU9cP21MG0Ex
# iHxaqjrikf2qbfrXIip4Ef3v2bNYKQxCxN3Sczp1SX0H7uqK2L5OhfDEiXf15iou
# 5hh+EPaaqp49czNQpJDOR/vfJghUc/qcslDPhoCZpZx8b2ODvywGQNXwqlbsmCS2
# 4uGmEkQ3UH5JUeN6c91yasVchS78riMrm6R9ZpAiO5pfNKMGU2MLm1A3pp098Dcb
# FTAc95Hh6Qvkh//28F/Xe2bMFb6DL7Sw0ZO95v0gv0ZTyJfxS/LCxfraeEII9FSF
# OKAMEp1zNFSs2ue0GGjBt9yEEMUwvxq9ExFz0aZzYm8ivJfffpIVDnX/+rVRTYcx
# IkQyFYslIhYlWF9SjCw5r49qakjMRNh8W9O7aaoolSVZleQZjGt0K8JzMlyp6hp2
# lbW6XqRx2cOHbbxJDxmENzohGUziI13lI2g2Bf5qibfC4bKNRpJo9lbE8HUbY0qJ
# iE8u3SU8eDQaySPXOEhJjxRCQwwOvejYmBG5P7CckQNBSnnl12+FKRKgPoj0Mv+z
# 5OMhj9z2MtpbnHLAkep0odQClEyyCG/uR5tK5rW6mZH5Oq56UWS0NI6NV1JGS7Jr
# i6jFMYIHRjCCB0ICAQEweDBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBU
# aW1lc3RhbXBpbmcgQ0EgMjAyMAITMwAAAFXZ3WkmKPn44gAAAAAAVTANBglghkgB
# ZQMEAgEFAKCCBJ8wEQYLKoZIhvcNAQkQAg8xAgUAMBoGCSqGSIb3DQEJAzENBgsq
# hkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjYwNTI1MjMxMjAxWjAvBgkqhkiG
# 9w0BCQQxIgQgJ5D1J3krj9COM0UWCsc3NgKnPaD6Kz1vQnprkK0X3cgwgbkGCyqG
# SIb3DQEJEAIvMYGpMIGmMIGjMIGgBCDYuTyXZIZiu799/v4PaqsmeSzBxh0rqkYq
# 7sYYavj+zTB8MGWkYzBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1l
# c3RhbXBpbmcgQ0EgMjAyMAITMwAAAFXZ3WkmKPn44gAAAAAAVTCCA2EGCyqGSIb3
# DQEJEAISMYIDUDCCA0yhggNIMIIDRDCCAiwCAQEwggEJoYHhpIHeMIHbMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3Nv
# ZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046
# N0QwMC0wNUUwLUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRp
# bWUgU3RhbXBpbmcgQXV0aG9yaXR5oiMKAQEwBwYFKw4DAhoDFQAdO1QBgmW/tuBZ
# V5EGjhfsV4cN6qBnMGWkYzBhMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUHVibGljIFJTQSBU
# aW1lc3RhbXBpbmcgQ0EgMjAyMDANBgkqhkiG9w0BAQsFAAIFAO2/Ka8wIhgPMjAy
# NjA1MjUyMDAzNTlaGA8yMDI2MDUyNjIwMDM1OVowdzA9BgorBgEEAYRZCgQBMS8w
# LTAKAgUA7b8prwIBADAKAgEAAgIZwQIB/zAHAgEAAgISqjAKAgUA7cB7LwIBADA2
# BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIB
# AAIDAYagMA0GCSqGSIb3DQEBCwUAA4IBAQAIszmNe5k8Olj7vWvfOeafnJXwNebs
# 7GYt5g+V14r5WlEzMsiaEB6AY9hb7hPleBxtDTfXI8yndhPFKhtX4JQT0Hy3A8ld
# 4ThATR6VHd+moiteUQUeQfDsAIKy7CweZGgGRKYbJvgUwSynUIO6wygBe6lP9Oku
# RDILAIYiHuKrx4Gq2pA5Rd1GH8iehHvt5Kcoj1aUGr3ZwumJWzmyDoQXB7EvIjnH
# /IBY38HY/K1cIbvUspGPSQYlBXCxC41nH6ZekGIe3/p7E0TM0Qdh44ThWJhkgaYS
# v2Az46RFe0fNUGr7mnH8ZriiIEan7Fye8ns1J6DpM68Csk1SGiwp+QH3MA0GCSqG
# SIb3DQEBAQUABIICAKkiBrLHIZkhrif7cAVG0Vq/tyauqxxwOZZ/bO62IRH1QDKx
# Nep3d4PcRTgFmKr0Wn1GHXygoZ7IAHccCyT4dJX6w912yL8fBlDC9Tpoe64VHn0k
# Ih+r2WHMHbT18W2wn/A7hIX9Fyts328BvABs8ZEUDcPhakS97PNLw2pAYx9NeO/f
# ilYo47y+unxPCzztfEBhs/qegxPIfk5uNQwspHvzqbNKUIiZP9N9LTUxn85DvwCx
# P9nfgM85w7P4V9+Jp2YXnQ4BYoa9KBi/GRwT0DgfeO6w5OFbR1ZdO5VUB1ojBFgx
# UdUFMuhfIMJgFc0Q0W7ZlR52JY/Lz+T4JpN1OeIEoILxtbibdxgCW2OPfsl7B6Mo
# OGvgFoYL6k2282Ly+g9pqK0z38Bjof66zIzqpOdIs180+oUZpR4dv8OUfbyCp5u0
# zjrKuY4kEjt5ddvtWtXjFYKAgA0baGZAqzvLVFNugHTlimfCgllqm8zV7xWO9KHj
# OGBjRO6ryHpa35bFw0kcERqG/hBtrBF3FI8CUrRVTxijoIDxO+Hd84OYf1lp9qCG
# ckF2rxJS8UztHHqN4QntKQC5+GRfkoViGxnlRKr1R1S9OEq0r7BVmHJrHrBmeJk2
# 6gBT04J4NjYd0F4K87JXge3U/pFY0UfnITetj3EpRO47QlTcZS+62rbsL2gg
# SIG # End signature block
