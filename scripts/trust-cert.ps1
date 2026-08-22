<#
.SYNOPSIS
    Trusts OpenSecurity's code-signing certificate on this machine, so OpenSecurity
    executables stop showing "the publisher could not be verified" when you run them.

.DESCRIPTION
    OpenSecurity's release exes are signed with a self-signed certificate (see
    signing/README.md for why - a certificate from a trusted CA costs money and
    requires identity verification). Windows only shows the real publisher name
    instead of "Unknown Publisher" when it can verify the signature chains to a
    certificate it trusts, and by default nobody's machine trusts this one but the
    one it was created on.

    This script imports signing/OpenSecurity-SelfSigned.cer - the public
    certificate only, no private key, safe to run from anyone - into this
    Windows user account's Trusted Root Certification Authorities and Trusted
    Publisher stores. That's a real, local decision to trust software signed by
    this specific certificate going forward; only run it if you're getting
    OpenSecurity from a source you trust (e.g. the project's own GitHub releases).

    This only affects the machine it's run on, and only removes the "Unknown
    Publisher" / "Open File - Security Warning" prompt - it's unrelated to (and
    doesn't change) Windows SmartScreen's separate, reputation-based blue "Windows
    protected your PC" screen, which only a CA-issued certificate resolves.

    Optionally also removes the Mark-of-the-Web from specific downloaded file(s)
    via -UnblockFiles, which is what actually makes the security-warning prompt
    disappear for those files (trusting the certificate makes the publisher show
    up correctly; unblocking the file is what skips the prompt itself).

.EXAMPLE
    ./scripts/trust-cert.ps1

.EXAMPLE
    ./scripts/trust-cert.ps1 -UnblockFiles "OpenSecurity.Ui.exe","OpenSecurity.Cli.exe"
#>
param(
    [string]$CerPath = (Join-Path $PSScriptRoot "..\signing\OpenSecurity-SelfSigned.cer"),
    [string[]]$UnblockFiles
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $CerPath)) {
    throw "Certificate not found at $CerPath."
}

$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path $CerPath).Path)

Write-Output "Certificate: $($cert.Subject)"
Write-Output "Thumbprint:  $($cert.Thumbprint)"
Write-Output ""
Write-Output "Windows may ask you to confirm adding a root certificate - that's expected."
Write-Output ""

foreach ($storeName in @("Root", "TrustedPublisher")) {
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, "CurrentUser")
    $store.Open("ReadWrite")
    try {
        if ($store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $cert.Thumbprint, $false).Count -eq 0) {
            $store.Add($cert)
            Write-Output "Added to CurrentUser\$storeName"
        } else {
            Write-Output "Already present in CurrentUser\$storeName"
        }
    } finally {
        $store.Close()
    }
}

if ($UnblockFiles) {
    Write-Output ""
    foreach ($file in $UnblockFiles) {
        if (Test-Path $file) {
            Unblock-File -Path $file
            Write-Output "Unblocked: $file"
        } else {
            Write-Warning "File not found, skipped: $file"
        }
    }
}

Write-Output ""
Write-Output "Done. OpenSecurity executables signed with this certificate will now show as"
Write-Output "'$($cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false))' instead of 'Unknown Publisher' when you run them."
