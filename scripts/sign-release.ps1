<#
.SYNOPSIS
    Code-signs one or more files with the OpenSecurity signing certificate.

.DESCRIPTION
    Looks for signtool.exe (Windows SDK), signs each given file with SHA-256 and a
    trusted timestamp so the signature stays valid after the certificate expires.

    Two signing modes, mutually exclusive:

    - PFX mode (default): uses signing/OpenSecurity-SelfSigned.pfx, a self-signed
      certificate. Proves the pipeline works and gives the exe tamper-evidence, but
      does NOT stop Windows SmartScreen warnings - only a certificate issued by a
      trusted CA does that, and that requires purchase + identity verification.

    - Thumbprint mode (-CertThumbprint): signs using a certificate already installed
      in the Windows certificate store instead of a .pfx file/password. This is the
      mode a real EV (Extended Validation) code-signing certificate needs - EV certs
      are legally required to live on a hardware token (USB dongle) or a cloud HSM,
      not as an exportable .pfx, so /f+/p can't be used with one. Find the thumbprint
      with: Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert (or Cert:\LocalMachine\My).
      A standard (OV) CA certificate can use either mode depending on how it was issued.

.EXAMPLE
    ./scripts/sign-release.ps1 -Files "publish/ui/OpenSecurity.Ui.exe","publish/cli/OpenSecurity.Cli.exe"

.EXAMPLE
    ./scripts/sign-release.ps1 -Files "publish/ui/OpenSecurity.Ui.exe" -CertThumbprint "AB12CD34..."
#>
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Files,

    [string]$PfxPath = (Join-Path $PSScriptRoot "..\signing\OpenSecurity-SelfSigned.pfx"),
    [string]$PfxPasswordFile = (Join-Path $PSScriptRoot "..\signing\cert-password.txt"),
    [string]$CertThumbprint,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $signtool) {
    throw "signtool.exe not found. Install the Windows SDK."
}

if ($CertThumbprint) {
    foreach ($file in $Files) {
        if (-not (Test-Path $file)) {
            throw "File not found: $file"
        }

        & $signtool sign /sha1 $CertThumbprint /fd SHA256 /t $TimestampUrl $file
        if ($LASTEXITCODE -ne 0) {
            throw "signtool failed to sign $file (exit code $LASTEXITCODE)"
        }
    }
} else {
    if (-not (Test-Path $PfxPath)) {
        throw "Signing certificate not found at $PfxPath. See signing/README.md to generate one, or pass -CertThumbprint if you're signing with a store-installed (e.g. EV hardware-token) certificate instead."
    }
    if (-not (Test-Path $PfxPasswordFile)) {
        throw "Certificate password file not found at $PfxPasswordFile."
    }

    $password = Get-Content $PfxPasswordFile -Raw

    foreach ($file in $Files) {
        if (-not (Test-Path $file)) {
            throw "File not found: $file"
        }

        & $signtool sign /f $PfxPath /p $password /fd SHA256 /t $TimestampUrl $file
        if ($LASTEXITCODE -ne 0) {
            throw "signtool failed to sign $file (exit code $LASTEXITCODE)"
        }
    }
}

Write-Output "Signed $($Files.Count) file(s)."
