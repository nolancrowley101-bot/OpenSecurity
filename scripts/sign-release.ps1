<#
.SYNOPSIS
    Code-signs one or more files with the OpenSecurity signing certificate.

.DESCRIPTION
    Looks for signtool.exe (Windows SDK), signs each given file with SHA-256 and a
    trusted timestamp so the signature stays valid after the certificate expires.

    Currently uses signing/OpenSecurity-SelfSigned.pfx - a self-signed certificate.
    This proves the signing pipeline works and gives the exe tamper-evidence, but it
    will NOT stop Windows SmartScreen warnings for other people downloading it, since
    the certificate isn't issued by a trusted CA. To upgrade: buy a real code-signing
    certificate (e.g. from DigiCert or Sectigo), export it as a .pfx, and point
    -PfxPath / -PfxPasswordFile at it instead - no other changes needed.

.EXAMPLE
    ./scripts/sign-release.ps1 -Files "publish/ui/OpenSecurity.Ui.exe","publish/cli/OpenSecurity.Cli.exe"
#>
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Files,

    [string]$PfxPath = (Join-Path $PSScriptRoot "..\signing\OpenSecurity-SelfSigned.pfx"),
    [string]$PfxPasswordFile = (Join-Path $PSScriptRoot "..\signing\cert-password.txt"),
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $PfxPath)) {
    throw "Signing certificate not found at $PfxPath. See signing/README.md to generate one."
}
if (-not (Test-Path $PfxPasswordFile)) {
    throw "Certificate password file not found at $PfxPasswordFile."
}

$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $signtool) {
    throw "signtool.exe not found. Install the Windows SDK."
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

Write-Output "Signed $($Files.Count) file(s)."
