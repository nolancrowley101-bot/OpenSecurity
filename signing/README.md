# Code signing

`OpenSecurity-SelfSigned.pfx` (private key + password) is **never committed** - see `.gitignore`.
`OpenSecurity-SelfSigned.cer` (public certificate only, no private key) is safe to share/commit if you want people to be able to trust it locally.

## What this gets you

A self-signed certificate proves the pipeline works and makes the exe tamper-evident (any
modification after signing invalidates the signature), but it does **not** stop Windows
SmartScreen warnings for anyone downloading the exe - only a certificate issued by a
trusted CA (DigiCert, Sectigo, etc.) does that, and those cost money and require identity
verification.

## Regenerating the self-signed certificate

```powershell
$cert = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject "CN=Nolan Crowley, O=OpenSecurity, C=US" `
  -KeyUsage DigitalSignature `
  -FriendlyName "OpenSecurity Code Signing (self-signed)" `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -NotAfter (Get-Date).AddYears(5) `
  -HashAlgorithm SHA256 `
  -KeyExportPolicy Exportable

$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 24
$rng.GetBytes($bytes)
$password = [Convert]::ToBase64String($bytes)
$securePassword = ConvertTo-SecureString -String $password -Force -AsPlainText

Export-PfxCertificate -Cert $cert -FilePath "signing\OpenSecurity-SelfSigned.pfx" -Password $securePassword
Export-Certificate -Cert $cert -FilePath "signing\OpenSecurity-SelfSigned.cer"
Set-Content -Path "signing\cert-password.txt" -Value $password -NoNewline
```

Then sign a build with:

```powershell
./scripts/sign-release.ps1 -Files "publish\ui\OpenSecurity.Ui.exe","publish\cli\OpenSecurity.Cli.exe"
```

## Upgrading to a real (CA-issued) certificate

1. Buy a code-signing certificate from a CA (DigiCert, Sectigo, SSL.com, etc.) - requires identity/business verification.
2. Export it as a `.pfx` with a password.
3. Replace `signing/OpenSecurity-SelfSigned.pfx` and `signing/cert-password.txt` with the new files (same filenames, or pass `-PfxPath`/`-PfxPasswordFile` to the script).

No code changes needed - `scripts/sign-release.ps1` works the same either way.
