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

**EV (Extended Validation)** clears SmartScreen almost immediately (no reputation-building
period) because issuance requires stronger identity verification. The trade-off: Microsoft's
CA/Browser Forum baseline requirements mandate the private key live on a hardware token (a
USB dongle shipped by the CA) or a cloud HSM - it can't be exported as a portable `.pfx`.
Typical cost is roughly $300-600/year from a CA like DigiCert, Sectigo, or SSL.com; expect
the identity/business verification step to take anywhere from a day to a couple of weeks.

**OV (Organization Validation)** is cheaper (roughly $70-300/year) and can usually be
exported as a `.pfx`, but SmartScreen still warns initially - it clears over time as
download/run reputation builds, with no fixed timeline.

Once you have a certificate:

- **.pfx-based (OV, or EV via a cloud HSM that exposes one)**: replace `signing/OpenSecurity-SelfSigned.pfx` and `signing/cert-password.txt` with the new files (same filenames, or pass `-PfxPath`/`-PfxPasswordFile` to the script).
- **Hardware-token EV**: install the token's driver/software from the CA, plug in the dongle, then find the certificate's thumbprint with `Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert` (or `Cert:\LocalMachine\My`) and pass it as `-CertThumbprint` to `scripts/sign-release.ps1` - the token handles the private key, signtool never touches a password file. The token typically needs to be plugged into whatever machine actually runs the signing step.

No other code changes needed either way - `scripts/sign-release.ps1` already supports both modes.
