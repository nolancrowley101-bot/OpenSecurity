// Generic, low-confidence indicators sometimes seen in obfuscated dropper scripts
// embedded inside binaries. Weak signals on their own -- Suspicious, not Malicious.
rule Suspicious_PowerShell_EncodedCommand : Suspicious
{
    strings:
        $enc1 = "-EncodedCommand" ascii nocase
        $enc2 = "-enc " ascii nocase
        $bypass = "-ExecutionPolicy Bypass" ascii nocase

    condition:
        any of them
}

rule Suspicious_Amsi_Bypass_Reference : Suspicious
{
    // The bare native API name "AmsiScanBuffer" is too broad on its own - any AMSI-aware
    // software (including the .NET runtime's own built-in AMSI integration, bundled into
    // every self-contained .NET app) legitimately references it. PowerShell's internal
    // AmsiUtils type name is specific to the well-known reflection-based bypass technique
    // and isn't something legitimate AMSI-integrated code would contain.
    strings:
        $amsiUtils = "System.Management.Automation.AmsiUtils" ascii nocase
        $amsiCtx = "amsiInitFailed" ascii

    condition:
        any of them
}
