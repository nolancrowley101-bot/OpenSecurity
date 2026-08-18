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
    strings:
        $amsi = "AmsiScanBuffer" ascii
        $amsiCtx = "amsiInitFailed" ascii

    condition:
        any of them
}
