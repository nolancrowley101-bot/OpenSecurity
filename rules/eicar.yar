// Demonstrates string-pattern matching using the standard EICAR test string.
// This is the universal, harmless AV self-test signature, not real malware content.
rule Eicar_Test_String : Malicious
{
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii

    condition:
        any of them
}
