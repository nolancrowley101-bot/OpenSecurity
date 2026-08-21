// Structural indicator strings for common webshell, dropper, and living-off-the-land
// techniques. These are indicators of technique, not proof of malice on their own --
// legitimate admin/dev tooling can trigger some of these too, so most stay Suspicious.

rule Suspicious_PHP_Webshell_Eval : Suspicious
{
    strings:
        $a = "eval($_POST" ascii
        $b = "eval($_GET" ascii
        $c = "eval(base64_decode" ascii
        $d = "system($_POST" ascii
        $e = "shell_exec($_" ascii
        $f = "passthru($_" ascii

    condition:
        any of them
}

rule Suspicious_Script_Downloader : Suspicious
{
    strings:
        $a = "DownloadString(" ascii nocase
        $b = "DownloadFile(" ascii nocase
        $c = "IEX (New-Object" ascii nocase
        $d = "Invoke-Expression" ascii nocase
        $e = "Net.WebClient" ascii nocase

    condition:
        any of them
}

rule Suspicious_LOLBin_Abuse : Suspicious
{
    strings:
        $a = "certutil -decode" ascii nocase
        $b = "certutil.exe -urlcache" ascii nocase
        $c = "mshta http" ascii nocase
        $d = "rundll32.exe javascript:" ascii nocase
        $e = "bitsadmin /transfer" ascii nocase

    condition:
        any of them
}

// "Living off the land" - using Windows' own trusted binaries to download or execute
// payloads, evading tools that only flag unknown/unsigned executables.
rule Suspicious_Ransom_Note_Language : Suspicious
{
    strings:
        $a = "your files have been encrypted" ascii nocase
        $b = "decrypt your files" ascii nocase
        $c = "pay the ransom" ascii nocase
        $d = "your personal files are encrypted" ascii nocase

    condition:
        any of them
}

// Split into one rule per trigger name rather than one rule listing all three - the parser's
// "all of them" requires every listed string to be present, and a macro only ever uses one
// specific autoexec trigger name, never all three at once.
rule Suspicious_Macro_AutoOpen_Shell : Suspicious
{
    strings:
        $auto = "Auto_Open" ascii nocase
        $shell = "Shell(" ascii nocase

    condition:
        all of them
}

rule Suspicious_Macro_AutoOpenAlt_Shell : Suspicious
{
    strings:
        $auto = "AutoOpen" ascii nocase
        $shell = "Shell(" ascii nocase

    condition:
        all of them
}

rule Suspicious_Macro_DocumentOpen_Shell : Suspicious
{
    strings:
        $auto = "Document_Open" ascii nocase
        $shell = "Shell(" ascii nocase

    condition:
        all of them
}
