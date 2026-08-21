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
