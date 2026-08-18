using System.Text;
using OpenSecurity.Core.Rules;
using OpenSecurity.Core.Scanning;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class PatternRuleEngineTests
{
    private const string RuleText = """
        rule Test_Ascii_Match : Malicious
        {
            strings:
                $a = "HELLO-MALWARE-MARKER" ascii
            condition:
                any of them
        }

        rule Test_NoCase_Match : Suspicious
        {
            strings:
                $a = "secret-token" ascii nocase
            condition:
                any of them
        }

        rule Test_All_Of_Them : Suspicious
        {
            strings:
                $a = "part-one"
                $b = "part-two"
            condition:
                all of them
        }
        """;

    [Fact]
    public void ParseText_ParsesThreeRules()
    {
        var rules = PatternRuleParser.ParseText(RuleText);
        Assert.Equal(3, rules.Count);
    }

    [Fact]
    public void Scan_MatchesAsciiPattern()
    {
        var engine = new PatternRuleEngine(PatternRuleParser.ParseText(RuleText));
        var content = Encoding.ASCII.GetBytes("junk before HELLO-MALWARE-MARKER junk after");

        var findings = engine.Scan(content).ToList();

        Assert.Contains(findings, f => f.Name == "Test_Ascii_Match" && f.Verdict == Verdict.Malicious);
    }

    [Fact]
    public void Scan_MatchesNoCasePattern_RegardlessOfCase()
    {
        var engine = new PatternRuleEngine(PatternRuleParser.ParseText(RuleText));
        var content = Encoding.ASCII.GetBytes("contains SECRET-TOKEN here");

        var findings = engine.Scan(content).ToList();

        Assert.Contains(findings, f => f.Name == "Test_NoCase_Match");
    }

    [Fact]
    public void Scan_AllOfThem_RequiresEveryPattern()
    {
        var engine = new PatternRuleEngine(PatternRuleParser.ParseText(RuleText));

        var onlyOne = engine.Scan(Encoding.ASCII.GetBytes("part-one only")).ToList();
        Assert.DoesNotContain(onlyOne, f => f.Name == "Test_All_Of_Them");

        var both = engine.Scan(Encoding.ASCII.GetBytes("part-one and part-two together")).ToList();
        Assert.Contains(both, f => f.Name == "Test_All_Of_Them");
    }

    [Fact]
    public void Scan_ReturnsNothing_WhenNoPatternMatches()
    {
        var engine = new PatternRuleEngine(PatternRuleParser.ParseText(RuleText));
        var findings = engine.Scan(Encoding.ASCII.GetBytes("totally benign content")).ToList();
        Assert.Empty(findings);
    }
}
