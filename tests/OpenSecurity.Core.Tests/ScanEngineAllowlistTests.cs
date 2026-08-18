using OpenSecurity.Core.Hashing;
using OpenSecurity.Core.Heuristics;
using OpenSecurity.Core.Rules;
using OpenSecurity.Core.Scanning;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class ScanEngineAllowlistTests : IDisposable
{
    private readonly string _tempFile = Path.Combine(Path.GetTempPath(), "OpenSecurityTests_" + Guid.NewGuid().ToString("N") + ".bin");

    private static readonly List<PatternRule> TestRules = PatternRuleParser.ParseText("""
        rule Test_Marker : Suspicious
        {
            strings:
                $a = "TESTMARKER"
            condition:
                any of them
        }
        """);

    public void Dispose()
    {
        if (File.Exists(_tempFile))
            File.Delete(_tempFile);
    }

    [Fact]
    public void Scan_FlagsPatternMatch_WhenNotAllowlisted()
    {
        File.WriteAllText(_tempFile, "contains TESTMARKER inside");
        var engine = new ScanEngine(new HashScanner(HashSignatureDatabase.Empty()), new PatternRuleEngine(TestRules), new HeuristicAnalyzer());

        var result = engine.ScanFile(_tempFile);

        Assert.Equal(Verdict.Suspicious, result.OverallVerdict);
    }

    [Fact]
    public void Scan_SuppressesPatternMatch_WhenFileIsAllowlisted()
    {
        File.WriteAllText(_tempFile, "contains TESTMARKER inside");
        using var stream = File.OpenRead(_tempFile);
        var sha256 = HashScanner.ComputeSha256(stream);

        var allowlistFile = _tempFile + ".allowlist";
        File.WriteAllText(allowlistFile, $"{sha256}  trusted-by-user\n");
        var allowlist = HashSignatureDatabase.Load(allowlistFile);

        var engine = new ScanEngine(new HashScanner(HashSignatureDatabase.Empty()), new PatternRuleEngine(TestRules), new HeuristicAnalyzer(), allowlist);

        var result = engine.ScanFile(_tempFile);

        Assert.Equal(Verdict.Clean, result.OverallVerdict);
        File.Delete(allowlistFile);
    }

    [Fact]
    public void Scan_HashBlacklistMatch_StillWins_EvenWhenAllowlisted()
    {
        File.WriteAllText(_tempFile, "contains TESTMARKER inside");
        using var stream = File.OpenRead(_tempFile);
        var sha256 = HashScanner.ComputeSha256(stream);

        var allowlistFile = _tempFile + ".allowlist";
        File.WriteAllText(allowlistFile, $"{sha256}  trusted-by-user\n");
        var allowlist = HashSignatureDatabase.Load(allowlistFile);

        var blacklistFile = _tempFile + ".blacklist";
        File.WriteAllText(blacklistFile, $"{sha256}  known-bad\n");
        var blacklist = HashSignatureDatabase.Load(blacklistFile);

        var engine = new ScanEngine(new HashScanner(blacklist), new PatternRuleEngine(TestRules), new HeuristicAnalyzer(), allowlist);

        var result = engine.ScanFile(_tempFile);

        Assert.Equal(Verdict.Malicious, result.OverallVerdict);
        File.Delete(allowlistFile);
        File.Delete(blacklistFile);
    }
}
