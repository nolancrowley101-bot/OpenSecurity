using OpenSecurity.Core.Hashing;
using OpenSecurity.Core.Heuristics;
using OpenSecurity.Core.Rules;
using OpenSecurity.Core.Scanning;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class ScanEngineDirectoryTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "OpenSecurityTests_dir_" + Guid.NewGuid().ToString("N"));

    private static readonly List<PatternRule> TestRules = PatternRuleParser.ParseText("""
        rule Test_Marker : Malicious
        {
            strings:
                $a = "TESTMARKER"
            condition:
                any of them
        }
        """);

    public ScanEngineDirectoryTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, recursive: true);
    }

    private static ScanEngine MakeEngine() =>
        new(new HashScanner(HashSignatureDatabase.Empty()), new PatternRuleEngine(TestRules), new HeuristicAnalyzer());

    [Fact]
    public void ScanDirectory_MultipleFiles_ScansEveryFileExactlyOnce_RegardlessOfCompletionOrder()
    {
        // Parallel scanning means results arrive in completion order, not filesystem order -
        // this only asserts on the *set* of results, not their sequence.
        const int fileCount = 40;
        for (var i = 0; i < fileCount; i++)
            File.WriteAllText(Path.Combine(_dir, $"file{i}.txt"), i % 5 == 0 ? "contains TESTMARKER inside" : "clean content");

        var results = MakeEngine().ScanDirectory(_dir, recursive: false).ToList();

        Assert.Equal(fileCount, results.Count);
        Assert.Equal(fileCount, results.Select(r => r.FilePath).Distinct().Count());
        Assert.Equal(8, results.Count(r => r.OverallVerdict == Verdict.Malicious)); // every 5th of 40
        Assert.Equal(32, results.Count(r => r.OverallVerdict == Verdict.Clean));
    }

    [Fact]
    public void ScanDirectory_RespectsMaxDegreeOfParallelismOfOne_StillScansEverything()
    {
        for (var i = 0; i < 10; i++)
            File.WriteAllText(Path.Combine(_dir, $"file{i}.txt"), "clean content");

        var results = MakeEngine().ScanDirectory(_dir, recursive: false, maxDegreeOfParallelism: 1).ToList();

        Assert.Equal(10, results.Count);
        Assert.All(results, r => Assert.Equal(Verdict.Clean, r.OverallVerdict));
    }

    [Fact]
    public void ScanDirectory_MissingDirectory_ReportsErrorWithoutThrowing()
    {
        var results = MakeEngine().ScanDirectory(Path.Combine(_dir, "does-not-exist"), recursive: false).ToList();

        Assert.Single(results);
        Assert.Equal(Verdict.Error, results[0].OverallVerdict);
    }
}
