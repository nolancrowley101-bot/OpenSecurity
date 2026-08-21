using System.IO.Compression;
using OpenSecurity.Core.Hashing;
using OpenSecurity.Core.Heuristics;
using OpenSecurity.Core.Rules;
using OpenSecurity.Core.Scanning;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class ScanEngineZipTests : IDisposable
{
    private readonly string _tempFile = Path.Combine(Path.GetTempPath(), "OpenSecurityTests_" + Guid.NewGuid().ToString("N") + ".zip");

    private static readonly List<PatternRule> TestRules = PatternRuleParser.ParseText("""
        rule Test_Marker : Malicious
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

    private static ScanEngine MakeEngine() =>
        new(new HashScanner(HashSignatureDatabase.Empty()), new PatternRuleEngine(TestRules), new HeuristicAnalyzer());

    [Fact]
    public void ScanFile_ZipContainingMatch_FlagsArchiveFindingWithEntryName()
    {
        using (var zip = ZipFile.Open(_tempFile, ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry("payload.txt");
            using var writer = new StreamWriter(entry.Open());
            writer.Write("contains TESTMARKER inside");
        }

        var result = MakeEngine().ScanFile(_tempFile);

        Assert.Equal(Verdict.Malicious, result.OverallVerdict);
        Assert.Contains(result.Findings, f => f.Source == "archive" && f.Detail.Contains("payload.txt"));
    }

    [Fact]
    public void ScanFile_ZipWithNoMatchingEntries_IsClean()
    {
        using (var zip = ZipFile.Open(_tempFile, ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry("readme.txt");
            using var writer = new StreamWriter(entry.Open());
            writer.Write("just a normal readme file, nothing suspicious here");
        }

        var result = MakeEngine().ScanFile(_tempFile);

        Assert.Equal(Verdict.Clean, result.OverallVerdict);
    }

    [Fact]
    public void ScanFile_ZipWithMultipleEntries_OnlyFlagsTheMatchingOne()
    {
        using (var zip = ZipFile.Open(_tempFile, ZipArchiveMode.Create))
        {
            using (var writer = new StreamWriter(zip.CreateEntry("clean.txt").Open()))
                writer.Write("harmless");
            using (var writer = new StreamWriter(zip.CreateEntry("bad.txt").Open()))
                writer.Write("TESTMARKER");
        }

        var result = MakeEngine().ScanFile(_tempFile);

        var archiveFindings = result.Findings.Where(f => f.Source == "archive" && f.Verdict != Verdict.Error).ToList();
        Assert.Single(archiveFindings);
        Assert.Contains("bad.txt", archiveFindings[0].Detail);
    }

    [Fact]
    public void ScanFile_CorruptZipWithValidMagicBytes_ReportsErrorWithoutCrashing()
    {
        File.WriteAllBytes(_tempFile, new byte[] { (byte)'P', (byte)'K', 0x03, 0x04, 1, 2, 3, 4, 5 });

        var result = MakeEngine().ScanFile(_tempFile);

        Assert.Contains(result.Findings, f => f.Source == "archive" && f.Verdict == Verdict.Error);
    }

    [Fact]
    public void ScanFile_NonZipFile_DoesNotAttemptArchiveScan()
    {
        File.WriteAllText(_tempFile, "TESTMARKER but not a zip at all");

        var result = MakeEngine().ScanFile(_tempFile);

        Assert.DoesNotContain(result.Findings, f => f.Source == "archive");
        Assert.Equal(Verdict.Malicious, result.OverallVerdict); // still caught by the top-level rule scan
    }
}
