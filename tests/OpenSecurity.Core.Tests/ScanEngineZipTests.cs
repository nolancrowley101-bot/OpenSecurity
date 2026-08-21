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

    private static ScanEngine MakeEngineWithPasswords(params string[] passwords) =>
        new(new HashScanner(HashSignatureDatabase.Empty()), new PatternRuleEngine(TestRules), new HeuristicAnalyzer(),
            allowlist: null, archivePasswords: passwords);

    private static string FixturePath(string name) =>
        Path.Combine(AppContext.BaseDirectory, "TestFixtures", name);

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

    // The fixtures below are real AES-encrypted zip/7z archives created with 7-Zip, mirroring how
    // real malware sample collections are commonly shared (encrypted so AV engines and accidental
    // double-clicks can't touch the payload). "mysubsarethebest" is the actual password convention
    // used by a well-known public malware sample repository.

    [Fact]
    public void ScanFile_PasswordProtectedZip_OpensWithConfiguredPassword_AndFlagsContent()
    {
        var result = MakeEngineWithPasswords("wrongfirst", "mysubsarethebest").ScanFile(FixturePath("encrypted_sample.zip"));

        Assert.Equal(Verdict.Malicious, result.OverallVerdict);
        Assert.Contains(result.Findings, f => f.Source == "archive" && f.Detail.Contains("payload.txt"));
    }

    [Fact]
    public void ScanFile_ZipUsingLzmaPlusAesEncryption_ReportsUnsupportedCodec_NotMisleadingWrongPassword()
    {
        // A real sample from a public malware database used this exact combination (AES-256 +
        // LZMA in a zip, rather than the far more common AES+DEFLATE) - SharpCompress 0.50.4
        // can't decode it even with the correct password. The important thing is the error
        // message says so accurately, rather than implying the password itself was wrong.
        var result = MakeEngineWithPasswords("wrongfirst", "mysubsarethebest").ScanFile(FixturePath("encrypted_lzma_sample.zip"));

        var archiveError = result.Findings.SingleOrDefault(f => f.Source == "archive");
        Assert.NotNull(archiveError);
        Assert.Equal("unsupported-archive", archiveError!.Name);
        Assert.DoesNotContain("unknown password", archiveError.Detail);
    }

    [Fact]
    public void ScanFile_PasswordProtectedSevenZip_OpensWithConfiguredPassword_AndFlagsContent()
    {
        var result = MakeEngineWithPasswords("mysubsarethebest").ScanFile(FixturePath("encrypted_sample.7z"));

        Assert.Equal(Verdict.Malicious, result.OverallVerdict);
        Assert.Contains(result.Findings, f => f.Source == "archive" && f.Detail.Contains("payload7z"));
    }

    [Fact]
    public void ScanFile_PasswordProtectedZip_WithoutMatchingPassword_ReportsErrorWithoutCrashing()
    {
        var result = MakeEngine().ScanFile(FixturePath("encrypted_sample.zip")); // no passwords configured at all

        Assert.Contains(result.Findings, f => f.Source == "archive" && f.Name == "password-protected");
    }

    [Fact]
    public void ScanFile_ZipEncryptedWithUnlistedPassword_ReportsErrorWithoutCrashing()
    {
        var result = MakeEngineWithPasswords("mysubsarethebest", "infected").ScanFile(FixturePath("wrongpw_sample.zip"));

        Assert.Contains(result.Findings, f => f.Source == "archive" && f.Name == "password-protected");
    }

    [Fact]
    public void ScanFile_ZipWithDifferentPasswordsPerEntry_ScansEveryEntry()
    {
        // Real-world malware collections repackage third-party installers inside a curated
        // archive, and each nested file can keep its own original password instead of the
        // collection's convention - fixture built with 7-Zip via two separate "7z a -p<pw>"
        // invocations against the same zip, so payload_a.txt (containing TESTMARKER) is
        // encrypted with "passwordA" and payload_b.txt with "passwordB". The archive-level
        // password lock-in (based on the first entry) must not cause later entries encrypted
        // with a different password to be silently skipped.
        var result = MakeEngineWithPasswords("passwordA", "passwordB").ScanFile(FixturePath("mixedpw_sample.zip"));

        Assert.Equal(Verdict.Malicious, result.OverallVerdict);
        Assert.Contains(result.Findings, f => f.Source == "archive" && f.Detail.Contains("payload_a.txt"));
        Assert.DoesNotContain(result.Findings, f => f.Source == "archive" && f.Name == "entry-read-error");
    }
}
