using System.Text;
using OpenSecurity.Core.Hashing;
using OpenSecurity.Core.Scanning;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class HashScannerTests
{
    [Fact]
    public void ComputeSha256_MatchesKnownVector()
    {
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes("abc"));
        var hash = HashScanner.ComputeSha256(stream);
        Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hash);
        Assert.Equal(64, hash.Length);
    }

    [Fact]
    public void Scan_ReturnsMalicious_WhenHashMatchesDatabase()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            var testHash = "deadbeef" + new string('0', 56);
            File.WriteAllText(tempFile, $"# comment line\n\n{testHash}  test-sample\n");
            var db = HashSignatureDatabase.Load(tempFile);
            var scanner = new HashScanner(db);

            var findings = scanner.Scan(testHash).ToList();

            Assert.Single(findings);
            Assert.Equal(Verdict.Malicious, findings[0].Verdict);
            Assert.Equal("test-sample", findings[0].Name);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void Scan_ReturnsEmpty_WhenHashNotInDatabase()
    {
        var scanner = new HashScanner(HashSignatureDatabase.Empty());
        var findings = scanner.Scan(new string('0', 64)).ToList();
        Assert.Empty(findings);
    }
}
