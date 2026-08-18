using OpenSecurity.Core.Updates;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class SignatureFeedParserTests
{
    [Fact]
    public void Parse_ExtractsBareHashesOneParLine()
    {
        var hashA = new string('a', 64);
        var hashB = new string('b', 64);
        var feed = $"{hashA}\n{hashB}\n";

        var results = SignatureFeedParser.Parse(feed).ToList();

        Assert.Equal(2, results.Count);
        Assert.Contains(results, r => r.Hash == hashA);
        Assert.Contains(results, r => r.Hash == hashB);
    }

    [Fact]
    public void Parse_SkipsCommentsAndBlankLines()
    {
        var hash = new string('c', 64);
        var feed = $"# this is a comment\n\n{hash}\n";

        var results = SignatureFeedParser.Parse(feed).ToList();

        Assert.Single(results);
        Assert.Equal(hash, results[0].Hash);
    }

    [Fact]
    public void Parse_SkipsLinesWithoutAValidHash()
    {
        var feed = "not-a-hash-line\nshort123\n";
        Assert.Empty(SignatureFeedParser.Parse(feed));
    }

    [Fact]
    public void Parse_ExtractsLabelFromCsvRow()
    {
        var hash = new string('d', 64);
        var feed = $"\"2026-01-01\",\"{hash}\",\"md5abc\",\"exe\",\"TrickyMalwareFamily\"\n";

        var results = SignatureFeedParser.Parse(feed).ToList();

        Assert.Single(results);
        Assert.Equal(hash, results[0].Hash);
        Assert.False(string.IsNullOrWhiteSpace(results[0].Label));
    }

    [Fact]
    public void Parse_NormalizesHashToLowercase()
    {
        var hash = new string('A', 64);
        var results = SignatureFeedParser.Parse(hash).ToList();

        Assert.Single(results);
        Assert.Equal(new string('a', 64), results[0].Hash);
    }
}
