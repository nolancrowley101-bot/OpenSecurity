using System.Reflection;
using OpenSecurity.Core.Pe;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class PeParserTests
{
    [Fact]
    public void TryParse_ParsesOwnTestAssembly_AsValidPe()
    {
        var path = Assembly.GetExecutingAssembly().Location;
        var bytes = File.ReadAllBytes(path);

        var ok = PeParser.TryParse(bytes, out var pe);

        Assert.True(ok);
        Assert.NotNull(pe);
        Assert.True(pe!.Sections.Count > 0);
    }

    [Fact]
    public void TryParse_ReturnsFalse_ForNonPeData()
    {
        var bytes = "this is not a PE file at all, just plain text padding"u8.ToArray();
        var ok = PeParser.TryParse(bytes, out var pe);
        Assert.False(ok);
        Assert.Null(pe);
    }

    [Fact]
    public void TryParse_ReturnsFalse_ForTruncatedMzHeader()
    {
        var bytes = new byte[] { (byte)'M', (byte)'Z' };
        var ok = PeParser.TryParse(bytes, out var pe);
        Assert.False(ok);
        Assert.Null(pe);
    }

    [Fact]
    public void TryParse_NeverThrows_OnRandomGarbageWithMzMagic()
    {
        var random = new Random(42);
        var bytes = new byte[4096];
        random.NextBytes(bytes);
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';

        var exception = Record.Exception(() => PeParser.TryParse(bytes, out _));
        Assert.Null(exception);
    }
}
