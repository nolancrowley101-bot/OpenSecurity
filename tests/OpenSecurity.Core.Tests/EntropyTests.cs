using OpenSecurity.Core.Heuristics;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class EntropyTests
{
    [Fact]
    public void Shannon_OfEmptyData_IsZero()
    {
        Assert.Equal(0.0, Entropy.Shannon(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Shannon_OfSingleRepeatedByte_IsZero()
    {
        var data = new byte[1000];
        Array.Fill(data, (byte)0x41);
        Assert.Equal(0.0, Entropy.Shannon(data), precision: 6);
    }

    [Fact]
    public void Shannon_OfUniformRandomBytes_IsCloseToEight()
    {
        var data = new byte[256];
        for (var i = 0; i < 256; i++)
            data[i] = (byte)i; // each byte value appears exactly once -> maximal entropy

        Assert.True(Entropy.Shannon(data) > 7.99);
    }

    [Fact]
    public void Shannon_OfTwoAlternatingBytes_IsOne()
    {
        var data = new byte[1000];
        for (var i = 0; i < data.Length; i++)
            data[i] = (byte)(i % 2 == 0 ? 0x00 : 0xFF);

        Assert.Equal(1.0, Entropy.Shannon(data), precision: 6);
    }
}
