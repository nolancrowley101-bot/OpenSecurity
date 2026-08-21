using OpenSecurity.Core.Hashing;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class FuzzyHashTests
{
    private static byte[] RandomBytes(int length, int seed)
    {
        var random = new Random(seed);
        var bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }

    [Fact]
    public void Compute_IdenticalInputs_ProduceIdenticalSignatures()
    {
        var data = RandomBytes(8192, seed: 1);

        var sig1 = FuzzyHash.Compute(data);
        var sig2 = FuzzyHash.Compute((byte[])data.Clone());

        Assert.Equal(sig1, sig2);
    }

    [Fact]
    public void Similarity_IdenticalSignatures_Scores100()
    {
        var data = RandomBytes(8192, seed: 2);
        var signature = FuzzyHash.Compute(data);

        Assert.Equal(100, FuzzyHash.Similarity(signature, signature));
    }

    [Fact]
    public void Similarity_SmallAppendedChange_StaysHighlySimilar()
    {
        // Simulates a recompiled/repacked variant of the same sample: mostly identical bytes
        // with a small chunk changed near the end - the whole point of fuzzy hashing is that
        // this should still score highly, unlike SHA-256 which would differ completely.
        var original = RandomBytes(16384, seed: 3);
        var modified = (byte[])original.Clone();
        for (var i = modified.Length - 200; i < modified.Length; i++)
            modified[i] = (byte)(modified[i] ^ 0xFF);

        var sig1 = FuzzyHash.Compute(original);
        var sig2 = FuzzyHash.Compute(modified);

        var score = FuzzyHash.Similarity(sig1, sig2);
        Assert.True(score >= 60, $"expected high similarity for a small localized change, got {score}");
    }

    [Fact]
    public void Similarity_CompletelyUnrelatedInputs_ScoresLow()
    {
        var data1 = RandomBytes(8192, seed: 10);
        var data2 = RandomBytes(8192, seed: 20);

        var score = FuzzyHash.Similarity(FuzzyHash.Compute(data1), FuzzyHash.Compute(data2));

        Assert.True(score < 30, $"expected low similarity for unrelated inputs, got {score}");
    }

    [Fact]
    public void Similarity_IncompatibleBlockSizes_ScoresZero()
    {
        // A tiny input and a huge one land on very different block sizes (more than a factor
        // of two apart), so their piecewise hashes were computed at incompatible granularities
        // and can't be meaningfully compared.
        var small = FuzzyHash.Compute(RandomBytes(64, seed: 4));
        var large = FuzzyHash.Compute(RandomBytes(1_000_000, seed: 5));

        Assert.Equal(0, FuzzyHash.Similarity(small, large));
    }

    [Fact]
    public void Compute_EmptyInput_DoesNotThrow()
    {
        var signature = FuzzyHash.Compute(Array.Empty<byte>());
        Assert.NotNull(signature);
        Assert.Contains(':', signature);
    }

    [Fact]
    public void FuzzySignatureDatabase_FindSimilar_MatchesNearDuplicate_AboveThreshold()
    {
        var scratchPath = Path.Combine(Path.GetTempPath(), "OpenSecurityTests_fuzzy_" + Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            var original = RandomBytes(16384, seed: 6);
            var modified = (byte[])original.Clone();
            for (var i = 0; i < 100; i++)
                modified[i] = (byte)(modified[i] ^ 0xAA);

            File.WriteAllLines(scratchPath, new[] { $"{FuzzyHash.Compute(original)}  TestFamily:variant-a" });
            var db = FuzzySignatureDatabase.Load(scratchPath);

            var matches = db.FindSimilar(FuzzyHash.Compute(modified), threshold: 60).ToList();

            Assert.Single(matches);
            Assert.Equal("TestFamily:variant-a", matches[0].Label);
            Assert.True(matches[0].Score >= 60);
        }
        finally
        {
            File.Delete(scratchPath);
        }
    }
}
