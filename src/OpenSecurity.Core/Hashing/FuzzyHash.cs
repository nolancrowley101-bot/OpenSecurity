using System.Text;

namespace OpenSecurity.Core.Hashing;

/// <summary>
/// Context-triggered piecewise hashing (CTPH) - the technique behind ssdeep. Unlike SHA-256,
/// where a single changed byte produces a completely unrelated hash, CTPH signatures of similar
/// inputs (a recompiled sample, a repacked installer) stay similar, so near-duplicate malware
/// variants can be caught even when no exact hash matches. This is a self-contained
/// implementation of the same rolling-hash/block-hash technique described in Kornblum's original
/// "Identifying almost identical files using context triggered piecewise hashing" paper - it is
/// not bit-compatible with upstream ssdeep signatures, so hashes can't be mixed between the two.
/// </summary>
public static class FuzzyHash
{
    private const string Base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private const int MinBlockSize = 3;
    private const int SpamSumLength = 64; // target signature length per block size
    private const int RollingWindow = 7;
    private const uint HashInit = 0x28021967;
    private const uint HashPrime = 0x01000193;

    /// <summary>Produces a "blocksize:hash1:hash2" signature, where hash1 is piecewise-hashed at
    /// the chosen block size and hash2 at double that size (letting <see cref="Similarity"/>
    /// compare signatures computed at adjacent scales).</summary>
    public static string Compute(byte[] data)
    {
        if (data.Length == 0)
            return $"{MinBlockSize}::";

        var blockSize = MinBlockSize;
        while ((long)blockSize * SpamSumLength < data.Length)
            blockSize *= 2;

        var (hash1, hash2) = HashAtBlockSize(data, blockSize);

        // If the finer-grained signature came out too short to be useful for comparison, ssdeep's
        // convention is to halve the block size and retry - more, shorter blocks give a longer,
        // more discriminating signature for small-to-medium inputs.
        while (blockSize > MinBlockSize && hash1.Length < SpamSumLength / 2)
        {
            blockSize /= 2;
            (hash1, hash2) = HashAtBlockSize(data, blockSize);
        }

        return $"{blockSize}:{hash1}:{hash2}";
    }

    private static (string Hash1, string Hash2) HashAtBlockSize(byte[] data, int blockSize)
    {
        var result1 = new StringBuilder();
        var result2 = new StringBuilder();
        var blockSize2 = blockSize * 2;

        var window = new byte[RollingWindow];
        uint rollH1 = 0, rollH2 = 0, rollH3 = 0;
        var windowPos = 0;

        var blockHash1 = HashInit;
        var blockHash2 = HashInit;

        foreach (var c in data)
        {
            blockHash1 = (blockHash1 * HashPrime) ^ c;
            blockHash2 = (blockHash2 * HashPrime) ^ c;

            rollH2 = unchecked(rollH2 - rollH1 + (uint)RollingWindow * c);
            rollH1 = unchecked(rollH1 + c - window[windowPos % RollingWindow]);
            window[windowPos % RollingWindow] = c;
            windowPos++;
            rollH3 = unchecked((rollH3 << 5) & 0xFFFFFFFF) ^ c;
            var rollingHash = unchecked(rollH1 + rollH2 + rollH3);

            if (rollingHash % (uint)blockSize == (uint)blockSize - 1)
            {
                result1.Append(Base64Alphabet[(int)(blockHash1 % 64)]);
                blockHash1 = HashInit;
            }

            if (rollingHash % (uint)blockSize2 == (uint)blockSize2 - 1 && result2.Length < SpamSumLength / 2)
            {
                result2.Append(Base64Alphabet[(int)(blockHash2 % 64)]);
                blockHash2 = HashInit;
            }
        }

        if (windowPos > 0)
        {
            result1.Append(Base64Alphabet[(int)(blockHash1 % 64)]);
            if (result2.Length < SpamSumLength / 2)
                result2.Append(Base64Alphabet[(int)(blockHash2 % 64)]);
        }

        return (result1.ToString(), result2.ToString());
    }

    /// <summary>Compares two "blocksize:hash1:hash2" signatures, returning a 0-100 similarity
    /// score. Signatures can only be meaningfully compared when their block sizes match or are
    /// exactly double one another (the same constraint ssdeep imposes) - anything else scores 0,
    /// since the piecewise hashes were computed at incompatible granularities.</summary>
    public static int Similarity(string signature1, string signature2)
    {
        if (!TryParse(signature1, out var bs1, out var h1a, out var h1b))
            return 0;
        if (!TryParse(signature2, out var bs2, out var h2a, out var h2b))
            return 0;

        if (bs1 == bs2)
            return StringSimilarity(h1a, h2a);
        if (bs1 * 2 == bs2)
            return StringSimilarity(h1b, h2a);
        if (bs2 * 2 == bs1)
            return StringSimilarity(h1a, h2b);

        return 0;
    }

    private static bool TryParse(string signature, out int blockSize, out string hash1, out string hash2)
    {
        blockSize = 0;
        hash1 = hash2 = "";
        var parts = signature.Split(':');
        if (parts.Length != 3 || !int.TryParse(parts[0], out blockSize))
            return false;

        hash1 = parts[1];
        hash2 = parts[2];
        return true;
    }

    /// <summary>Normalized edit-distance similarity (0-100), with a minimum-shared-run gate:
    /// CTPH signatures that share no run of matching characters at least as long as the rolling
    /// window are treated as unrelated, since short coincidental overlaps between two otherwise
    /// unrelated hashes are common and not a meaningful similarity signal.</summary>
    private static int StringSimilarity(string a, string b)
    {
        if (a.Length == 0 || b.Length == 0)
            return 0;

        if (!HasSharedRun(a, b, RollingWindow))
            return 0;

        var distance = LevenshteinDistance(a, b);
        var maxLen = Math.Max(a.Length, b.Length);
        var similarity = (1.0 - (double)distance / maxLen) * 100.0;
        return Math.Max(0, (int)Math.Round(similarity));
    }

    private static bool HasSharedRun(string a, string b, int runLength)
    {
        if (a.Length < runLength || b.Length < runLength)
            return a == b;

        for (var i = 0; i <= a.Length - runLength; i++)
        {
            if (b.Contains(a.AsSpan(i, runLength), StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    private static int LevenshteinDistance(string a, string b)
    {
        var prev = new int[b.Length + 1];
        var curr = new int[b.Length + 1];
        for (var j = 0; j <= b.Length; j++)
            prev[j] = j;

        for (var i = 1; i <= a.Length; i++)
        {
            curr[0] = i;
            for (var j = 1; j <= b.Length; j++)
            {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                curr[j] = Math.Min(Math.Min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            (prev, curr) = (curr, prev);
        }

        return prev[b.Length];
    }
}
