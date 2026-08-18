namespace OpenSecurity.Core.Heuristics;

public static class Entropy
{
    /// <summary>Shannon entropy in bits per byte, 0.0 (uniform/empty) to 8.0 (fully random).</summary>
    public static double Shannon(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
            return 0.0;

        Span<int> counts = stackalloc int[256];
        foreach (var b in data)
            counts[b]++;

        var entropy = 0.0;
        var length = (double)data.Length;
        foreach (var count in counts)
        {
            if (count == 0)
                continue;
            var p = count / length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
