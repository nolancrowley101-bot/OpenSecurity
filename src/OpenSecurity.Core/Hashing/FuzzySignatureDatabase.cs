namespace OpenSecurity.Core.Hashing;

/// <summary>
/// Known-bad fuzzy (CTPH) hashes loaded from a flat text file, one entry per line:
///   &lt;blocksize:hash1:hash2&gt;  &lt;label&gt;
/// Blank lines and lines starting with '#' are ignored.
///
/// <see cref="FuzzyHash.Similarity"/> only produces a non-zero score when two signatures' block
/// sizes match or are exactly double one another, so entries are bucketed by block size up front -
/// a scanned file only ever needs comparing against the (usually small) subset of the database at
/// a compatible scale, not the whole thing.
/// </summary>
public sealed class FuzzySignatureDatabase
{
    private readonly Dictionary<int, List<(string Signature, string Label)>> _byBlockSize;

    private FuzzySignatureDatabase(Dictionary<int, List<(string, string)>> byBlockSize)
    {
        _byBlockSize = byBlockSize;
    }

    public int Count => _byBlockSize.Values.Sum(v => v.Count);

    public static FuzzySignatureDatabase Load(string path)
    {
        var byBlockSize = new Dictionary<int, List<(string, string)>>();
        if (!File.Exists(path))
            return new FuzzySignatureDatabase(byBlockSize);

        foreach (var rawLine in File.ReadLines(path))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            var parts = line.Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries);
            var signature = parts[0].Trim();
            var blockSizePart = signature.Split(':', 2)[0];
            if (!int.TryParse(blockSizePart, out var blockSize))
                continue;

            var label = parts.Length > 1 ? parts[1].Trim() : "known-malicious";
            if (!byBlockSize.TryGetValue(blockSize, out var list))
                byBlockSize[blockSize] = list = new List<(string, string)>();
            list.Add((signature, label));
        }

        return new FuzzySignatureDatabase(byBlockSize);
    }

    public static FuzzySignatureDatabase Empty() => new(new Dictionary<int, List<(string, string)>>());

    /// <summary>Returns every database entry whose similarity to <paramref name="signature"/>
    /// meets or exceeds <paramref name="threshold"/>, ordered highest-score first. Only compares
    /// against entries at a compatible block size (see class remarks).</summary>
    public IEnumerable<(string Label, int Score)> FindSimilar(string signature, int threshold)
    {
        var blockSizePart = signature.Split(':', 2)[0];
        if (!int.TryParse(blockSizePart, out var blockSize))
            yield break;

        var candidates = new List<(string Signature, string Label)>();
        foreach (var candidateBlockSize in new[] { blockSize, blockSize / 2, blockSize * 2 })
        {
            if (candidateBlockSize > 0 && _byBlockSize.TryGetValue(candidateBlockSize, out var list))
                candidates.AddRange(list);
        }

        foreach (var (candidateSignature, label) in candidates)
        {
            var score = FuzzyHash.Similarity(signature, candidateSignature);
            if (score >= threshold)
                yield return (label, score);
        }
    }
}
