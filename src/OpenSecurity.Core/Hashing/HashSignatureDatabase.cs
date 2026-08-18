namespace OpenSecurity.Core.Hashing;

/// <summary>
/// Known-bad SHA-256 hashes loaded from a flat text file, one entry per line:
///   &lt;64-char sha256 hex&gt;  &lt;label&gt;
/// Blank lines and lines starting with '#' are ignored.
/// </summary>
public sealed class HashSignatureDatabase
{
    private readonly Dictionary<string, string> _hashToLabel;

    private HashSignatureDatabase(Dictionary<string, string> hashToLabel)
    {
        _hashToLabel = hashToLabel;
    }

    public int Count => _hashToLabel.Count;

    public static HashSignatureDatabase Load(string path)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (!File.Exists(path))
            return new HashSignatureDatabase(map);

        foreach (var rawLine in File.ReadLines(path))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            var parts = line.Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries);
            var hash = parts[0].Trim();
            if (hash.Length != 64)
                continue;

            var label = parts.Length > 1 ? parts[1].Trim() : "known-malicious";
            map[hash] = label;
        }

        return new HashSignatureDatabase(map);
    }

    public static HashSignatureDatabase Empty() => new(new Dictionary<string, string>());

    public bool TryMatch(string sha256Hex, out string label) => _hashToLabel.TryGetValue(sha256Hex, out label!);
}
