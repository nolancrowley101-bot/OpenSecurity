using System.Text.RegularExpressions;

namespace OpenSecurity.Core.Updates;

/// <summary>
/// Parses a plaintext hash feed into (hash, label) pairs. Tolerant of common feed formats:
/// bare hashes one per line, CSV rows with a sha256 column, "hash  label" pairs, and
/// comment lines starting with # (used by feeds like abuse.ch's MalwareBazaar exports).
/// Pure text-in/data-out so it can be unit tested without a network call.
/// </summary>
public static class SignatureFeedParser
{
    private static readonly Regex Sha256Regex = new("\\b[a-fA-F0-9]{64}\\b", RegexOptions.Compiled);

    public static IEnumerable<(string Hash, string Label)> Parse(string feedText)
    {
        foreach (var rawLine in feedText.Replace("\r\n", "\n").Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            var match = Sha256Regex.Match(line);
            if (!match.Success)
                continue;

            var hash = match.Value.ToLowerInvariant();
            var label = ExtractLabel(line, match) is { Length: > 0 } candidate ? candidate : "feed-import";
            yield return (hash, label);
        }
    }

    private static string? ExtractLabel(string line, Match hashMatch)
    {
        // CSV-style feeds (abuse.ch MalwareBazaar): "first_seen","sha256_hash","md5_hash",...,"signature",...
        if (line.Contains(','))
        {
            var fields = line.Split(',').Select(f => f.Trim().Trim('"')).Where(f => f.Length > 0).ToArray();
            var nonHashFields = fields.Where(f => !f.Equals(hashMatch.Value, StringComparison.OrdinalIgnoreCase)).ToArray();
            return nonHashFields.FirstOrDefault(f => f.Length is > 2 and < 64 && !Sha256Regex.IsMatch(f));
        }

        var remainder = line.Remove(hashMatch.Index, hashMatch.Length).Trim(' ', ',', '\t');
        return remainder.Length > 0 ? remainder : null;
    }
}
