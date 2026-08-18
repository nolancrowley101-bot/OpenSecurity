using System.Security.Cryptography;
using OpenSecurity.Core.Scanning;

namespace OpenSecurity.Core.Hashing;

public sealed class HashScanner
{
    private readonly HashSignatureDatabase _database;

    public HashScanner(HashSignatureDatabase database)
    {
        _database = database;
    }

    public static string ComputeSha256(Stream stream)
    {
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(stream);
        return Convert.ToHexStringLower(hashBytes);
    }

    public IEnumerable<ScanFinding> Scan(string sha256Hex)
    {
        if (_database.TryMatch(sha256Hex, out var label))
        {
            yield return new ScanFinding(
                Source: "hash",
                Verdict: Verdict.Malicious,
                Name: label,
                Detail: $"SHA-256 matches known-malicious signature {sha256Hex}",
                Score: 100);
        }
    }
}
