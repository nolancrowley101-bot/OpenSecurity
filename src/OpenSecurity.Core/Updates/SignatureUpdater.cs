using OpenSecurity.Core.Hashing;

namespace OpenSecurity.Core.Updates;

/// <summary>
/// Pulls a plaintext hash feed (e.g. abuse.ch MalwareBazaar's SHA-256 export) from any URL
/// and merges new entries into the local hash signature database.
/// </summary>
public sealed class SignatureUpdater
{
    public const string SuggestedFeedUrl = "https://bazaar.abuse.ch/export/txt/sha256/full/";

    private readonly HttpClient _httpClient;

    public SignatureUpdater(HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromMinutes(3) };
    }

    public async Task<int> UpdateFromUrlAsync(string url, string hashDbPath, CancellationToken cancellationToken = default)
    {
        var feedText = await _httpClient.GetStringAsync(url, cancellationToken);
        var entries = SignatureFeedParser.Parse(feedText);
        return HashSignatureDatabase.AppendNewEntries(hashDbPath, entries);
    }
}
