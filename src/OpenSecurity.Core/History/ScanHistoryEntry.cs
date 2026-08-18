using OpenSecurity.Core.Scanning;

namespace OpenSecurity.Core.History;

public sealed record FlaggedFile(string FilePath, string Verdict, string Sha256, string TopFinding);

public sealed class ScanHistoryEntry
{
    public required string Id { get; init; }
    public required DateTime TimestampUtc { get; init; }
    public required string TargetPath { get; init; }
    public required int FilesScanned { get; init; }
    public required int CleanCount { get; init; }
    public required int SuspiciousCount { get; init; }
    public required int MaliciousCount { get; init; }
    public required int ErrorCount { get; init; }
    public required double DurationSeconds { get; init; }
    public List<FlaggedFile> FlaggedFiles { get; init; } = new();

    public static ScanHistoryEntry FromResults(string targetPath, IReadOnlyList<ScanResult> results, double durationSeconds)
    {
        var entry = new ScanHistoryEntry
        {
            Id = Guid.NewGuid().ToString("N"),
            TimestampUtc = DateTime.UtcNow,
            TargetPath = targetPath,
            FilesScanned = results.Count,
            CleanCount = results.Count(r => r.OverallVerdict == Verdict.Clean),
            SuspiciousCount = results.Count(r => r.OverallVerdict == Verdict.Suspicious),
            MaliciousCount = results.Count(r => r.OverallVerdict == Verdict.Malicious),
            ErrorCount = results.Count(r => r.OverallVerdict == Verdict.Error),
            DurationSeconds = durationSeconds
        };

        foreach (var result in results.Where(r => r.OverallVerdict is Verdict.Suspicious or Verdict.Malicious))
        {
            var topFinding = result.Findings.OrderByDescending(f => f.Score).FirstOrDefault();
            entry.FlaggedFiles.Add(new FlaggedFile(result.FilePath, result.OverallVerdict.ToString(), result.Sha256, topFinding?.Name ?? ""));
        }

        return entry;
    }
}
