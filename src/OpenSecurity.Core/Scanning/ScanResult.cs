namespace OpenSecurity.Core.Scanning;

public sealed class ScanResult
{
    public required string FilePath { get; init; }
    public required long FileSizeBytes { get; init; }
    public required string Sha256 { get; init; }
    public List<ScanFinding> Findings { get; } = new();

    public Verdict OverallVerdict =>
        Findings.Count == 0
            ? Verdict.Clean
            : Findings.Max(f => f.Verdict);
}
