namespace OpenSecurity.Core.Quarantine;

public sealed class QuarantineEntry
{
    public required string Id { get; init; }
    public required string OriginalPath { get; init; }
    public required string QuarantinedFileName { get; init; }
    public required string Sha256 { get; init; }
    public required string Reason { get; init; }
    public required DateTime TimestampUtc { get; init; }
}
