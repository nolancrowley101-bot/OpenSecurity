using OpenSecurity.Core.History;

namespace OpenSecurity.Ui.ViewModels;

public sealed class HistoryRowViewModel
{
    public HistoryRowViewModel(ScanHistoryEntry entry)
    {
        Entry = entry;
    }

    public ScanHistoryEntry Entry { get; }

    public string TargetPath => Entry.TargetPath;
    public string TimestampLabel => Entry.TimestampUtc.ToLocalTime().ToString("g");
    public string SummaryLabel =>
        $"{Entry.FilesScanned} scanned - {Entry.CleanCount} clean, {Entry.SuspiciousCount} suspicious, {Entry.MaliciousCount} malicious, {Entry.ErrorCount} errors ({Entry.DurationSeconds:F1}s)";
    public IReadOnlyList<FlaggedFile> FlaggedFiles => Entry.FlaggedFiles;
    public bool HasFlaggedFiles => Entry.FlaggedFiles.Count > 0;
}
