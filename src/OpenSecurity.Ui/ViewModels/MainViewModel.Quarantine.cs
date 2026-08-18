using System.Collections.ObjectModel;
using System.IO;
using OpenSecurity.Core.Hashing;
using OpenSecurity.Core.Quarantine;

namespace OpenSecurity.Ui.ViewModels;

public sealed partial class MainViewModel
{
    private readonly QuarantineManager _quarantineManager;

    public ObservableCollection<QuarantineRowViewModel> QuarantineEntries { get; } = new();

    public void QuarantineResult(ScanRowViewModel row)
    {
        var reason = string.Join("; ", row.Findings.Select(f => f.Name));
        _quarantineManager.Quarantine(row.FilePath, row.Sha256, reason);
        Results.Remove(row);
        DecrementCount(row.Verdict);
        OnPropertyChanged(nameof(CanExport));
        RefreshQuarantineEntries();
        StatusText = $"Quarantined {Path.GetFileName(row.FilePath)}.";
    }

    public void AllowlistResult(ScanRowViewModel row)
    {
        HashSignatureDatabase.AppendNewEntries(_allowlistPath, new[] { (row.Sha256, "user-allowlisted") });
        Results.Remove(row);
        DecrementCount(row.Verdict);
        OnPropertyChanged(nameof(CanExport));
        ReloadEngine();
        StatusText = $"Added {Path.GetFileName(row.FilePath)} to the allowlist - it won't be flagged by rules/heuristics again.";
    }

    public void RestoreQuarantineEntry(QuarantineRowViewModel entry)
    {
        _quarantineManager.Restore(entry.Id);
        RefreshQuarantineEntries();
        StatusText = $"Restored {Path.GetFileName(entry.OriginalPath)}.";
    }

    public void DeleteQuarantineEntry(QuarantineRowViewModel entry)
    {
        _quarantineManager.Delete(entry.Id);
        RefreshQuarantineEntries();
        StatusText = $"Permanently deleted quarantined file (was {Path.GetFileName(entry.OriginalPath)}).";
    }

    private void RefreshQuarantineEntries()
    {
        QuarantineEntries.Clear();
        foreach (var entry in _quarantineManager.ListEntries())
            QuarantineEntries.Add(new QuarantineRowViewModel(entry));
    }
}
