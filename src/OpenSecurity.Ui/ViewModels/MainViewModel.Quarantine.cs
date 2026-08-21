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
        try
        {
            var reason = string.Join("; ", row.Findings.Select(f => f.Name));
            _quarantineManager.Quarantine(row.FilePath, row.Sha256, reason);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The file can legitimately be gone or locked (moved/deleted since the scan ran,
            // still open in another program) - report it instead of crashing on a plain
            // synchronous WPF event handler, which has nothing above it to catch this either.
            StatusText = $"Could not quarantine {Path.GetFileName(row.FilePath)}: {ex.Message}";
            return;
        }

        Results.Remove(row);
        _allResults.Remove(row);
        DecrementCount(row.Verdict);
        OnPropertyChanged(nameof(CanExport));
        RefreshQuarantineEntries();
        StatusText = $"Quarantined {Path.GetFileName(row.FilePath)}.";
    }

    public void AllowlistResult(ScanRowViewModel row)
    {
        HashSignatureDatabase.AppendNewEntries(_allowlistPath, new[] { (row.Sha256, "user-allowlisted") });
        Results.Remove(row);
        _allResults.Remove(row);
        DecrementCount(row.Verdict);
        OnPropertyChanged(nameof(CanExport));
        ReloadEngine();
        StatusText = $"Added {Path.GetFileName(row.FilePath)} to the allowlist - it won't be flagged by rules/heuristics again.";
    }

    public void RestoreQuarantineEntry(QuarantineRowViewModel entry)
    {
        try
        {
            _quarantineManager.Restore(entry.Id);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            StatusText = $"Could not restore {Path.GetFileName(entry.OriginalPath)}: {ex.Message}";
            return;
        }

        RefreshQuarantineEntries();
        StatusText = $"Restored {Path.GetFileName(entry.OriginalPath)}.";
    }

    public void DeleteQuarantineEntry(QuarantineRowViewModel entry)
    {
        try
        {
            _quarantineManager.Delete(entry.Id);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            StatusText = $"Could not delete {Path.GetFileName(entry.OriginalPath)}: {ex.Message}";
            return;
        }

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
