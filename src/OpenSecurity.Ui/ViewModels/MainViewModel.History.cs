using System.Collections.ObjectModel;
using OpenSecurity.Core.History;

namespace OpenSecurity.Ui.ViewModels;

public sealed partial class MainViewModel
{
    private readonly ScanHistoryStore _historyStore;

    public ObservableCollection<HistoryRowViewModel> HistoryEntries { get; } = new();

    private void RefreshHistory()
    {
        HistoryEntries.Clear();
        foreach (var entry in _historyStore.ListEntries())
            HistoryEntries.Add(new HistoryRowViewModel(entry));
    }
}
