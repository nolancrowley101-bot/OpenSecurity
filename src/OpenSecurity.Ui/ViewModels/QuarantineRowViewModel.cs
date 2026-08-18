using OpenSecurity.Core.Quarantine;

namespace OpenSecurity.Ui.ViewModels;

public sealed class QuarantineRowViewModel
{
    public QuarantineRowViewModel(QuarantineEntry entry)
    {
        Entry = entry;
    }

    public QuarantineEntry Entry { get; }

    public string Id => Entry.Id;
    public string OriginalPath => Entry.OriginalPath;
    public string Reason => Entry.Reason;
    public string TimestampLabel => Entry.TimestampUtc.ToLocalTime().ToString("g");
}
