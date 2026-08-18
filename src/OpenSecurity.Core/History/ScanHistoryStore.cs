using System.Text.Json;

namespace OpenSecurity.Core.History;

/// <summary>Append-only local log of past scans, capped so it can't grow unbounded over years of use.</summary>
public sealed class ScanHistoryStore
{
    private const int MaxEntries = 500;

    private readonly string _historyFilePath;

    public ScanHistoryStore(string historyFilePath)
    {
        _historyFilePath = historyFilePath;
    }

    public void Append(ScanHistoryEntry entry)
    {
        var entries = LoadAll();
        entries.Add(entry);

        if (entries.Count > MaxEntries)
            entries = entries.OrderByDescending(e => e.TimestampUtc).Take(MaxEntries).ToList();

        Save(entries);
    }

    public IReadOnlyList<ScanHistoryEntry> ListEntries() =>
        LoadAll().OrderByDescending(e => e.TimestampUtc).ToList();

    public void Clear() => Save(new List<ScanHistoryEntry>());

    private List<ScanHistoryEntry> LoadAll()
    {
        if (!File.Exists(_historyFilePath))
            return new List<ScanHistoryEntry>();

        var json = File.ReadAllText(_historyFilePath);
        return JsonSerializer.Deserialize<List<ScanHistoryEntry>>(json) ?? new List<ScanHistoryEntry>();
    }

    private void Save(List<ScanHistoryEntry> entries)
    {
        var directory = Path.GetDirectoryName(_historyFilePath);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        var json = JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_historyFilePath, json);
    }
}
