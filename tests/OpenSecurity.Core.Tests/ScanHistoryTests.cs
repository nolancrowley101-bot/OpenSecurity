using OpenSecurity.Core.History;
using OpenSecurity.Core.Scanning;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class ScanHistoryTests : IDisposable
{
    private readonly string _historyFile = Path.Combine(Path.GetTempPath(), "OpenSecurityTests_" + Guid.NewGuid().ToString("N") + ".json");

    public void Dispose()
    {
        if (File.Exists(_historyFile))
            File.Delete(_historyFile);
    }

    private static ScanResult MakeResult(string path, Verdict verdict)
    {
        var result = new ScanResult { FilePath = path, FileSizeBytes = 10, Sha256 = new string('a', 64) };
        if (verdict != Verdict.Clean)
            result.Findings.Add(new ScanFinding("test", verdict, "test-finding", "detail", 50));
        return result;
    }

    [Fact]
    public void FromResults_SummarizesCountsCorrectly()
    {
        var results = new List<ScanResult>
        {
            MakeResult("a.txt", Verdict.Clean),
            MakeResult("b.txt", Verdict.Clean),
            MakeResult("c.exe", Verdict.Suspicious),
            MakeResult("d.exe", Verdict.Malicious),
        };

        var entry = ScanHistoryEntry.FromResults("C:\\target", results, 4.2);

        Assert.Equal(4, entry.FilesScanned);
        Assert.Equal(2, entry.CleanCount);
        Assert.Equal(1, entry.SuspiciousCount);
        Assert.Equal(1, entry.MaliciousCount);
        Assert.Equal(0, entry.ErrorCount);
        Assert.Equal(2, entry.FlaggedFiles.Count);
    }

    [Fact]
    public void Store_AppendAndList_RoundTrips()
    {
        var store = new ScanHistoryStore(_historyFile);
        var entry = ScanHistoryEntry.FromResults("C:\\target", new List<ScanResult> { MakeResult("a.exe", Verdict.Malicious) }, 1.0);

        store.Append(entry);
        var loaded = store.ListEntries();

        Assert.Single(loaded);
        Assert.Equal(entry.Id, loaded[0].Id);
        Assert.Equal("C:\\target", loaded[0].TargetPath);
    }

    [Fact]
    public void Store_ListEntries_OrdersNewestFirst()
    {
        var store = new ScanHistoryStore(_historyFile);
        var older = ScanHistoryEntry.FromResults("old", new List<ScanResult>(), 1.0);
        var newer = ScanHistoryEntry.FromResults("new", new List<ScanResult>(), 1.0);
        typeof(ScanHistoryEntry).GetProperty(nameof(ScanHistoryEntry.TimestampUtc))!.SetValue(older, DateTime.UtcNow.AddDays(-1));

        store.Append(older);
        store.Append(newer);

        var loaded = store.ListEntries();
        Assert.Equal("new", loaded[0].TargetPath);
        Assert.Equal("old", loaded[1].TargetPath);
    }
}
