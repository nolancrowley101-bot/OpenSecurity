using OpenSecurity.Core.Hashing;
using OpenSecurity.Core.Heuristics;
using OpenSecurity.Core.RealTime;
using OpenSecurity.Core.Rules;
using OpenSecurity.Core.Scanning;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class RealTimeProtectionServiceTests : IDisposable
{
    private readonly string _watchedFolder = Path.Combine(Path.GetTempPath(), "OpenSecurityTests_" + Guid.NewGuid().ToString("N"));

    private static readonly List<PatternRule> TestRules = PatternRuleParser.ParseText("""
        rule Test_Marker : Malicious
        {
            strings:
                $a = "TESTMARKER"
            condition:
                any of them
        }
        """);

    public RealTimeProtectionServiceTests() => Directory.CreateDirectory(_watchedFolder);

    public void Dispose()
    {
        if (Directory.Exists(_watchedFolder))
            Directory.Delete(_watchedFolder, recursive: true);
    }

    [Fact]
    public async Task DroppingAMatchingFile_TriggersThreatDetected_WithinDebounceWindow()
    {
        var engine = new ScanEngine(new HashScanner(HashSignatureDatabase.Empty()), new PatternRuleEngine(TestRules), new HeuristicAnalyzer());
        using var service = new RealTimeProtectionService(engine);

        var tcs = new TaskCompletionSource<ScanResult>();
        service.ThreatDetected += result => tcs.TrySetResult(result);

        service.Start(new[] { _watchedFolder });
        Assert.True(service.IsRunning);

        var filePath = Path.Combine(_watchedFolder, "dropped.txt");
        await File.WriteAllTextAsync(filePath, "contains TESTMARKER inside");

        var completed = await Task.WhenAny(tcs.Task, Task.Delay(TimeSpan.FromSeconds(10)));
        Assert.Same(tcs.Task, completed);

        var result = await tcs.Task;
        Assert.Equal(Verdict.Malicious, result.OverallVerdict);
        Assert.Equal(filePath, result.FilePath);
    }

    [Fact]
    public async Task DroppingAMatchingFile_UnderTheAppsOwnDirectory_DoesNotTriggerThreatDetected()
    {
        // Real AVs exclude their own install directory from real-time scanning - scanning your
        // own binaries is never meaningful, and this is also what stops OpenSecurity flagging
        // itself if a watched folder happens to contain its own install (e.g. Desktop).
        var engine = new ScanEngine(new HashScanner(HashSignatureDatabase.Empty()), new PatternRuleEngine(TestRules), new HeuristicAnalyzer());
        using var service = new RealTimeProtectionService(engine);

        var detected = false;
        service.ThreatDetected += _ => detected = true;

        var ownDirectory = AppContext.BaseDirectory;
        service.Start(new[] { ownDirectory });
        Assert.True(service.IsRunning);

        var filePath = Path.Combine(ownDirectory, "OpenSecurityTests_selfexclusion_" + Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            await File.WriteAllTextAsync(filePath, "contains TESTMARKER inside");
            await Task.Delay(TimeSpan.FromSeconds(4)); // longer than the debounce window, so a real detection would have fired by now

            Assert.False(detected);
        }
        finally
        {
            File.Delete(filePath);
        }
    }

    [Fact]
    public async Task RepeatedEventsForUnchangedContent_OnlyNotifyOnce_WithinCooldown()
    {
        var engine = new ScanEngine(new HashScanner(HashSignatureDatabase.Empty()), new PatternRuleEngine(TestRules), new HeuristicAnalyzer());
        using var service = new RealTimeProtectionService(engine);

        var detectionCount = 0;
        service.ThreatDetected += _ => Interlocked.Increment(ref detectionCount);

        service.Start(new[] { _watchedFolder });

        var filePath = Path.Combine(_watchedFolder, "dropped.txt");
        const string content = "contains TESTMARKER inside";
        await File.WriteAllTextAsync(filePath, content);
        await Task.Delay(TimeSpan.FromSeconds(4));
        Assert.Equal(1, detectionCount);

        // Re-write the exact same content - a save-without-edit, or a build tool touching the
        // file - must not re-alert, unlike a genuine content change which would get a new hash.
        await File.WriteAllTextAsync(filePath, content);
        await Task.Delay(TimeSpan.FromSeconds(4));

        Assert.Equal(1, detectionCount);
    }

    [Fact]
    public void Stop_DisablesWatchers()
    {
        var engine = new ScanEngine(new HashScanner(HashSignatureDatabase.Empty()), new PatternRuleEngine(new List<PatternRule>()), new HeuristicAnalyzer());
        using var service = new RealTimeProtectionService(engine);

        service.Start(new[] { _watchedFolder });
        Assert.True(service.IsRunning);

        service.Stop();
        Assert.False(service.IsRunning);
        Assert.Empty(service.WatchedFolders);
    }
}
