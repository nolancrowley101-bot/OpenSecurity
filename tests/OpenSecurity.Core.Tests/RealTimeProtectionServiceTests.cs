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
