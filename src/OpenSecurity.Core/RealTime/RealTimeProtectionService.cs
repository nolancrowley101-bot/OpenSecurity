using System.Collections.Concurrent;
using OpenSecurity.Core.Scanning;

namespace OpenSecurity.Core.RealTime;

/// <summary>
/// User-mode on-access scanning: watches a set of folders for new/changed files and scans them
/// automatically. Not a kernel-mode filter driver - it can't intercept execution the way a real
/// AV's minifilter does, but it catches files as they land in the folders that matter most
/// (Downloads, Desktop, temp) without needing a signed driver or elevated privileges.
/// </summary>
public sealed class RealTimeProtectionService : IDisposable
{
    private static readonly TimeSpan DebounceDelay = TimeSpan.FromSeconds(2);
    private const int StabilityRetries = 5;
    private static readonly TimeSpan StabilityRetryDelay = TimeSpan.FromMilliseconds(500);

    private readonly ScanEngine _engine;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _pending = new();

    public RealTimeProtectionService(ScanEngine engine)
    {
        _engine = engine;
    }

    public bool IsRunning { get; private set; }
    public IReadOnlyList<string> WatchedFolders { get; private set; } = Array.Empty<string>();

    /// <summary>Fired for every file that gets scanned, regardless of verdict.</summary>
    public event Action<ScanResult>? FileScanned;

    /// <summary>Fired only when a scanned file comes back Suspicious or Malicious.</summary>
    public event Action<ScanResult>? ThreatDetected;

    public void Start(IEnumerable<string> folders)
    {
        Stop();

        var list = folders.Where(Directory.Exists).Distinct().ToList();
        WatchedFolders = list;

        foreach (var folder in list)
        {
            var watcher = new FileSystemWatcher(folder)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime
            };
            watcher.Created += OnFileEvent;
            watcher.Changed += OnFileEvent;
            watcher.Renamed += OnFileEvent;
            watcher.Error += (_, _) => { }; // e.g. internal buffer overflow on a burst of events - keep watching
            watcher.EnableRaisingEvents = true;
            _watchers.Add(watcher);
        }

        IsRunning = _watchers.Count > 0;
    }

    public void Stop()
    {
        foreach (var watcher in _watchers)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
        }
        _watchers.Clear();

        foreach (var cts in _pending.Values)
            cts.Cancel();
        _pending.Clear();

        IsRunning = false;
        WatchedFolders = Array.Empty<string>();
    }

    private void OnFileEvent(object sender, FileSystemEventArgs e)
    {
        if (Directory.Exists(e.FullPath))
            return;

        ScheduleScan(e.FullPath);
    }

    private void ScheduleScan(string path)
    {
        var cts = new CancellationTokenSource();
        _pending.AddOrUpdate(path, cts, (_, previous) =>
        {
            previous.Cancel();
            return cts;
        });

        _ = RunDebouncedScanAsync(path, cts);
    }

    private async Task RunDebouncedScanAsync(string path, CancellationTokenSource cts)
    {
        try
        {
            await Task.Delay(DebounceDelay, cts.Token);

            if (!await WaitUntilStableAsync(path, cts.Token))
                return;

            var result = _engine.ScanFile(path);
            FileScanned?.Invoke(result);
            if (result.OverallVerdict is Verdict.Suspicious or Verdict.Malicious)
                ThreatDetected?.Invoke(result);
        }
        catch (TaskCanceledException)
        {
            // superseded by a newer event for the same path, or Stop() was called
        }
        finally
        {
            _pending.TryRemove(path, out _);
        }
    }

    private static async Task<bool> WaitUntilStableAsync(string path, CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < StabilityRetries; attempt++)
        {
            if (!File.Exists(path))
                return false;

            try
            {
                using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None);
                return true;
            }
            catch (IOException)
            {
                await Task.Delay(StabilityRetryDelay, cancellationToken);
            }
        }
        return false;
    }

    public void Dispose() => Stop();
}
