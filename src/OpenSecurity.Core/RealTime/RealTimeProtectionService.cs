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

    // Real AVs exclude their own install directory from real-time scanning - scanning your own
    // security tool's binaries is never meaningful, and self-contained single-file executables
    // (bundled/compressed assemblies appended to the exe) structurally resemble what a packer
    // does, which is exactly the shape the heuristic engine looks for. Without this, a watched
    // folder that happens to contain OpenSecurity itself (e.g. Desktop, if that's where it's
    // installed or built from) would have OpenSecurity flag itself.
    private static readonly string SelfDirectory = Path.GetFullPath(AppContext.BaseDirectory);

    // Repeated FileSystemWatcher events for the same unchanged content (a save-without-edit, a
    // build tool touching a file's timestamp, antivirus/indexing activity) shouldn't re-alert
    // every time - only a genuine content change (different hash) should. Cooldown, not a
    // permanent suppression, so a file that's flagged, fixed, and re-flagged still gets reported.
    private static readonly TimeSpan NotificationCooldown = TimeSpan.FromMinutes(5);

    private readonly ScanEngine _engine;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _pending = new();
    private readonly ConcurrentDictionary<string, (string Sha256, DateTime NotifiedAtUtc)> _recentNotifications = new();

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
        _recentNotifications.Clear();

        IsRunning = false;
        WatchedFolders = Array.Empty<string>();
    }

    private void OnFileEvent(object sender, FileSystemEventArgs e)
    {
        if (Directory.Exists(e.FullPath))
            return;

        if (IsUnderSelfDirectory(e.FullPath))
            return;

        ScheduleScan(e.FullPath);
    }

    private static bool IsUnderSelfDirectory(string path)
    {
        try
        {
            var fullPath = Path.GetFullPath(path);
            return fullPath.StartsWith(SelfDirectory, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or PathTooLongException or NotSupportedException)
        {
            return false;
        }
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
            if (result.OverallVerdict is Verdict.Suspicious or Verdict.Malicious && !WasRecentlyNotified(path, result.Sha256))
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

    /// <summary>True if this exact path+hash combination already triggered a notification within
    /// the cooldown window - i.e. the content hasn't actually changed since we last alerted on it.
    /// Updates the tracked timestamp either way, so a fresh cooldown starts from this check.</summary>
    private bool WasRecentlyNotified(string path, string sha256)
    {
        var now = DateTime.UtcNow;
        var alreadyNotified = _recentNotifications.TryGetValue(path, out var last)
            && last.Sha256 == sha256
            && now - last.NotifiedAtUtc < NotificationCooldown;

        _recentNotifications[path] = (sha256, now);
        return alreadyNotified;
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
