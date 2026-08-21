using System.Collections.ObjectModel;
using System.IO;
using OpenSecurity.Core.RealTime;
using OpenSecurity.Core.Scanning;
using OpenSecurity.Core.Settings;

namespace OpenSecurity.Ui.ViewModels;

public sealed partial class MainViewModel
{
    private const int MaxRealTimeDetections = 200;

    private RealTimeProtectionService? _realTimeService;
    private bool _isRealTimeProtectionEnabled;

    public ObservableCollection<string> WatchedFolders { get; } = new();
    public ObservableCollection<ScanRowViewModel> RealTimeDetections { get; } = new();

    public bool IsRealTimeProtectionEnabled
    {
        get => _isRealTimeProtectionEnabled;
        set
        {
            if (value)
                StartRealTimeProtection();
            else
                StopRealTimeProtection();
        }
    }

    public bool AutoQuarantineOnDetect
    {
        get => _settings.AutoQuarantineOnDetect;
        set
        {
            _settings.AutoQuarantineOnDetect = value;
            _settings.Save(_settingsFilePath);
            OnPropertyChanged();
        }
    }

    private void InitializeRealTime()
    {
        var folders = _settings.WatchedFolders.Count > 0 ? _settings.WatchedFolders : AppSettings.DefaultWatchedFolders();
        foreach (var folder in folders)
            WatchedFolders.Add(folder);

        if (_settings.RealTimeProtectionEnabled)
            StartRealTimeProtection();
    }

    public void AddWatchedFolder(string folder)
    {
        if (!Directory.Exists(folder) || WatchedFolders.Contains(folder, StringComparer.OrdinalIgnoreCase))
            return;

        WatchedFolders.Add(folder);
        PersistWatchedFolders();

        if (IsRealTimeProtectionEnabled)
            RestartRealTimeProtectionIfRunning();
    }

    public void RemoveWatchedFolder(string folder)
    {
        WatchedFolders.Remove(folder);
        PersistWatchedFolders();

        if (IsRealTimeProtectionEnabled)
            RestartRealTimeProtectionIfRunning();
    }

    private void StartRealTimeProtection()
    {
        _realTimeService?.Dispose();
        _realTimeService = new RealTimeProtectionService(_engine);
        _realTimeService.ThreatDetected += OnRealTimeThreatDetected;
        _realTimeService.Start(WatchedFolders);

        _isRealTimeProtectionEnabled = true;
        _settings.RealTimeProtectionEnabled = true;
        _settings.WatchedFolders = WatchedFolders.ToList();
        _settings.Save(_settingsFilePath);

        OnPropertyChanged(nameof(IsRealTimeProtectionEnabled));
        StatusText = $"Real-time protection enabled, watching {WatchedFolders.Count} folder(s).";
    }

    private void StopRealTimeProtection()
    {
        _realTimeService?.Dispose();
        _realTimeService = null;

        _isRealTimeProtectionEnabled = false;
        _settings.RealTimeProtectionEnabled = false;
        _settings.Save(_settingsFilePath);

        OnPropertyChanged(nameof(IsRealTimeProtectionEnabled));
        StatusText = "Real-time protection disabled.";
    }

    private void RestartRealTimeProtectionIfRunning()
    {
        if (_realTimeService is null)
            return;

        _realTimeService.Dispose();
        _realTimeService = new RealTimeProtectionService(_engine);
        _realTimeService.ThreatDetected += OnRealTimeThreatDetected;
        _realTimeService.Start(WatchedFolders);
    }

    private void OnRealTimeThreatDetected(ScanResult result)
    {
        // No kernel-mode filter driver means execution itself can't be blocked the way
        // SmartScreen or a real AV's minifilter does - but a Malicious-verdict file (the
        // highest-confidence tier: an exact hash match, or heuristics crossing the malicious
        // threshold on multiple combined signals) can be moved out of reach before the user
        // gets a chance to double-click it. Quarantine is reversible via the Quarantine tab,
        // so this errs toward acting rather than just logging a detection nobody may notice.
        string? quarantineFailure = null;
        if (_settings.AutoQuarantineOnDetect && result.OverallVerdict == Verdict.Malicious)
        {
            try
            {
                var reason = string.Join("; ", result.Findings.Select(f => f.Name));
                _quarantineManager.Quarantine(result.FilePath, result.Sha256, reason);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // The file can legitimately be gone or locked by the time this runs (another
                // process still writing it, a build tool rebuilding it, the user having already
                // deleted it) - this runs on a background thread with nothing above it to catch
                // an unhandled exception, so a real I/O failure here must not go unhandled.
                quarantineFailure = ex.Message;
            }
        }

        System.Windows.Application.Current.Dispatcher.Invoke(() =>
        {
            RealTimeDetections.Insert(0, new ScanRowViewModel(result));
            while (RealTimeDetections.Count > MaxRealTimeDetections)
                RealTimeDetections.RemoveAt(RealTimeDetections.Count - 1);

            if (quarantineFailure is not null)
                RealTimeQuarantineFailed?.Invoke(result.FilePath, quarantineFailure);

            RealTimeThreatDetected?.Invoke(result);
        });
    }

    private void PersistWatchedFolders()
    {
        _settings.WatchedFolders = WatchedFolders.ToList();
        _settings.Save(_settingsFilePath);
    }

    /// <summary>Lets the UI pop a tray balloon/notification without the view model knowing about WinForms.</summary>
    public event Action<ScanResult>? RealTimeThreatDetected;

    /// <summary>Fired when auto-quarantining a real-time detection fails (file locked/already
    /// gone) - the detection itself is still reported via <see cref="RealTimeThreatDetected"/>,
    /// this just surfaces that the follow-up quarantine action specifically didn't succeed.</summary>
    public event Action<string, string>? RealTimeQuarantineFailed;
}
