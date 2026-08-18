using System.Collections.ObjectModel;
using System.IO;
using OpenSecurity.Core.RealTime;
using OpenSecurity.Core.Scanning;
using OpenSecurity.Core.Settings;

namespace OpenSecurity.Ui.ViewModels;

public sealed partial class MainViewModel
{
    private const int MaxRealTimeDetections = 200;

    private readonly string _settingsFilePath;
    private readonly AppSettings _settings;
    private readonly Action<bool>? _applyAutoStart;
    private RealTimeProtectionService? _realTimeService;
    private bool _isRealTimeProtectionEnabled;
    private bool _startWithWindows;

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

    public bool StartWithWindows
    {
        get => _startWithWindows;
        set
        {
            _startWithWindows = value;
            _settings.StartWithWindows = value;
            _settings.Save(_settingsFilePath);
            _applyAutoStart?.Invoke(value);
            OnPropertyChanged();
        }
    }

    private void InitializeRealTime()
    {
        var folders = _settings.WatchedFolders.Count > 0 ? _settings.WatchedFolders : AppSettings.DefaultWatchedFolders();
        foreach (var folder in folders)
            WatchedFolders.Add(folder);

        _startWithWindows = _settings.StartWithWindows;

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
        System.Windows.Application.Current.Dispatcher.Invoke(() =>
        {
            RealTimeDetections.Insert(0, new ScanRowViewModel(result));
            while (RealTimeDetections.Count > MaxRealTimeDetections)
                RealTimeDetections.RemoveAt(RealTimeDetections.Count - 1);

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
}
