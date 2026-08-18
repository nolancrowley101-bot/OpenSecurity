using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Windows.Threading;
using OpenSecurity.Core.Hashing;
using OpenSecurity.Core.Heuristics;
using OpenSecurity.Core.History;
using OpenSecurity.Core.Quarantine;
using OpenSecurity.Core.Reporting;
using OpenSecurity.Core.Rules;
using OpenSecurity.Core.Scanning;
using OpenSecurity.Core.Scheduling;
using OpenSecurity.Core.Settings;
using OpenSecurity.Core.Updates;

namespace OpenSecurity.Ui.ViewModels;

public sealed partial class MainViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly string _hashDbPath;
    private readonly string _rulesDir;
    private readonly string _allowlistPath;
    private readonly SignatureUpdater _signatureUpdater = new();
    private readonly DispatcherTimer _elapsedTimer;
    private Stopwatch? _stopwatch;
    private ScanEngine _engine = null!;

    private string _targetPath = "";
    private bool _isRecursive = true;
    private bool _isScanning;
    private bool _isUpdatingSignatures;
    private string _statusText = "Ready.";
    private string _elapsedLabel = "";
    private string _updateFeedUrl = SignatureUpdater.SuggestedFeedUrl;

    public MainViewModel(
        string hashDbPath, string rulesDir, string allowlistPath, string quarantineDirectory,
        string historyFilePath, string settingsFilePath, Action<bool>? applyAutoStart = null)
    {
        _hashDbPath = hashDbPath;
        _rulesDir = rulesDir;
        _allowlistPath = allowlistPath;
        _quarantineManager = new QuarantineManager(quarantineDirectory);
        _historyStore = new ScanHistoryStore(historyFilePath);
        _scheduledScanManager = new ScheduledScanManager();
        _settingsFilePath = settingsFilePath;
        _settings = AppSettings.Load(settingsFilePath);
        _applyAutoStart = applyAutoStart;

        ReloadEngine();
        RefreshQuarantineEntries();
        RefreshHistory();
        InitializeRealTime();
        RefreshScheduleStatus();

        _elapsedTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(200) };
        _elapsedTimer.Tick += (_, _) => ElapsedLabel = _stopwatch is null ? "" : $"{_stopwatch.Elapsed.TotalSeconds:F1}s";
    }

    public ObservableCollection<ScanRowViewModel> Results { get; } = new();

    public string TargetPath
    {
        get => _targetPath;
        set { _targetPath = value; OnPropertyChanged(); OnPropertyChanged(nameof(CanScan)); }
    }

    public bool IsRecursive
    {
        get => _isRecursive;
        set { _isRecursive = value; OnPropertyChanged(); }
    }

    public bool IsScanning
    {
        get => _isScanning;
        private set { _isScanning = value; OnPropertyChanged(); OnPropertyChanged(nameof(CanScan)); }
    }

    public bool IsUpdatingSignatures
    {
        get => _isUpdatingSignatures;
        private set { _isUpdatingSignatures = value; OnPropertyChanged(); }
    }

    public string UpdateFeedUrl
    {
        get => _updateFeedUrl;
        set { _updateFeedUrl = value; OnPropertyChanged(); }
    }

    public bool CanScan => !IsScanning && (File.Exists(TargetPath) || Directory.Exists(TargetPath));
    public bool CanExport => !IsScanning && Results.Count > 0;

    public string StatusText
    {
        get => _statusText;
        private set { _statusText = value; OnPropertyChanged(); }
    }

    public string ElapsedLabel
    {
        get => _elapsedLabel;
        private set { _elapsedLabel = value; OnPropertyChanged(); }
    }

    public List<string> AvailableDrives { get; } = DriveInfo.GetDrives()
        .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
        .Select(d => d.RootDirectory.FullName)
        .ToList();

    private int _cleanCount;
    private int _suspiciousCount;
    private int _maliciousCount;
    private int _errorCount;
    private int _hashSignatureCount;
    private int _ruleCount;
    private int _allowlistCount;

    public int CleanCount { get => _cleanCount; private set { _cleanCount = value; OnPropertyChanged(); } }
    public int SuspiciousCount { get => _suspiciousCount; private set { _suspiciousCount = value; OnPropertyChanged(); } }
    public int MaliciousCount { get => _maliciousCount; private set { _maliciousCount = value; OnPropertyChanged(); } }
    public int ErrorCount { get => _errorCount; private set { _errorCount = value; OnPropertyChanged(); } }
    public int HashSignatureCount { get => _hashSignatureCount; private set { _hashSignatureCount = value; OnPropertyChanged(); } }
    public int RuleCount { get => _ruleCount; private set { _ruleCount = value; OnPropertyChanged(); } }
    public int AllowlistCount { get => _allowlistCount; private set { _allowlistCount = value; OnPropertyChanged(); } }

    public void ScanFullDrive(string driveRoot)
    {
        TargetPath = driveRoot;
        IsRecursive = true;
    }

    public async Task RunScanAsync()
    {
        if (!File.Exists(TargetPath) && !Directory.Exists(TargetPath))
        {
            StatusText = "Path not found.";
            return;
        }

        Results.Clear();
        CleanCount = 0;
        SuspiciousCount = 0;
        MaliciousCount = 0;
        ErrorCount = 0;

        IsScanning = true;
        OnPropertyChanged(nameof(CanExport));
        StatusText = "Scanning...";
        _stopwatch = Stopwatch.StartNew();
        _elapsedTimer.Start();

        var path = TargetPath;
        var recursive = IsRecursive;
        var scannedResults = new List<ScanResult>();

        try
        {
            await Task.Run(() =>
            {
                var results = File.Exists(path)
                    ? new[] { _engine.ScanFile(path) }
                    : _engine.ScanDirectory(path, recursive);

                foreach (var result in results)
                {
                    scannedResults.Add(result);
                    var row = new ScanRowViewModel(result);
                    System.Windows.Application.Current.Dispatcher.Invoke(() => AddResult(row));
                }
            });
        }
        finally
        {
            _stopwatch.Stop();
            _elapsedTimer.Stop();
            ElapsedLabel = $"{_stopwatch.Elapsed.TotalSeconds:F1}s";
            IsScanning = false;
            OnPropertyChanged(nameof(CanExport));
            StatusText = $"Scanned {Results.Count} file(s) in {_stopwatch.Elapsed.TotalSeconds:F1}s.";

            _historyStore.Append(ScanHistoryEntry.FromResults(path, scannedResults, _stopwatch.Elapsed.TotalSeconds));
            RefreshHistory();
        }
    }

    public void ExportReport(string path)
    {
        ReportExporter.Export(Results.Select(r => r.Result).ToList(), path);
        StatusText = $"Report exported to {path}.";
    }

    public async Task UpdateSignaturesAsync()
    {
        IsUpdatingSignatures = true;
        StatusText = $"Fetching signature feed...";
        try
        {
            var added = await _signatureUpdater.UpdateFromUrlAsync(UpdateFeedUrl, _hashDbPath);
            ReloadEngine();
            StatusText = $"Added {added} new hash signature(s) from the feed.";
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            StatusText = $"Signature update failed: {ex.Message}";
        }
        finally
        {
            IsUpdatingSignatures = false;
        }
    }

    private void ReloadEngine()
    {
        var hashDb = File.Exists(_hashDbPath) ? HashSignatureDatabase.Load(_hashDbPath) : HashSignatureDatabase.Empty();
        var rules = Directory.Exists(_rulesDir) ? PatternRuleParser.ParseDirectory(_rulesDir) : new List<PatternRule>();
        var allowlist = File.Exists(_allowlistPath) ? HashSignatureDatabase.Load(_allowlistPath) : HashSignatureDatabase.Empty();

        _engine = new ScanEngine(new HashScanner(hashDb), new PatternRuleEngine(rules), new HeuristicAnalyzer(), allowlist);
        HashSignatureCount = hashDb.Count;
        RuleCount = rules.Count;
        AllowlistCount = allowlist.Count;

        RestartRealTimeProtectionIfRunning();
    }

    private void DecrementCount(Verdict verdict)
    {
        switch (verdict)
        {
            case Verdict.Clean: CleanCount--; break;
            case Verdict.Suspicious: SuspiciousCount--; break;
            case Verdict.Malicious: MaliciousCount--; break;
            case Verdict.Error: ErrorCount--; break;
        }
    }

    private void AddResult(ScanRowViewModel row)
    {
        Results.Add(row);
        switch (row.Verdict)
        {
            case Verdict.Clean: CleanCount++; break;
            case Verdict.Suspicious: SuspiciousCount++; break;
            case Verdict.Malicious: MaliciousCount++; break;
            case Verdict.Error: ErrorCount++; break;
        }
    }

    public void Dispose()
    {
        _realTimeService?.Dispose();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
