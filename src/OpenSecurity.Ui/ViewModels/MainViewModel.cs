using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Threading;
using OpenSecurity.Core.Hashing;
using OpenSecurity.Core.Heuristics;
using OpenSecurity.Core.Rules;
using OpenSecurity.Core.Scanning;

namespace OpenSecurity.Ui.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly ScanEngine _engine;
    private readonly DispatcherTimer _elapsedTimer;
    private Stopwatch? _stopwatch;

    private string _targetPath = "";
    private bool _isRecursive = true;
    private bool _isScanning;
    private string _statusText = "Ready.";
    private string _elapsedLabel = "";

    public MainViewModel(string hashDbPath, string rulesDir, string engineInfoLabel)
    {
        var hashDb = File.Exists(hashDbPath) ? HashSignatureDatabase.Load(hashDbPath) : HashSignatureDatabase.Empty();
        var rules = Directory.Exists(rulesDir) ? PatternRuleParser.ParseDirectory(rulesDir) : new List<PatternRule>();
        _engine = new ScanEngine(new HashScanner(hashDb), new PatternRuleEngine(rules), new HeuristicAnalyzer());
        EngineInfoLabel = engineInfoLabel;

        _elapsedTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(200) };
        _elapsedTimer.Tick += (_, _) => ElapsedLabel = _stopwatch is null ? "" : $"{_stopwatch.Elapsed.TotalSeconds:F1}s";
    }

    public ObservableCollection<ScanRowViewModel> Results { get; } = new();

    public string EngineInfoLabel { get; }

    public string TargetPath
    {
        get => _targetPath;
        set { _targetPath = value; OnPropertyChanged(); }
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

    public bool CanScan => !IsScanning && (File.Exists(TargetPath) || Directory.Exists(TargetPath));

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

    private int _cleanCount;
    private int _suspiciousCount;
    private int _maliciousCount;
    private int _errorCount;

    public int CleanCount { get => _cleanCount; private set { _cleanCount = value; OnPropertyChanged(); } }
    public int SuspiciousCount { get => _suspiciousCount; private set { _suspiciousCount = value; OnPropertyChanged(); } }
    public int MaliciousCount { get => _maliciousCount; private set { _maliciousCount = value; OnPropertyChanged(); } }
    public int ErrorCount { get => _errorCount; private set { _errorCount = value; OnPropertyChanged(); } }

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
        StatusText = "Scanning...";
        _stopwatch = Stopwatch.StartNew();
        _elapsedTimer.Start();

        var path = TargetPath;
        var recursive = IsRecursive;

        try
        {
            await Task.Run(() =>
            {
                var results = File.Exists(path)
                    ? new[] { _engine.ScanFile(path) }
                    : _engine.ScanDirectory(path, recursive);

                foreach (var result in results)
                {
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
            StatusText = $"Scanned {Results.Count} file(s) in {_stopwatch.Elapsed.TotalSeconds:F1}s.";
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

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
