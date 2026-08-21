using System.IO;
using System.Windows;
using System.Windows.Threading;
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;
using OpenSecurity.Core;
using OpenSecurity.Ui.Services;
using OpenSecurity.Ui.ViewModels;

namespace OpenSecurity.Ui;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ShutdownMode = ShutdownMode.OnExplicitShutdown;

        // Nothing before this point should have been able to crash the whole app to desktop on
        // a bug in one scan/update/quarantine action - three async void event handlers (Scan,
        // ScanDrive, UpdateSignatures) plus the Explorer "--scan" launch path all had no
        // exception handling above them, so any exception anywhere in the scan/heuristics/
        // quarantine pipeline was an instant, unrecoverable crash. This is the safety net: log
        // what happened, tell the user, and keep the app alive instead of vanishing.
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnAppDomainUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;

        var appDir = AppContext.BaseDirectory;
        var hashDbPath = DefaultPaths.FindUp(appDir, Path.Combine("signatures", "hashes.txt")) ?? Path.Combine(appDir, "signatures", "hashes.txt");
        var rulesDir = DefaultPaths.FindUp(appDir, "rules") ?? Path.Combine(appDir, "rules");
        var allowlistPath = DefaultPaths.FindUp(appDir, Path.Combine("signatures", "allowlist.txt")) ?? Path.Combine(appDir, "signatures", "allowlist.txt");
        var archivePasswordsPath = DefaultPaths.FindUp(appDir, Path.Combine("signatures", "archive_passwords.txt")) ?? Path.Combine(appDir, "signatures", "archive_passwords.txt");
        var fuzzyHashesPath = DefaultPaths.FindUp(appDir, Path.Combine("signatures", "fuzzy_hashes.txt")) ?? Path.Combine(appDir, "signatures", "fuzzy_hashes.txt");

        var viewModel = new MainViewModel(
            hashDbPath, rulesDir, allowlistPath, archivePasswordsPath, fuzzyHashesPath,
            DefaultPaths.DefaultQuarantineDirectory(),
            DefaultPaths.DefaultHistoryFilePath(),
            DefaultPaths.DefaultSettingsFilePath(),
            AutoStartManager.SetEnabled);

        var scanArgIndex = Array.IndexOf(e.Args, "--scan");
        var scanPath = scanArgIndex >= 0 && scanArgIndex + 1 < e.Args.Length ? e.Args[scanArgIndex + 1] : null;
        var startMinimized = e.Args.Contains("--minimized");

        var window = new MainWindow(viewModel, startMinimized && scanPath is null);

        if (scanPath is not null)
        {
            viewModel.TargetPath = scanPath;
            window.Show();
            window.Activate();
            _ = viewModel.RunScanAsync();
        }
        else if (!startMinimized)
        {
            window.Show();
        }
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        LogCrash("UI thread", e.Exception);
        MessageBox.Show(
            $"OpenSecurity hit an unexpected error and recovered:\n\n{e.Exception.Message}\n\nDetails were written to {CrashLogPath()}.",
            "OpenSecurity - error", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true; // without this, WPF terminates the process
    }

    private void OnAppDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        // Background-thread exceptions (e.g. inside a real-time protection scan) can't be
        // stopped from terminating the process here, but logging them is still worth doing -
        // without this, they vanish with no trace of what actually happened.
        if (e.ExceptionObject is Exception ex)
            LogCrash("background thread", ex);
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        LogCrash("unobserved task", e.Exception);
        e.SetObserved(); // prevents this from also surfacing as a process-terminating AppDomain exception
    }

    private static string CrashLogPath() => Path.Combine(DefaultPaths.DefaultAppDataDirectory(), "crash.log");

    private static void LogCrash(string source, Exception ex)
    {
        try
        {
            var path = CrashLogPath();
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            File.AppendAllText(path, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] ({source}) {ex}\n\n");
        }
        catch
        {
            // Logging the crash must never itself become a second crash.
        }
    }
}
