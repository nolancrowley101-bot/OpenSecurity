using System.IO;
using System.Windows;
using Application = System.Windows.Application;
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
}
