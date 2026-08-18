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

        var viewModel = new MainViewModel(
            hashDbPath, rulesDir, allowlistPath,
            DefaultPaths.DefaultQuarantineDirectory(),
            DefaultPaths.DefaultHistoryFilePath(),
            DefaultPaths.DefaultSettingsFilePath(),
            AutoStartManager.SetEnabled);

        var startMinimized = e.Args.Contains("--minimized");
        var window = new MainWindow(viewModel, startMinimized);

        if (!startMinimized)
            window.Show();
    }
}
