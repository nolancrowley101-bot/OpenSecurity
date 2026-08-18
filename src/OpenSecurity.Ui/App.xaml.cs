using System.IO;
using System.Windows;
using OpenSecurity.Core;
using OpenSecurity.Ui.ViewModels;

namespace OpenSecurity.Ui;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var appDir = AppContext.BaseDirectory;
        var hashDbPath = DefaultPaths.FindUp(appDir, Path.Combine("signatures", "hashes.txt")) ?? Path.Combine(appDir, "signatures", "hashes.txt");
        var rulesDir = DefaultPaths.FindUp(appDir, "rules") ?? Path.Combine(appDir, "rules");
        var rulesCount = Directory.Exists(rulesDir) ? Directory.EnumerateFiles(rulesDir, "*.yar", SearchOption.AllDirectories).Count() : 0;

        var engineInfo = $"signatures: {hashDbPath}   |   rules: {rulesCount} file(s) from {rulesDir}";
        var viewModel = new MainViewModel(hashDbPath, rulesDir, engineInfo);

        var window = new MainWindow(viewModel);
        window.Show();
    }
}
