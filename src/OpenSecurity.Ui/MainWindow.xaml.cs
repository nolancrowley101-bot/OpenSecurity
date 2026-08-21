using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using Application = System.Windows.Application;
using Button = System.Windows.Controls.Button;
using DragEventArgs = System.Windows.DragEventArgs;
using MessageBox = System.Windows.MessageBox;
using Microsoft.Win32;
using OpenSecurity.Ui.Services;
using OpenSecurity.Ui.ViewModels;

namespace OpenSecurity.Ui;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;
    private readonly TrayIconManager _trayIcon = new();
    private bool _isExiting;

    public MainWindow(MainViewModel viewModel, bool startMinimized = false)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = _viewModel;

        _trayIcon.OpenRequested += () => Dispatcher.Invoke(RestoreFromTray);
        _trayIcon.ExitRequested += () => Dispatcher.Invoke(ExitApplication);
        _trayIcon.Show();

        _viewModel.RealTimeThreatDetected += result =>
            _trayIcon.ShowBalloon("OpenSecurity - threat detected", $"{result.OverallVerdict}: {Path.GetFileName(result.FilePath)}");

        if (startMinimized)
        {
            WindowState = WindowState.Minimized;
            ShowInTaskbar = false;
        }
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        ApplyDarkTitleBar();
    }

    private void ApplyDarkTitleBar()
    {
        // Cosmetic only (native title bar to match the dark theme) - a failure here on an
        // older Windows build must never affect the rest of the app, so swallow everything.
        try
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            var useDarkMode = 1;
            const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
            const int DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19;

            if (DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref useDarkMode, sizeof(int)) != 0)
                DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_OLD, ref useDarkMode, sizeof(int));
        }
        catch (Exception)
        {
            // ignored - decorative
        }
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (_isExiting)
        {
            base.OnClosing(e);
            return;
        }

        e.Cancel = true;
        Hide();
        ShowInTaskbar = false;
    }

    private void RestoreFromTray()
    {
        Show();
        ShowInTaskbar = true;
        WindowState = WindowState.Normal;
        Activate();
    }

    private void ExitApplication()
    {
        _isExiting = true;
        _trayIcon.Dispose();
        _viewModel.Dispose();
        Close();
        Application.Current.Shutdown();
    }

    private void BrowseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Select a folder to scan" };
        if (dialog.ShowDialog() == true)
            _viewModel.TargetPath = dialog.FolderName;
    }

    private void BrowseFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Select a file to scan" };
        if (dialog.ShowDialog() == true)
            _viewModel.TargetPath = dialog.FileName;
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        await _viewModel.RunScanAsync();
    }

    private async void ScanDrive_Click(object sender, RoutedEventArgs e)
    {
        if (((Button)sender).Tag is string driveRoot)
        {
            _viewModel.ScanFullDrive(driveRoot);
            await _viewModel.RunScanAsync();
        }
    }

    private void ExportReport_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Export scan report",
            Filter = "JSON report (*.json)|*.json|CSV report (*.csv)|*.csv",
            FileName = $"OpenSecurity-report-{DateTime.Now:yyyy-MM-dd_HHmmss}.json"
        };
        if (dialog.ShowDialog() == true)
            _viewModel.ExportReport(dialog.FileName);
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop))
            return;

        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } paths)
            _viewModel.TargetPath = paths[0];
    }

    private void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        if (((Button)sender).Tag is ScanRowViewModel row)
        {
            var confirm = MessageBox.Show(
                $"Move '{Path.GetFileName(row.FilePath)}' to quarantine?\n\nThe file will be removed from its current location. You can restore it later from the Quarantine tab.",
                "Quarantine file", MessageBoxButton.YesNo, MessageBoxImage.Warning);

            if (confirm == MessageBoxResult.Yes)
                _viewModel.QuarantineResult(row);
        }
    }

    private void Allow_Click(object sender, RoutedEventArgs e)
    {
        if (((Button)sender).Tag is ScanRowViewModel row)
            _viewModel.AllowlistResult(row);
    }

    private void RestoreQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (((Button)sender).Tag is QuarantineRowViewModel entry)
            _viewModel.RestoreQuarantineEntry(entry);
    }

    private void DeleteQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if (((Button)sender).Tag is QuarantineRowViewModel entry)
        {
            var confirm = MessageBox.Show(
                $"Permanently delete the quarantined copy of '{Path.GetFileName(entry.OriginalPath)}'?\n\nThis cannot be undone.",
                "Delete quarantined file", MessageBoxButton.YesNo, MessageBoxImage.Warning);

            if (confirm == MessageBoxResult.Yes)
                _viewModel.DeleteQuarantineEntry(entry);
        }
    }

    private async void UpdateSignatures_Click(object sender, RoutedEventArgs e)
    {
        await _viewModel.UpdateSignaturesAsync();
    }

    private void AddWatchedFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Select a folder to watch" };
        if (dialog.ShowDialog() == true)
            _viewModel.AddWatchedFolder(dialog.FolderName);
    }

    private void RemoveWatchedFolder_Click(object sender, RoutedEventArgs e)
    {
        if (((Button)sender).Tag is string folder)
            _viewModel.RemoveWatchedFolder(folder);
    }

    private void EnableSchedule_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.EnableSchedule();
    }

    private void DisableSchedule_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.DisableSchedule();
    }

    private void BrowseScheduleFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Select a folder to scan on schedule" };
        if (dialog.ShowDialog() == true)
            _viewModel.ScheduleTargetPath = dialog.FolderName;
    }
}
