using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using OpenSecurity.Ui.ViewModels;

namespace OpenSecurity.Ui;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;

    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = _viewModel;
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
                $"Move '{System.IO.Path.GetFileName(row.FilePath)}' to quarantine?\n\nThe file will be removed from its current location. You can restore it later from the Quarantine tab.",
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
                $"Permanently delete the quarantined copy of '{System.IO.Path.GetFileName(entry.OriginalPath)}'?\n\nThis cannot be undone.",
                "Delete quarantined file", MessageBoxButton.YesNo, MessageBoxImage.Warning);

            if (confirm == MessageBoxResult.Yes)
                _viewModel.DeleteQuarantineEntry(entry);
        }
    }

    private async void UpdateSignatures_Click(object sender, RoutedEventArgs e)
    {
        await _viewModel.UpdateSignaturesAsync();
    }
}
