using System.Windows;
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
}
