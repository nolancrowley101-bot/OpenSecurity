using System.IO;
using OpenSecurity.Core.Scheduling;

namespace OpenSecurity.Ui.ViewModels;

public sealed partial class MainViewModel
{
    private readonly ScheduledScanManager _scheduledScanManager;

    private string _scheduleTargetPath = "";
    private bool _scheduleIsWeekly;
    private string _scheduleTimeText = "09:00";
    private bool _scheduleQuarantine;
    private bool _isScheduleEnabled;

    public string ScheduleTargetPath
    {
        get => _scheduleTargetPath;
        set { _scheduleTargetPath = value; OnPropertyChanged(); }
    }

    public bool ScheduleIsWeekly
    {
        get => _scheduleIsWeekly;
        set { _scheduleIsWeekly = value; OnPropertyChanged(); }
    }

    public string ScheduleTimeText
    {
        get => _scheduleTimeText;
        set { _scheduleTimeText = value; OnPropertyChanged(); }
    }

    public bool ScheduleQuarantine
    {
        get => _scheduleQuarantine;
        set { _scheduleQuarantine = value; OnPropertyChanged(); }
    }

    public bool IsScheduleEnabled
    {
        get => _isScheduleEnabled;
        private set { _isScheduleEnabled = value; OnPropertyChanged(); }
    }

    public void EnableSchedule()
    {
        if (!Directory.Exists(ScheduleTargetPath) && !File.Exists(ScheduleTargetPath))
        {
            StatusText = "Schedule: path not found.";
            return;
        }

        if (!TimeSpan.TryParse(ScheduleTimeText, out var timeOfDay))
        {
            StatusText = "Schedule: invalid time, expected HH:mm.";
            return;
        }

        var cliExePath = Path.Combine(AppContext.BaseDirectory, "OpenSecurity.Cli.exe");
        var frequency = ScheduleIsWeekly ? ScanFrequency.Weekly : ScanFrequency.Daily;

        try
        {
            _scheduledScanManager.CreateOrUpdate(cliExePath, new ScheduledScanConfig(ScheduleTargetPath, ScheduleQuarantine, frequency, timeOfDay));
            RefreshScheduleStatus();
            StatusText = $"Scheduled scan enabled: {frequency} at {ScheduleTimeText}.";
        }
        catch (InvalidOperationException ex)
        {
            StatusText = $"Failed to enable schedule: {ex.Message}";
        }
    }

    public void DisableSchedule()
    {
        _scheduledScanManager.Delete();
        RefreshScheduleStatus();
        StatusText = "Scheduled scan disabled.";
    }

    private void RefreshScheduleStatus()
    {
        IsScheduleEnabled = _scheduledScanManager.Exists();
    }
}
