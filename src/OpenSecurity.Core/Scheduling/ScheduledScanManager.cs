using System.Diagnostics;

namespace OpenSecurity.Core.Scheduling;

public enum ScanFrequency
{
    Daily,
    Weekly
}

public sealed record ScheduledScanConfig(string TargetPath, bool Quarantine, ScanFrequency Frequency, TimeSpan TimeOfDay);

/// <summary>
/// Wraps Windows Task Scheduler (schtasks.exe) so OpenSecurity doesn't need to run a background
/// process of its own just to fire off a scan on a schedule - Task Scheduler handles wake-up and
/// execution reliably even when the app isn't running.
/// </summary>
public sealed class ScheduledScanManager
{
    public const string TaskName = "OpenSecurity_ScheduledScan";

    public void CreateOrUpdate(string cliExePath, ScheduledScanConfig config)
    {
        var taskCommand = $"\"{cliExePath}\" \"{config.TargetPath}\"" + (config.Quarantine ? " --quarantine" : "");
        var startTime = config.TimeOfDay.ToString(@"hh\:mm");

        var args = new List<string> { "/Create", "/TN", TaskName, "/TR", taskCommand, "/SC", config.Frequency == ScanFrequency.Weekly ? "WEEKLY" : "DAILY", "/ST", startTime, "/F" };
        if (config.Frequency == ScanFrequency.Weekly)
        {
            args.Add("/D");
            args.Add("SUN");
        }

        RunSchtasks(args, $"create scheduled task '{TaskName}'");
    }

    public void Delete()
    {
        if (!Exists())
            return;

        RunSchtasks(new List<string> { "/Delete", "/TN", TaskName, "/F" }, $"delete scheduled task '{TaskName}'");
    }

    public bool Exists()
    {
        var psi = BuildStartInfo(new List<string> { "/Query", "/TN", TaskName });
        using var process = Process.Start(psi)!;
        process.WaitForExit();
        return process.ExitCode == 0;
    }

    private static void RunSchtasks(List<string> args, string actionDescription)
    {
        var psi = BuildStartInfo(args);
        using var process = Process.Start(psi)!;
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0)
            throw new InvalidOperationException($"Failed to {actionDescription}: {stderr.Trim()}");
    }

    private static ProcessStartInfo BuildStartInfo(List<string> args)
    {
        var psi = new ProcessStartInfo("schtasks.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);
        return psi;
    }
}
