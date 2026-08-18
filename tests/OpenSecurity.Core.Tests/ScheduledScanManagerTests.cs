using OpenSecurity.Core.Scheduling;
using Xunit;

namespace OpenSecurity.Core.Tests;

/// <summary>Exercises the real schtasks.exe integration (not mocked) - creates and deletes an
/// actual Windows scheduled task, cleaning up after itself.</summary>
public class ScheduledScanManagerTests : IDisposable
{
    private readonly ScheduledScanManager _manager = new();

    public void Dispose()
    {
        if (_manager.Exists())
            _manager.Delete();
    }

    [Fact]
    public void CreateOrUpdate_ThenExists_ReturnsTrue()
    {
        var config = new ScheduledScanConfig(@"C:\Users", Quarantine: false, ScanFrequency.Daily, TimeSpan.FromHours(9));
        _manager.CreateOrUpdate(@"C:\fake\OpenSecurity.Cli.exe", config);

        Assert.True(_manager.Exists());
    }

    [Fact]
    public void Delete_ThenExists_ReturnsFalse()
    {
        var config = new ScheduledScanConfig(@"C:\Users", Quarantine: false, ScanFrequency.Daily, TimeSpan.FromHours(9));
        _manager.CreateOrUpdate(@"C:\fake\OpenSecurity.Cli.exe", config);

        _manager.Delete();

        Assert.False(_manager.Exists());
    }

    [Fact]
    public void CreateOrUpdate_IsIdempotent_OverwritesExistingTask()
    {
        var first = new ScheduledScanConfig(@"C:\Users", Quarantine: false, ScanFrequency.Daily, TimeSpan.FromHours(9));
        var second = new ScheduledScanConfig(@"C:\Windows", Quarantine: true, ScanFrequency.Weekly, TimeSpan.FromHours(14));

        _manager.CreateOrUpdate(@"C:\fake\OpenSecurity.Cli.exe", first);
        _manager.CreateOrUpdate(@"C:\fake\OpenSecurity.Cli.exe", second);

        Assert.True(_manager.Exists());
    }
}
