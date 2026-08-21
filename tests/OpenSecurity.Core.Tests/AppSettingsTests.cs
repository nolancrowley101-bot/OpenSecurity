using OpenSecurity.Core.Settings;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class AppSettingsTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), "OpenSecurityTests_settings_" + Guid.NewGuid().ToString("N") + ".json");

    public void Dispose()
    {
        if (File.Exists(_path))
            File.Delete(_path);
    }

    [Fact]
    public void NewInstance_DefaultsToProtectionOn()
    {
        // Protection defaults on (like SmartScreen/commercial AV) rather than opt-in, so a
        // fresh install is actually protected without the user finding and flipping switches.
        var settings = new AppSettings();

        Assert.True(settings.RealTimeProtectionEnabled);
        Assert.True(settings.StartWithWindows);
        Assert.True(settings.AutoQuarantineOnDetect);
    }

    [Fact]
    public void Load_MissingFile_ReturnsProtectionOnDefaults()
    {
        var settings = AppSettings.Load(_path);

        Assert.True(settings.RealTimeProtectionEnabled);
        Assert.True(settings.StartWithWindows);
        Assert.True(settings.AutoQuarantineOnDetect);
    }

    [Fact]
    public void SaveThenLoad_PreservesExplicitlyDisabledSettings()
    {
        // An existing user who deliberately turned protection off must not have it silently
        // re-enabled just because the in-memory default changed - the persisted choice wins.
        var settings = new AppSettings { RealTimeProtectionEnabled = false, StartWithWindows = false, AutoQuarantineOnDetect = false };
        settings.Save(_path);

        var loaded = AppSettings.Load(_path);

        Assert.False(loaded.RealTimeProtectionEnabled);
        Assert.False(loaded.StartWithWindows);
        Assert.False(loaded.AutoQuarantineOnDetect);
    }

    [Fact]
    public void Load_OlderSettingsFileMissingNewProperty_FillsInDefaultForIt()
    {
        // Simulates upgrading from a version before AutoQuarantineOnDetect existed - the JSON
        // on disk simply doesn't have that field yet.
        File.WriteAllText(_path, """{"RealTimeProtectionEnabled":false,"WatchedFolders":[],"StartWithWindows":false}""");

        var loaded = AppSettings.Load(_path);

        Assert.False(loaded.RealTimeProtectionEnabled); // explicit value from the old file preserved
        Assert.True(loaded.AutoQuarantineOnDetect);      // absent from the old file - falls back to the default
    }
}
