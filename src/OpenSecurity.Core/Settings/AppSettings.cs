using System.Text.Json;

namespace OpenSecurity.Core.Settings;

public sealed class AppSettings
{
    // On by default (like commercial AV real-time protection and SmartScreen) rather than
    // opt-in, so a fresh install is actually protected without the user needing to find and
    // flip two separate switches first. Existing installs keep whatever they already saved,
    // since these defaults only apply when there's no settings.json yet to load.
    public bool RealTimeProtectionEnabled { get; set; } = true;
    public List<string> WatchedFolders { get; set; } = new();
    public bool StartWithWindows { get; set; } = true;

    // A minifilter driver could block execution outright; without one, immediately moving a
    // high-confidence (Malicious, not just Suspicious) real-time detection to quarantine is
    // the closest user-mode equivalent - it shrinks the window between "file lands on disk"
    // and "user double-clicks it" down to the ~2 second detection debounce.
    public bool AutoQuarantineOnDetect { get; set; } = true;

    public static List<string> DefaultWatchedFolders()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new List<string>
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Path.GetTempPath()
        }.Where(Directory.Exists).Distinct().ToList();
    }

    public static AppSettings Load(string path)
    {
        if (!File.Exists(path))
            return new AppSettings { WatchedFolders = DefaultWatchedFolders() };

        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings { WatchedFolders = DefaultWatchedFolders() };
    }

    public void Save(string path)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, json);
    }
}
