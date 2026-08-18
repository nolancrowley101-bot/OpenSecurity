using System.Text.Json;

namespace OpenSecurity.Core.Settings;

public sealed class AppSettings
{
    public bool RealTimeProtectionEnabled { get; set; }
    public List<string> WatchedFolders { get; set; } = new();
    public bool StartWithWindows { get; set; }

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
