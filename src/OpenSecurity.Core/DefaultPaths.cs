namespace OpenSecurity.Core;

/// <summary>Locates the signatures/rules data directories relative to wherever the app is running from.</summary>
public static class DefaultPaths
{
    public static string? FindUp(string startDir, string relativePath)
    {
        var dir = new DirectoryInfo(startDir);
        for (var i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir.FullName, relativePath);
            if (File.Exists(candidate) || Directory.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }
        return null;
    }

    /// <summary>Per-user quarantine folder, independent of wherever the app binary happens to be running from.</summary>
    public static string DefaultQuarantineDirectory() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OpenSecurity", "Quarantine");
}
