using System.Text.Json;

namespace OpenSecurity.Core.Quarantine;

/// <summary>
/// Moves malicious files into an isolated folder instead of just reporting them.
/// Quarantined files are XOR-obfuscated (not encrypted - just enough that they can't be
/// double-clicked or picked up by another scanner while sitting in quarantine) and tracked
/// in a manifest so they can be restored to their original location later.
/// </summary>
public sealed class QuarantineManager
{
    private const byte ObfuscationKey = 0xFF;

    private readonly string _quarantineDirectory;
    private readonly string _manifestPath;

    public QuarantineManager(string quarantineDirectory)
    {
        _quarantineDirectory = quarantineDirectory;
        _manifestPath = Path.Combine(quarantineDirectory, "manifest.json");
    }

    public QuarantineEntry Quarantine(string filePath, string sha256, string reason)
    {
        Directory.CreateDirectory(_quarantineDirectory);

        var bytes = File.ReadAllBytes(filePath);
        Obfuscate(bytes);

        var id = Guid.NewGuid().ToString("N");
        var quarantinedFileName = $"{id}.quarantine";
        File.WriteAllBytes(Path.Combine(_quarantineDirectory, quarantinedFileName), bytes);
        File.Delete(filePath);

        var entry = new QuarantineEntry
        {
            Id = id,
            OriginalPath = Path.GetFullPath(filePath),
            QuarantinedFileName = quarantinedFileName,
            Sha256 = sha256,
            Reason = reason,
            TimestampUtc = DateTime.UtcNow
        };

        var entries = LoadManifest();
        entries.Add(entry);
        SaveManifest(entries);

        return entry;
    }

    public void Restore(string id, string? restoreToPath = null)
    {
        var entries = LoadManifest();
        var entry = entries.FirstOrDefault(e => e.Id == id)
            ?? throw new InvalidOperationException($"No quarantine entry with id {id}");

        var targetPath = restoreToPath ?? entry.OriginalPath;
        var targetDir = Path.GetDirectoryName(targetPath);
        if (!string.IsNullOrEmpty(targetDir))
            Directory.CreateDirectory(targetDir);

        var quarantinedPath = Path.Combine(_quarantineDirectory, entry.QuarantinedFileName);
        var bytes = File.ReadAllBytes(quarantinedPath);
        Obfuscate(bytes);
        File.WriteAllBytes(targetPath, bytes);
        File.Delete(quarantinedPath);

        entries.Remove(entry);
        SaveManifest(entries);
    }

    public void Delete(string id)
    {
        var entries = LoadManifest();
        var entry = entries.FirstOrDefault(e => e.Id == id)
            ?? throw new InvalidOperationException($"No quarantine entry with id {id}");

        var quarantinedPath = Path.Combine(_quarantineDirectory, entry.QuarantinedFileName);
        if (File.Exists(quarantinedPath))
            File.Delete(quarantinedPath);

        entries.Remove(entry);
        SaveManifest(entries);
    }

    public IReadOnlyList<QuarantineEntry> ListEntries() =>
        LoadManifest().OrderByDescending(e => e.TimestampUtc).ToList();

    private static void Obfuscate(byte[] bytes)
    {
        for (var i = 0; i < bytes.Length; i++)
            bytes[i] ^= ObfuscationKey;
    }

    private List<QuarantineEntry> LoadManifest()
    {
        if (!File.Exists(_manifestPath))
            return new List<QuarantineEntry>();

        var json = File.ReadAllText(_manifestPath);
        return JsonSerializer.Deserialize<List<QuarantineEntry>>(json) ?? new List<QuarantineEntry>();
    }

    private void SaveManifest(List<QuarantineEntry> entries)
    {
        Directory.CreateDirectory(_quarantineDirectory);
        var json = JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_manifestPath, json);
    }
}
