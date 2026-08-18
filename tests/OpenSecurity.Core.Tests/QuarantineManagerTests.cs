using OpenSecurity.Core.Quarantine;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class QuarantineManagerTests : IDisposable
{
    private readonly string _workDir = Path.Combine(Path.GetTempPath(), "OpenSecurityTests_" + Guid.NewGuid().ToString("N"));

    public QuarantineManagerTests() => Directory.CreateDirectory(_workDir);

    public void Dispose()
    {
        if (Directory.Exists(_workDir))
            Directory.Delete(_workDir, recursive: true);
    }

    [Fact]
    public void Quarantine_RemovesOriginalFile_AndRecordsEntry()
    {
        var filePath = Path.Combine(_workDir, "evil.exe");
        File.WriteAllText(filePath, "totally-not-malware-content");
        var manager = new QuarantineManager(Path.Combine(_workDir, "quarantine"));

        var entry = manager.Quarantine(filePath, "deadbeef", "test-detection");

        Assert.False(File.Exists(filePath));
        Assert.Equal(filePath, entry.OriginalPath);
        Assert.Single(manager.ListEntries());
    }

    [Fact]
    public void Quarantine_ObfuscatesStoredBytes()
    {
        var filePath = Path.Combine(_workDir, "evil.exe");
        var originalContent = "totally-not-malware-content"u8.ToArray();
        File.WriteAllBytes(filePath, originalContent);
        var quarantineDir = Path.Combine(_workDir, "quarantine");
        var manager = new QuarantineManager(quarantineDir);

        var entry = manager.Quarantine(filePath, "deadbeef", "test-detection");

        var storedBytes = File.ReadAllBytes(Path.Combine(quarantineDir, entry.QuarantinedFileName));
        Assert.NotEqual(originalContent, storedBytes);
    }

    [Fact]
    public void Restore_RecreatesOriginalFileExactly()
    {
        var filePath = Path.Combine(_workDir, "evil.exe");
        var originalContent = "totally-not-malware-content"u8.ToArray();
        File.WriteAllBytes(filePath, originalContent);
        var manager = new QuarantineManager(Path.Combine(_workDir, "quarantine"));
        var entry = manager.Quarantine(filePath, "deadbeef", "test-detection");

        manager.Restore(entry.Id);

        Assert.True(File.Exists(filePath));
        Assert.Equal(originalContent, File.ReadAllBytes(filePath));
        Assert.Empty(manager.ListEntries());
    }

    [Fact]
    public void Delete_RemovesQuarantinedFile_WithoutRestoring()
    {
        var filePath = Path.Combine(_workDir, "evil.exe");
        File.WriteAllText(filePath, "content");
        var quarantineDir = Path.Combine(_workDir, "quarantine");
        var manager = new QuarantineManager(quarantineDir);
        var entry = manager.Quarantine(filePath, "deadbeef", "test-detection");

        manager.Delete(entry.Id);

        Assert.False(File.Exists(filePath));
        Assert.False(File.Exists(Path.Combine(quarantineDir, entry.QuarantinedFileName)));
        Assert.Empty(manager.ListEntries());
    }
}
