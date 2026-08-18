using OpenSecurity.Core.Hashing;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class HashSignatureDatabaseTests : IDisposable
{
    private readonly string _tempFile = Path.Combine(Path.GetTempPath(), "OpenSecurityTests_" + Guid.NewGuid().ToString("N") + ".txt");

    public void Dispose()
    {
        if (File.Exists(_tempFile))
            File.Delete(_tempFile);
    }

    [Fact]
    public void AppendNewEntries_AddsHashesNotAlreadyPresent()
    {
        var existingHash = new string('1', 64);
        File.WriteAllText(_tempFile, $"{existingHash}  already-known\n");

        var newHash = new string('2', 64);
        var added = HashSignatureDatabase.AppendNewEntries(_tempFile, new[] { (existingHash, "dup"), (newHash, "new-one") });

        Assert.Equal(1, added);
        var db = HashSignatureDatabase.Load(_tempFile);
        Assert.Equal(2, db.Count);
        Assert.True(db.TryMatch(newHash, out var label));
        Assert.Equal("new-one", label);
    }

    [Fact]
    public void AppendNewEntries_DedupesWithinTheBatchItself()
    {
        var hash = new string('3', 64);
        var added = HashSignatureDatabase.AppendNewEntries(_tempFile, new[] { (hash, "first"), (hash, "second") });

        Assert.Equal(1, added);
        Assert.Equal(1, HashSignatureDatabase.Load(_tempFile).Count);
    }

    [Fact]
    public void AppendNewEntries_ReturnsZero_WhenNothingNew()
    {
        var hash = new string('4', 64);
        File.WriteAllText(_tempFile, $"{hash}  known\n");

        var added = HashSignatureDatabase.AppendNewEntries(_tempFile, new[] { (hash, "known-again") });

        Assert.Equal(0, added);
    }

    [Fact]
    public void AppendNewEntries_CreatesFile_WhenItDoesNotExist()
    {
        var hash = new string('5', 64);
        var added = HashSignatureDatabase.AppendNewEntries(_tempFile, new[] { (hash, "fresh") });

        Assert.Equal(1, added);
        Assert.True(File.Exists(_tempFile));
    }
}
