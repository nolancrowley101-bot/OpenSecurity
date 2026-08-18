using OpenSecurity.Core.Scanning;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class ResilientFileWalkerTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "OpenSecurityTests_" + Guid.NewGuid().ToString("N"));

    public ResilientFileWalkerTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public void EnumerateFiles_Recursive_FindsFilesInSubdirectories()
    {
        File.WriteAllText(Path.Combine(_root, "top.txt"), "x");
        var subdir = Path.Combine(_root, "sub");
        Directory.CreateDirectory(subdir);
        File.WriteAllText(Path.Combine(subdir, "nested.txt"), "x");

        var files = ResilientFileWalker.EnumerateFiles(_root, recursive: true).ToList();

        Assert.Contains(files, f => f.EndsWith("top.txt"));
        Assert.Contains(files, f => f.EndsWith("nested.txt"));
    }

    [Fact]
    public void EnumerateFiles_NonRecursive_IgnoresSubdirectories()
    {
        File.WriteAllText(Path.Combine(_root, "top.txt"), "x");
        var subdir = Path.Combine(_root, "sub");
        Directory.CreateDirectory(subdir);
        File.WriteAllText(Path.Combine(subdir, "nested.txt"), "x");

        var files = ResilientFileWalker.EnumerateFiles(_root, recursive: false).ToList();

        Assert.Contains(files, f => f.EndsWith("top.txt"));
        Assert.DoesNotContain(files, f => f.EndsWith("nested.txt"));
    }

    [Fact]
    public void EnumerateFiles_NonExistentRoot_ReturnsEmpty_DoesNotThrow()
    {
        var missingRoot = Path.Combine(_root, "does-not-exist");
        var files = ResilientFileWalker.EnumerateFiles(missingRoot, recursive: true).ToList();
        Assert.Empty(files);
    }
}
