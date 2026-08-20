using Microsoft.Win32;
using OpenSecurity.Ui.Services;
using Xunit;

namespace OpenSecurity.Ui.Tests;

/// <summary>Exercises the real HKCU registry (not mocked) - registers and unregisters the
/// actual context-menu keys, cleaning up after itself.</summary>
public class ContextMenuManagerTests : IDisposable
{
    public void Dispose()
    {
        if (ContextMenuManager.IsRegistered())
            ContextMenuManager.Unregister();
    }

    [Fact]
    public void Register_ThenIsRegistered_ReturnsTrue()
    {
        ContextMenuManager.Register();
        Assert.True(ContextMenuManager.IsRegistered());
    }

    [Fact]
    public void Unregister_ThenIsRegistered_ReturnsFalse()
    {
        ContextMenuManager.Register();
        ContextMenuManager.Unregister();
        Assert.False(ContextMenuManager.IsRegistered());
    }

    [Fact]
    public void Register_CreatesEntriesForFilesFoldersAndDrives()
    {
        ContextMenuManager.Register();

        Assert.NotNull(Registry.CurrentUser.OpenSubKey(@"Software\Classes\*\shell\OpenSecurityScan\command"));
        Assert.NotNull(Registry.CurrentUser.OpenSubKey(@"Software\Classes\Directory\shell\OpenSecurityScan\command"));
        Assert.NotNull(Registry.CurrentUser.OpenSubKey(@"Software\Classes\Drive\shell\OpenSecurityScan\command"));
    }

    [Fact]
    public void Register_CommandInvokesCurrentExeWithScanFlag()
    {
        ContextMenuManager.Register();

        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Classes\*\shell\OpenSecurityScan\command");
        var command = key?.GetValue("") as string;

        Assert.NotNull(command);
        Assert.Contains("--scan", command);
        Assert.Contains("%1", command);
    }

    [Fact]
    public void Register_IsIdempotent()
    {
        ContextMenuManager.Register();
        ContextMenuManager.Register();
        Assert.True(ContextMenuManager.IsRegistered());
    }
}
