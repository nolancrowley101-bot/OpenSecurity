using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace OpenSecurity.Ui.Services;

/// <summary>
/// Registers/unregisters the "Scan with OpenSecurity" right-click entry in Windows Explorer
/// for files, folders, and drives. Uses the per-user HKCU\Software\Classes hive so no admin
/// rights are needed and nothing affects other user accounts on the machine.
/// </summary>
public static class ContextMenuManager
{
    private const string VerbName = "OpenSecurityScan";
    private const string MenuText = "Scan with OpenSecurity";
    private static readonly string[] RootKeys = { @"*\shell", @"Directory\shell", @"Drive\shell" };

    [DllImport("shell32.dll")]
    private static extern void SHChangeNotify(int wEventId, int uFlags, IntPtr dwItem1, IntPtr dwItem2);

    public static void Register()
    {
        var exePath = Environment.ProcessPath ?? throw new InvalidOperationException("Could not determine the running exe path.");

        foreach (var root in RootKeys)
        {
            using var shellKey = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{root}\{VerbName}");
            shellKey.SetValue("", MenuText);
            shellKey.SetValue("Icon", $"\"{exePath}\",0");

            using var commandKey = shellKey.CreateSubKey("command");
            commandKey.SetValue("", $"\"{exePath}\" --scan \"%1\"");
        }

        NotifyShellOfChange();
    }

    public static void Unregister()
    {
        foreach (var root in RootKeys)
            Registry.CurrentUser.DeleteSubKeyTree($@"Software\Classes\{root}\{VerbName}", throwOnMissingSubKey: false);

        NotifyShellOfChange();
    }

    public static bool IsRegistered()
    {
        using var key = Registry.CurrentUser.OpenSubKey($@"Software\Classes\*\shell\{VerbName}");
        return key is not null;
    }

    private static void NotifyShellOfChange()
    {
        const int SHCNE_ASSOCCHANGED = 0x08000000;
        const int SHCNF_IDLIST = 0x0000;
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, IntPtr.Zero, IntPtr.Zero);
    }
}
