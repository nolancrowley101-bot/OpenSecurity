using System.Security;

namespace OpenSecurity.Core.Scanning;

/// <summary>
/// Recursively enumerates files, skipping any subdirectory that throws on access instead of
/// aborting the whole walk - .NET's own Directory.EnumerateFiles(path, "*", AllDirectories)
/// throws lazily mid-enumeration on the first inaccessible folder, which makes it useless for
/// a full-drive scan (C:\System Volume Information, C:\Windows\CSC, etc. are always there).
/// Also skips reparse-point directories (junctions/symlinks) to avoid cycles.
/// </summary>
public static class ResilientFileWalker
{
    public static IEnumerable<string> EnumerateFiles(string rootPath, bool recursive)
    {
        var pending = new Stack<string>();
        pending.Push(rootPath);

        while (pending.Count > 0)
        {
            var dir = pending.Pop();

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
            {
                continue;
            }

            foreach (var file in files)
                yield return file;

            if (!recursive)
                continue;

            IEnumerable<string> subdirs;
            try
            {
                subdirs = Directory.EnumerateDirectories(dir);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
            {
                continue;
            }

            foreach (var subdir in subdirs)
            {
                if (IsReparsePoint(subdir))
                    continue;
                pending.Push(subdir);
            }
        }
    }

    private static bool IsReparsePoint(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return true; // if we can't even stat it, don't recurse into it
        }
    }
}
