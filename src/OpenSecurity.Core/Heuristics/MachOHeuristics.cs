namespace OpenSecurity.Core.Heuristics;

/// <summary>
/// Load-path patterns for a Mach-O's linked dylibs that are unusual for legitimate software.
/// Normal apps link against /usr/lib, /System/Library frameworks, or bundle-relative paths
/// (@rpath/@loader_path/@executable_path); a dylib loaded from a world-writable temp location
/// or via directory traversal is a much weaker signal to trust than a fixed name blocklist
/// (which ages out as soon as a sample is recompiled), so this checks shape, not identity.
/// </summary>
public static class MachOHeuristics
{
    public static bool IsSuspiciousDylibPath(string path)
    {
        if (path.Contains("../", StringComparison.Ordinal))
            return true;

        return path.StartsWith("/tmp/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/var/tmp/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/var/folders/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/private/tmp/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/Downloads/", StringComparison.OrdinalIgnoreCase);
    }
}
