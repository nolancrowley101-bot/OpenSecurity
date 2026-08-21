namespace OpenSecurity.Core.Scanning;

/// <summary>Loads the flat list of conventional passwords to try against encrypted archives.</summary>
public static class ArchivePasswordList
{
    public static List<string> Load(string path)
    {
        if (!File.Exists(path))
            return new List<string>();

        var passwords = new List<string>();
        foreach (var rawLine in File.ReadLines(path))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;
            passwords.Add(line);
        }
        return passwords;
    }
}
