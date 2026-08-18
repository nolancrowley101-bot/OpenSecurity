namespace OpenSecurity.Cli;

public sealed class CliOptions
{
    public required string TargetPath { get; init; }
    public bool Recursive { get; init; } = true;
    public bool Verbose { get; init; }
    public string? HashDbPath { get; init; }
    public string? RulesDir { get; init; }
    public string? AllowlistPath { get; init; }
    public bool Quarantine { get; init; }

    public static CliOptions? Parse(string[] args)
    {
        if (args.Length == 0)
            return null;

        string? path = null;
        var recursive = true;
        var verbose = false;
        string? hashDb = null;
        string? rulesDir = null;
        string? allowlist = null;
        var quarantine = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--recursive" or "-r":
                    recursive = true;
                    break;
                case "--no-recursive":
                    recursive = false;
                    break;
                case "--verbose" or "-v":
                    verbose = true;
                    break;
                case "--hashdb":
                    if (++i >= args.Length) return null;
                    hashDb = args[i];
                    break;
                case "--rules":
                    if (++i >= args.Length) return null;
                    rulesDir = args[i];
                    break;
                case "--allowlist":
                    if (++i >= args.Length) return null;
                    allowlist = args[i];
                    break;
                case "--quarantine":
                    quarantine = true;
                    break;
                case "-h" or "--help":
                    return null;
                default:
                    if (path is not null)
                        return null;
                    path = args[i];
                    break;
            }
        }

        return path is null
            ? null
            : new CliOptions
            {
                TargetPath = path,
                Recursive = recursive,
                Verbose = verbose,
                HashDbPath = hashDb,
                RulesDir = rulesDir,
                AllowlistPath = allowlist,
                Quarantine = quarantine
            };
    }
}
