using OpenSecurity.Core;
using OpenSecurity.Core.Hashing;
using OpenSecurity.Core.Heuristics;
using OpenSecurity.Core.Quarantine;
using OpenSecurity.Core.Rules;
using OpenSecurity.Core.Scanning;
using OpenSecurity.Core.Updates;

namespace OpenSecurity.Cli;

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "update-signatures")
            return RunUpdateSignatures(args.Skip(1).ToArray()).GetAwaiter().GetResult();

        if (args.Length > 0 && args[0] == "list-quarantine")
            return RunListQuarantine();

        if (args.Length > 0 && args[0] == "restore-quarantine")
            return RunRestoreQuarantine(args.Skip(1).ToArray());

        var options = CliOptions.Parse(args);
        if (options is null)
        {
            PrintUsage();
            return 2;
        }

        if (!File.Exists(options.TargetPath) && !Directory.Exists(options.TargetPath))
        {
            Console.Error.WriteLine($"error: path not found: {options.TargetPath}");
            return 2;
        }

        var appDir = AppContext.BaseDirectory;
        var hashDbPath = options.HashDbPath ?? DefaultPaths.FindUp(appDir, Path.Combine("signatures", "hashes.txt"));
        var rulesDir = options.RulesDir ?? DefaultPaths.FindUp(appDir, "rules");
        var allowlistPath = options.AllowlistPath ?? DefaultPaths.FindUp(appDir, Path.Combine("signatures", "allowlist.txt"));

        var hashDb = hashDbPath is not null ? HashSignatureDatabase.Load(hashDbPath) : HashSignatureDatabase.Empty();
        var rules = rulesDir is not null ? PatternRuleParser.ParseDirectory(rulesDir) : new List<PatternRule>();
        var allowlist = allowlistPath is not null ? HashSignatureDatabase.Load(allowlistPath) : HashSignatureDatabase.Empty();

        Console.WriteLine($"OpenSecurity core scan engine");
        Console.WriteLine($"  by Nolan Crowley - Open Source (MIT License)");
        Console.WriteLine($"  hash signatures loaded : {hashDb.Count} (from {hashDbPath ?? "none found"})");
        Console.WriteLine($"  pattern rules loaded    : {rules.Count} (from {rulesDir ?? "none found"})");
        Console.WriteLine($"  allowlist entries       : {allowlist.Count} (from {allowlistPath ?? "none found"})");
        Console.WriteLine();

        var engine = new ScanEngine(new HashScanner(hashDb), new PatternRuleEngine(rules), new HeuristicAnalyzer(), allowlist);
        var quarantineManager = new QuarantineManager(DefaultPaths.DefaultQuarantineDirectory());

        var results = File.Exists(options.TargetPath)
            ? new[] { engine.ScanFile(options.TargetPath) }
            : engine.ScanDirectory(options.TargetPath, options.Recursive).ToArray();

        var scanned = 0;
        var clean = 0;
        var suspicious = 0;
        var malicious = 0;
        var errors = 0;

        foreach (var result in results)
        {
            scanned++;
            switch (result.OverallVerdict)
            {
                case Verdict.Clean:
                    clean++;
                    if (options.Verbose)
                        Console.WriteLine($"[clean]      {result.FilePath}");
                    break;
                case Verdict.Suspicious:
                    suspicious++;
                    PrintFindings(result, "SUSPICIOUS");
                    break;
                case Verdict.Malicious:
                    malicious++;
                    PrintFindings(result, "MALICIOUS");
                    if (options.Quarantine)
                    {
                        var reason = string.Join("; ", result.Findings.Select(f => f.Name));
                        var entry = quarantineManager.Quarantine(result.FilePath, result.Sha256, reason);
                        Console.WriteLine($"    -> quarantined (id: {entry.Id})");
                    }
                    break;
                case Verdict.Error:
                    errors++;
                    PrintFindings(result, "ERROR");
                    break;
            }
        }

        Console.WriteLine();
        Console.WriteLine($"Scanned {scanned} file(s): {clean} clean, {suspicious} suspicious, {malicious} malicious, {errors} errors.");

        return malicious > 0 ? 1 : 0;
    }

    private static async Task<int> RunUpdateSignatures(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine($"error: missing feed URL");
            Console.Error.WriteLine($"usage: OpenSecurity.Cli update-signatures <url> [--hashdb <file>]");
            Console.Error.WriteLine($"  suggested feed: {SignatureUpdater.SuggestedFeedUrl}");
            return 2;
        }

        var url = args[0];
        string? hashDbPath = null;
        for (var i = 1; i < args.Length; i++)
        {
            if (args[i] == "--hashdb" && ++i < args.Length)
                hashDbPath = args[i];
        }

        hashDbPath ??= DefaultPaths.FindUp(AppContext.BaseDirectory, Path.Combine("signatures", "hashes.txt"))
            ?? Path.Combine(AppContext.BaseDirectory, "signatures", "hashes.txt");

        Console.WriteLine($"Fetching signature feed from {url} ...");
        try
        {
            var updater = new SignatureUpdater();
            var added = await updater.UpdateFromUrlAsync(url, hashDbPath);
            Console.WriteLine($"Added {added} new hash signature(s) to {hashDbPath}.");
            return 0;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            Console.Error.WriteLine($"error: failed to fetch feed: {ex.Message}");
            return 1;
        }
    }

    private static int RunListQuarantine()
    {
        var manager = new QuarantineManager(DefaultPaths.DefaultQuarantineDirectory());
        var entries = manager.ListEntries();

        if (entries.Count == 0)
        {
            Console.WriteLine("Quarantine is empty.");
            return 0;
        }

        foreach (var entry in entries)
        {
            Console.WriteLine($"{entry.Id}");
            Console.WriteLine($"  original path : {entry.OriginalPath}");
            Console.WriteLine($"  reason        : {entry.Reason}");
            Console.WriteLine($"  quarantined   : {entry.TimestampUtc:u}");
        }
        return 0;
    }

    private static int RunRestoreQuarantine(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("error: missing quarantine id");
            Console.Error.WriteLine("usage: OpenSecurity.Cli restore-quarantine <id>");
            return 2;
        }

        var manager = new QuarantineManager(DefaultPaths.DefaultQuarantineDirectory());
        try
        {
            manager.Restore(args[0]);
            Console.WriteLine($"Restored quarantine entry {args[0]}.");
            return 0;
        }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static void PrintFindings(ScanResult result, string label)
    {
        Console.WriteLine($"[{label}]  {result.FilePath}  (sha256: {result.Sha256})");
        foreach (var finding in result.Findings)
            Console.WriteLine($"    - [{finding.Source}] {finding.Name}: {finding.Detail}");
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            OpenSecurity - on-demand malware scanner

            Usage:
              OpenSecurity.Cli <path> [--recursive] [--verbose] [--hashdb <file>] [--rules <dir>] [--allowlist <file>] [--quarantine]
              OpenSecurity.Cli update-signatures <url> [--hashdb <file>]
              OpenSecurity.Cli list-quarantine
              OpenSecurity.Cli restore-quarantine <id>

            Options:
              --recursive, -r      Scan directories recursively (default: on for directories)
              --no-recursive       Disable recursive directory scan
              --verbose, -v        Print clean files too, not just detections
              --hashdb <file>      Path to hash signature database (default: signatures/hashes.txt)
              --rules <dir>        Path to pattern rules directory (default: rules/)
              --allowlist <file>   Path to allowlist database (default: signatures/allowlist.txt)
              --quarantine         Move malicious files to quarantine instead of just reporting them

            update-signatures fetches a plaintext SHA-256 hash feed and merges new entries into
            the hash database. Suggested feed: https://bazaar.abuse.ch/export/txt/sha256/full/

            Exit codes:
              0   no malicious files found
              1   at least one malicious file found
              2   usage or path error
            """);
    }
}
