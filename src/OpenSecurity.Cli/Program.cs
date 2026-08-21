using System.Diagnostics;
using OpenSecurity.Core;
using OpenSecurity.Core.Hashing;
using OpenSecurity.Core.Heuristics;
using OpenSecurity.Core.History;
using OpenSecurity.Core.Quarantine;
using OpenSecurity.Core.RealTime;
using OpenSecurity.Core.Reporting;
using OpenSecurity.Core.Rules;
using OpenSecurity.Core.Scanning;
using OpenSecurity.Core.Scheduling;
using OpenSecurity.Core.Updates;

namespace OpenSecurity.Cli;

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length > 0)
        {
            switch (args[0])
            {
                case "update-signatures": return RunUpdateSignatures(args.Skip(1).ToArray()).GetAwaiter().GetResult();
                case "list-quarantine": return RunListQuarantine();
                case "restore-quarantine": return RunRestoreQuarantine(args.Skip(1).ToArray());
                case "list-history": return RunListHistory();
                case "schedule": return RunSchedule(args.Skip(1).ToArray());
                case "watch": return RunWatch(args.Skip(1).ToArray());
            }
        }

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
        var archivePasswordsPath = DefaultPaths.FindUp(appDir, Path.Combine("signatures", "archive_passwords.txt"));
        var fuzzyHashesPath = DefaultPaths.FindUp(appDir, Path.Combine("signatures", "fuzzy_hashes.txt"));

        var hashDb = hashDbPath is not null ? HashSignatureDatabase.Load(hashDbPath) : HashSignatureDatabase.Empty();
        var rules = rulesDir is not null ? PatternRuleParser.ParseDirectory(rulesDir) : new List<PatternRule>();
        var allowlist = allowlistPath is not null ? HashSignatureDatabase.Load(allowlistPath) : HashSignatureDatabase.Empty();
        var archivePasswords = archivePasswordsPath is not null ? ArchivePasswordList.Load(archivePasswordsPath) : new List<string>();
        var fuzzySignatures = fuzzyHashesPath is not null ? FuzzySignatureDatabase.Load(fuzzyHashesPath) : FuzzySignatureDatabase.Empty();

        Console.WriteLine($"OpenSecurity core scan engine");
        Console.WriteLine($"  by Nolan Crowley - Open Source (MIT License)");
        Console.WriteLine($"  hash signatures loaded : {hashDb.Count} (from {hashDbPath ?? "none found"})");
        Console.WriteLine($"  fuzzy signatures loaded : {fuzzySignatures.Count} (from {fuzzyHashesPath ?? "none found"})");
        Console.WriteLine($"  pattern rules loaded    : {rules.Count} (from {rulesDir ?? "none found"})");
        Console.WriteLine($"  allowlist entries       : {allowlist.Count} (from {allowlistPath ?? "none found"})");
        Console.WriteLine($"  archive passwords       : {archivePasswords.Count} (from {archivePasswordsPath ?? "none found"})");
        Console.WriteLine();

        var engine = new ScanEngine(new HashScanner(hashDb), new PatternRuleEngine(rules), new HeuristicAnalyzer(), allowlist, archivePasswords, fuzzySignatures);
        var quarantineManager = new QuarantineManager(DefaultPaths.DefaultQuarantineDirectory());

        var stopwatch = Stopwatch.StartNew();
        var results = File.Exists(options.TargetPath)
            ? new[] { engine.ScanFile(options.TargetPath) }
            : engine.ScanDirectory(options.TargetPath, options.Recursive).ToArray();
        stopwatch.Stop();

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

        var historyStore = new ScanHistoryStore(DefaultPaths.DefaultHistoryFilePath());
        historyStore.Append(ScanHistoryEntry.FromResults(options.TargetPath, results, stopwatch.Elapsed.TotalSeconds));

        if (options.ExportPath is not null)
        {
            ReportExporter.Export(results, options.ExportPath);
            Console.WriteLine($"Report exported to {options.ExportPath}");
        }

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

    private static int RunListHistory()
    {
        var store = new ScanHistoryStore(DefaultPaths.DefaultHistoryFilePath());
        var entries = store.ListEntries();

        if (entries.Count == 0)
        {
            Console.WriteLine("No scan history yet.");
            return 0;
        }

        foreach (var entry in entries)
        {
            Console.WriteLine($"{entry.TimestampUtc:u}  {entry.TargetPath}");
            Console.WriteLine($"  {entry.FilesScanned} scanned, {entry.CleanCount} clean, {entry.SuspiciousCount} suspicious, {entry.MaliciousCount} malicious, {entry.ErrorCount} errors ({entry.DurationSeconds:F1}s)");
            foreach (var flagged in entry.FlaggedFiles)
                Console.WriteLine($"    [{flagged.Verdict}] {flagged.FilePath} ({flagged.TopFinding})");
        }
        return 0;
    }

    private static int RunSchedule(string[] args)
    {
        var manager = new ScheduledScanManager();

        if (args.Length == 0)
        {
            Console.Error.WriteLine("usage: OpenSecurity.Cli schedule <enable <path> [--frequency daily|weekly] [--time HH:mm] [--quarantine]|disable|status>");
            return 2;
        }

        switch (args[0])
        {
            case "status":
                Console.WriteLine(manager.Exists() ? $"Scheduled scan '{ScheduledScanManager.TaskName}' is enabled." : "No scheduled scan configured.");
                return 0;

            case "disable":
                manager.Delete();
                Console.WriteLine("Scheduled scan disabled.");
                return 0;

            case "enable":
                if (args.Length < 2)
                {
                    Console.Error.WriteLine("error: missing path to scan");
                    return 2;
                }

                var targetPath = args[1];
                var frequency = ScanFrequency.Daily;
                var time = new TimeSpan(9, 0, 0);
                var quarantine = false;

                for (var i = 2; i < args.Length; i++)
                {
                    switch (args[i])
                    {
                        case "--frequency" when ++i < args.Length:
                            frequency = args[i].Equals("weekly", StringComparison.OrdinalIgnoreCase) ? ScanFrequency.Weekly : ScanFrequency.Daily;
                            break;
                        case "--time" when ++i < args.Length:
                            if (!TimeSpan.TryParse(args[i], out time))
                            {
                                Console.Error.WriteLine($"error: invalid time '{args[i]}', expected HH:mm");
                                return 2;
                            }
                            break;
                        case "--quarantine":
                            quarantine = true;
                            break;
                    }
                }

                var cliExePath = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "OpenSecurity.Cli.exe");
                try
                {
                    manager.CreateOrUpdate(cliExePath, new ScheduledScanConfig(targetPath, quarantine, frequency, time));
                    Console.WriteLine($"Scheduled scan enabled: {frequency} at {time:hh\\:mm}, target '{targetPath}'{(quarantine ? " (auto-quarantine)" : "")}.");
                    return 0;
                }
                catch (InvalidOperationException ex)
                {
                    Console.Error.WriteLine($"error: {ex.Message}");
                    return 1;
                }

            default:
                Console.Error.WriteLine($"error: unknown schedule command '{args[0]}'");
                return 2;
        }
    }

    private static int RunWatch(string[] args)
    {
        var quarantine = args.Contains("--quarantine");
        var folders = args.Where(a => a != "--quarantine").ToList();
        if (folders.Count == 0)
            folders = OpenSecurity.Core.Settings.AppSettings.DefaultWatchedFolders();

        var missing = folders.Where(f => !Directory.Exists(f)).ToList();
        if (missing.Count > 0)
        {
            Console.Error.WriteLine($"error: folder(s) not found: {string.Join(", ", missing)}");
            return 2;
        }

        var appDir = AppContext.BaseDirectory;
        var hashDbPath = DefaultPaths.FindUp(appDir, Path.Combine("signatures", "hashes.txt"));
        var rulesDir = DefaultPaths.FindUp(appDir, "rules");
        var allowlistPath = DefaultPaths.FindUp(appDir, Path.Combine("signatures", "allowlist.txt"));
        var archivePasswordsPath = DefaultPaths.FindUp(appDir, Path.Combine("signatures", "archive_passwords.txt"));
        var fuzzyHashesPath = DefaultPaths.FindUp(appDir, Path.Combine("signatures", "fuzzy_hashes.txt"));

        var hashDb = hashDbPath is not null ? HashSignatureDatabase.Load(hashDbPath) : HashSignatureDatabase.Empty();
        var rules = rulesDir is not null ? PatternRuleParser.ParseDirectory(rulesDir) : new List<PatternRule>();
        var allowlist = allowlistPath is not null ? HashSignatureDatabase.Load(allowlistPath) : HashSignatureDatabase.Empty();
        var archivePasswords = archivePasswordsPath is not null ? ArchivePasswordList.Load(archivePasswordsPath) : new List<string>();
        var fuzzySignatures = fuzzyHashesPath is not null ? FuzzySignatureDatabase.Load(fuzzyHashesPath) : FuzzySignatureDatabase.Empty();
        var engine = new ScanEngine(new HashScanner(hashDb), new PatternRuleEngine(rules), new HeuristicAnalyzer(), allowlist, archivePasswords, fuzzySignatures);
        var quarantineManager = new QuarantineManager(DefaultPaths.DefaultQuarantineDirectory());

        using var service = new RealTimeProtectionService(engine);
        service.FileScanned += result => Console.WriteLine($"[scanned]    {result.FilePath} -> {result.OverallVerdict}");
        service.ThreatDetected += result =>
        {
            Console.WriteLine($"[{result.OverallVerdict.ToString().ToUpperInvariant()}]  {result.FilePath}");
            foreach (var finding in result.Findings)
                Console.WriteLine($"    - [{finding.Source}] {finding.Name}: {finding.Detail}");

            if (quarantine && result.OverallVerdict == Verdict.Malicious)
            {
                var reason = string.Join("; ", result.Findings.Select(f => f.Name));
                var entry = quarantineManager.Quarantine(result.FilePath, result.Sha256, reason);
                Console.WriteLine($"    -> quarantined (id: {entry.Id})");
            }
        };

        service.Start(folders);
        Console.WriteLine($"Watching {folders.Count} folder(s) for real-time protection{(quarantine ? ", auto-quarantining Malicious detections" : "")}. Press Ctrl+C to stop.");
        foreach (var folder in folders)
            Console.WriteLine($"  - {folder}");

        var exitSignal = new TaskCompletionSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            exitSignal.TrySetResult();
        };
        exitSignal.Task.GetAwaiter().GetResult();

        service.Stop();
        return 0;
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
              OpenSecurity.Cli <path> [--recursive] [--verbose] [--hashdb <file>] [--rules <dir>] [--allowlist <file>] [--quarantine] [--export <file>]
              OpenSecurity.Cli update-signatures <url> [--hashdb <file>]
              OpenSecurity.Cli list-quarantine
              OpenSecurity.Cli restore-quarantine <id>
              OpenSecurity.Cli list-history
              OpenSecurity.Cli schedule enable <path> [--frequency daily|weekly] [--time HH:mm] [--quarantine]
              OpenSecurity.Cli schedule disable
              OpenSecurity.Cli schedule status
              OpenSecurity.Cli watch [folder...] [--quarantine]

            Options:
              --recursive, -r      Scan directories recursively (default: on for directories)
              --no-recursive       Disable recursive directory scan
              --verbose, -v        Print clean files too, not just detections
              --hashdb <file>      Path to hash signature database (default: signatures/hashes.txt)
              --rules <dir>        Path to pattern rules directory (default: rules/)
              --allowlist <file>   Path to allowlist database (default: signatures/allowlist.txt)
              --quarantine         Move malicious files to quarantine instead of just reporting them
              --export <file>      Write a JSON or CSV report of the scan (format from extension)

            Every scan is recorded to local history automatically. To scan an entire drive,
            just pass its root, e.g. OpenSecurity.Cli.exe C:\ --quarantine

            update-signatures fetches a plaintext SHA-256 hash feed and merges new entries into
            the hash database. Suggested feed: https://bazaar.abuse.ch/export/txt/sha256/full/

            watch runs real-time protection in the foreground: it scans new/changed files in the
            given folders (default: Downloads, Desktop, temp) as they appear.

            Exit codes:
              0   no malicious files found
              1   at least one malicious file found
              2   usage or path error
            """);
    }
}
