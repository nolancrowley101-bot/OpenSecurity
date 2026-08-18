using OpenSecurity.Core;
using OpenSecurity.Core.Hashing;
using OpenSecurity.Core.Heuristics;
using OpenSecurity.Core.Rules;
using OpenSecurity.Core.Scanning;

namespace OpenSecurity.Cli;

public static class Program
{
    public static int Main(string[] args)
    {
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

        var hashDb = hashDbPath is not null ? HashSignatureDatabase.Load(hashDbPath) : HashSignatureDatabase.Empty();
        var rules = rulesDir is not null ? PatternRuleParser.ParseDirectory(rulesDir) : new List<PatternRule>();

        Console.WriteLine($"OpenSecurity core scan engine");
        Console.WriteLine($"  by Nolan Crowley - Open Source (MIT License)");
        Console.WriteLine($"  hash signatures loaded : {hashDb.Count} (from {hashDbPath ?? "none found"})");
        Console.WriteLine($"  pattern rules loaded    : {rules.Count} (from {rulesDir ?? "none found"})");
        Console.WriteLine();

        var engine = new ScanEngine(new HashScanner(hashDb), new PatternRuleEngine(rules), new HeuristicAnalyzer());

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
              OpenSecurity.Cli <path> [--recursive] [--verbose] [--hashdb <file>] [--rules <dir>]

            Options:
              --recursive, -r      Scan directories recursively (default: on for directories)
              --no-recursive       Disable recursive directory scan
              --verbose, -v        Print clean files too, not just detections
              --hashdb <file>      Path to hash signature database (default: signatures/hashes.txt)
              --rules <dir>        Path to pattern rules directory (default: rules/)

            Exit codes:
              0   no malicious files found
              1   at least one malicious file found
              2   usage or path error
            """);
    }
}
