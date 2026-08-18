using OpenSecurity.Core.Hashing;
using OpenSecurity.Core.Heuristics;
using OpenSecurity.Core.Pe;
using OpenSecurity.Core.Rules;

namespace OpenSecurity.Core.Scanning;

public sealed class ScanEngine
{
    private const long MaxFileSizeBytes = 200L * 1024 * 1024; // 200 MB safety cap

    private readonly HashScanner _hashScanner;
    private readonly PatternRuleEngine _ruleEngine;
    private readonly HeuristicAnalyzer _heuristicAnalyzer;
    private readonly HashSignatureDatabase _allowlist;

    public ScanEngine(HashScanner hashScanner, PatternRuleEngine ruleEngine, HeuristicAnalyzer heuristicAnalyzer, HashSignatureDatabase? allowlist = null)
    {
        _hashScanner = hashScanner;
        _ruleEngine = ruleEngine;
        _heuristicAnalyzer = heuristicAnalyzer;
        _allowlist = allowlist ?? HashSignatureDatabase.Empty();
    }

    public ScanResult ScanFile(string path)
    {
        var fileInfo = new FileInfo(path);

        if (!fileInfo.Exists)
        {
            var missing = new ScanResult { FilePath = path, FileSizeBytes = 0, Sha256 = "" };
            missing.Findings.Add(new ScanFinding("engine", Verdict.Error, "file-not-found", "file does not exist", 0));
            return missing;
        }

        if (fileInfo.Length > MaxFileSizeBytes)
        {
            var tooLarge = new ScanResult { FilePath = path, FileSizeBytes = fileInfo.Length, Sha256 = "" };
            tooLarge.Findings.Add(new ScanFinding("engine", Verdict.Error, "file-too-large", $"skipped, exceeds {MaxFileSizeBytes / 1024 / 1024} MB scan limit", 0));
            return tooLarge;
        }

        byte[] fileBytes;
        try
        {
            fileBytes = File.ReadAllBytes(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            var error = new ScanResult { FilePath = path, FileSizeBytes = fileInfo.Length, Sha256 = "" };
            error.Findings.Add(new ScanFinding("engine", Verdict.Error, "read-error", ex.Message, 0));
            return error;
        }

        var sha256 = HashScanner.ComputeSha256(new MemoryStream(fileBytes));
        var result = new ScanResult { FilePath = path, FileSizeBytes = fileBytes.LongLength, Sha256 = sha256 };

        result.Findings.AddRange(_hashScanner.Scan(sha256));

        // An explicit known-malicious hash match always stands; the allowlist only suppresses
        // the noisier pattern-rule/heuristic layers, so it can't be used to hide a blacklisted file.
        if (_allowlist.TryMatch(sha256, out _))
            return result;

        result.Findings.AddRange(_ruleEngine.Scan(fileBytes));

        if (PeParser.TryParse(fileBytes, out var peFile) && peFile is not null)
            result.Findings.AddRange(_heuristicAnalyzer.Analyze(peFile, fileBytes));

        return result;
    }

    public IEnumerable<ScanResult> ScanDirectory(string directoryPath, bool recursive = true)
    {
        var option = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        IEnumerable<string>? files = null;
        ScanResult? enumerateError = null;
        try
        {
            files = Directory.EnumerateFiles(directoryPath, "*", option);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            enumerateError = new ScanResult { FilePath = directoryPath, FileSizeBytes = 0, Sha256 = "" };
            enumerateError.Findings.Add(new ScanFinding("engine", Verdict.Error, "enumerate-error", ex.Message, 0));
        }

        if (enumerateError is not null)
        {
            yield return enumerateError;
            yield break;
        }

        foreach (var file in files!)
        {
            ScanResult result;
            try
            {
                result = ScanFile(file);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                result = new ScanResult { FilePath = file, FileSizeBytes = 0, Sha256 = "" };
                result.Findings.Add(new ScanFinding("engine", Verdict.Error, "scan-error", ex.Message, 0));
            }
            yield return result;
        }
    }
}
