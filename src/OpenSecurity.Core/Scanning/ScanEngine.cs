using System.IO.Compression;
using OpenSecurity.Core.Hashing;
using OpenSecurity.Core.Heuristics;
using OpenSecurity.Core.Pe;
using OpenSecurity.Core.Rules;

namespace OpenSecurity.Core.Scanning;

public sealed class ScanEngine
{
    private const long MaxFileSizeBytes = 200L * 1024 * 1024; // 200 MB safety cap
    private const int MaxZipEntries = 2000;
    private const long MaxZipEntryBytes = 50L * 1024 * 1024; // per-entry cap, smaller than the top-level cap since archives are more zip-bomb-prone
    private const long MaxZipTotalBytes = 500L * 1024 * 1024; // total decompressed budget across the whole archive

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

        var (sha256, findings) = ScanContent(fileBytes, path);
        var result = new ScanResult { FilePath = path, FileSizeBytes = fileBytes.LongLength, Sha256 = sha256 };
        result.Findings.AddRange(findings);

        if (IsZipMagic(fileBytes))
            ScanZipEntries(fileBytes, result);

        return result;
    }

    public IEnumerable<ScanResult> ScanDirectory(string directoryPath, bool recursive = true)
    {
        if (!Directory.Exists(directoryPath))
        {
            var missing = new ScanResult { FilePath = directoryPath, FileSizeBytes = 0, Sha256 = "" };
            missing.Findings.Add(new ScanFinding("engine", Verdict.Error, "directory-not-found", "directory does not exist", 0));
            yield return missing;
            yield break;
        }

        foreach (var file in ResilientFileWalker.EnumerateFiles(directoryPath, recursive))
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

    /// <summary>Runs the hash/allowlist/rule/heuristic pipeline against a blob of bytes, whether it's
    /// a real file on disk or an in-memory archive entry. <paramref name="filePathForAuthenticode"/>
    /// is null for archive entries, since Authenticode validation needs a real file path.</summary>
    private (string Sha256, List<ScanFinding> Findings) ScanContent(byte[] bytes, string? filePathForAuthenticode)
    {
        var sha256 = HashScanner.ComputeSha256(new MemoryStream(bytes));
        var findings = new List<ScanFinding>();

        findings.AddRange(_hashScanner.Scan(sha256));

        // An explicit known-malicious hash match always stands; the allowlist only suppresses
        // the noisier pattern-rule/heuristic layers, so it can't be used to hide a blacklisted file.
        if (_allowlist.TryMatch(sha256, out _))
            return (sha256, findings);

        findings.AddRange(_ruleEngine.Scan(bytes));

        if (PeParser.TryParse(bytes, out var peFile) && peFile is not null)
            findings.AddRange(_heuristicAnalyzer.Analyze(peFile, bytes, filePathForAuthenticode));

        return (sha256, findings);
    }

    private static bool IsZipMagic(byte[] bytes) =>
        bytes.Length >= 4 && bytes[0] == 'P' && bytes[1] == 'K' && bytes[2] is 0x03 or 0x05 or 0x07 && bytes[3] is 0x04 or 0x06 or 0x08;

    private void ScanZipEntries(byte[] zipBytes, ScanResult result)
    {
        using var stream = new MemoryStream(zipBytes);
        ZipArchive archive;
        try
        {
            archive = new ZipArchive(stream, ZipArchiveMode.Read);
        }
        catch (InvalidDataException)
        {
            result.Findings.Add(new ScanFinding("archive", Verdict.Error, "corrupt-archive", "could not be opened as a valid zip", 0));
            return;
        }

        using (archive)
        {
            var entryCount = 0;
            long totalBytesRead = 0;

            foreach (var entry in archive.Entries)
            {
                if (string.IsNullOrEmpty(entry.Name))
                    continue; // directory entry

                if (++entryCount > MaxZipEntries)
                {
                    result.Findings.Add(new ScanFinding("archive", Verdict.Error, "too-many-entries", $"stopped after {MaxZipEntries} entries", 0));
                    break;
                }

                if (totalBytesRead >= MaxZipTotalBytes)
                {
                    result.Findings.Add(new ScanFinding("archive", Verdict.Error, "archive-too-large", $"stopped after {MaxZipTotalBytes / 1024 / 1024} MB of decompressed content", 0));
                    break;
                }

                byte[]? entryBytes;
                try
                {
                    using var entryStream = entry.Open();
                    entryBytes = ReadBounded(entryStream, MaxZipEntryBytes);
                }
                catch (Exception ex) when (ex is InvalidDataException or IOException)
                {
                    result.Findings.Add(new ScanFinding("archive", Verdict.Error, "entry-read-error", $"[{entry.FullName}] {ex.Message}", 0));
                    continue;
                }

                if (entryBytes is null)
                {
                    result.Findings.Add(new ScanFinding("archive", Verdict.Error, "entry-too-large", $"[{entry.FullName}] exceeds {MaxZipEntryBytes / 1024 / 1024} MB, skipped", 0));
                    continue;
                }

                totalBytesRead += entryBytes.LongLength;

                var (_, entryFindings) = ScanContent(entryBytes, null);
                foreach (var finding in entryFindings)
                    result.Findings.Add(new ScanFinding("archive", finding.Verdict, finding.Name, $"[{entry.FullName}] {finding.Detail}", finding.Score));
            }
        }
    }

    /// <summary>Reads a stream into a byte array, returning null instead of exceeding <paramref name="maxBytes"/>
    /// - guards against zip-bomb entries that lie about their declared uncompressed size.</summary>
    private static byte[]? ReadBounded(Stream stream, long maxBytes)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = stream.Read(chunk, 0, chunk.Length)) > 0)
        {
            buffer.Write(chunk, 0, read);
            if (buffer.Length > maxBytes)
                return null;
        }
        return buffer.ToArray();
    }
}
