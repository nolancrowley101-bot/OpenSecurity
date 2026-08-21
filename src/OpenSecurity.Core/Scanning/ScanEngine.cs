using OpenSecurity.Core.Hashing;
using OpenSecurity.Core.Heuristics;
using OpenSecurity.Core.Pe;
using OpenSecurity.Core.Rules;
using SharpCompress.Archives;
using SharpCompress.Readers;

namespace OpenSecurity.Core.Scanning;

public sealed class ScanEngine
{
    private const long MaxFileSizeBytes = 200L * 1024 * 1024; // 200 MB safety cap
    private const int MaxArchiveEntries = 2000;
    private const long MaxArchiveEntryBytes = 50L * 1024 * 1024; // per-entry cap, smaller than the top-level cap since archives are more zip-bomb-prone
    private const long MaxArchiveTotalBytes = 500L * 1024 * 1024; // total decompressed budget across the whole archive

    private readonly HashScanner _hashScanner;
    private readonly PatternRuleEngine _ruleEngine;
    private readonly HeuristicAnalyzer _heuristicAnalyzer;
    private readonly HashSignatureDatabase _allowlist;
    private readonly IReadOnlyList<string> _archivePasswords;

    public ScanEngine(HashScanner hashScanner, PatternRuleEngine ruleEngine, HeuristicAnalyzer heuristicAnalyzer,
        HashSignatureDatabase? allowlist = null, IReadOnlyList<string>? archivePasswords = null)
    {
        _hashScanner = hashScanner;
        _ruleEngine = ruleEngine;
        _heuristicAnalyzer = heuristicAnalyzer;
        _allowlist = allowlist ?? HashSignatureDatabase.Empty();
        _archivePasswords = archivePasswords ?? Array.Empty<string>();
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

        if (IsSupportedArchiveMagic(fileBytes))
            ScanArchiveEntries(fileBytes, result);

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

    private static bool IsSupportedArchiveMagic(byte[] bytes)
    {
        if (bytes.Length >= 4 && bytes[0] == 'P' && bytes[1] == 'K' && bytes[2] is 0x03 or 0x05 or 0x07 && bytes[3] is 0x04 or 0x06 or 0x08)
            return true; // zip

        if (bytes.Length >= 6 && bytes[0] == 0x37 && bytes[1] == 0x7A && bytes[2] == 0xBC && bytes[3] == 0xAF && bytes[4] == 0x27 && bytes[5] == 0x1C)
            return true; // 7z

        return false;
    }

    /// <summary>
    /// Opens zip/7z archives - including password-protected ones, common for malware sample
    /// collections shared this way to prevent AV auto-deletion/accidental execution - and scans
    /// every entry with the same pipeline as a real file. Tries no password first, then each
    /// entry in the configured password list, so it also handles unencrypted archives cheaply.
    /// </summary>
    private void ScanArchiveEntries(byte[] archiveBytes, ScanResult result)
    {
        var candidatePasswords = new List<string?> { null };
        candidatePasswords.AddRange(_archivePasswords);
        Exception? lastFailure = null;

        foreach (var password in candidatePasswords)
        {
            IArchive archive;
            try
            {
                var stream = new MemoryStream(archiveBytes);
                var options = password is null ? new ReaderOptions() : new ReaderOptions { Password = password };
                archive = ArchiveFactory.OpenArchive(stream, options);
            }
            catch (Exception ex)
            {
                // Not this format, or this password attempt failed outright - try the next candidate.
                if (lastFailure is not NotSupportedException)
                    lastFailure = ex;
                continue;
            }

            using (archive)
            {
                // For 7z, decryption happens at the folder/header level, so a wrong password can
                // throw as soon as entries are enumerated - not just when reading an entry's stream
                // (unlike zip, where each entry is independently encrypted). Validate both steps
                // under the same catch so either format's failure mode moves on to the next password.
                List<IArchiveEntry> entries;
                byte[]? firstEntryBytes;
                try
                {
                    entries = archive.Entries.Where(e => !e.IsDirectory).ToList();
                    if (entries.Count == 0)
                        return; // nothing to scan, whether or not the archive is encrypted

                    using var firstStream = entries[0].OpenEntryStream();
                    firstEntryBytes = ReadBounded(firstStream, MaxArchiveEntryBytes);
                }
                catch (Exception ex)
                {
                    // Wrong password (or a corrupt/unsupported entry) - try the next candidate password.
                    // NotSupportedException means the password actually got past decryption into a
                    // codec we can't decode (e.g. LZMA+AES zip, an uncommon variant) - more informative
                    // than a generic wrong-password failure, so it takes priority when reported below.
                    if (lastFailure is not NotSupportedException)
                        lastFailure = ex;
                    continue;
                }

                long totalBytesRead = 0;
                if (firstEntryBytes is not null)
                {
                    totalBytesRead += firstEntryBytes.LongLength;
                    ScoreArchiveEntry(entries[0].Key ?? "?", firstEntryBytes, result);
                }
                else
                {
                    result.Findings.Add(new ScanFinding("archive", Verdict.Error, "entry-too-large",
                        $"[{entries[0].Key}] exceeds {MaxArchiveEntryBytes / 1024 / 1024} MB, skipped", 0));
                }

                for (var i = 1; i < entries.Count; i++)
                {
                    if (i >= MaxArchiveEntries)
                    {
                        result.Findings.Add(new ScanFinding("archive", Verdict.Error, "too-many-entries", $"stopped after {MaxArchiveEntries} entries", 0));
                        break;
                    }

                    if (totalBytesRead >= MaxArchiveTotalBytes)
                    {
                        result.Findings.Add(new ScanFinding("archive", Verdict.Error, "archive-too-large", $"stopped after {MaxArchiveTotalBytes / 1024 / 1024} MB of decompressed content", 0));
                        break;
                    }

                    var entry = entries[i];
                    byte[]? entryBytes;
                    try
                    {
                        using var entryStream = entry.OpenEntryStream();
                        entryBytes = ReadBounded(entryStream, MaxArchiveEntryBytes);
                    }
                    catch (Exception ex)
                    {
                        // Some curated malware collections repackage third-party installers inside
                        // the archive, each keeping its own original password instead of the
                        // collection's own convention - a single zip can genuinely mix passwords
                        // per entry. Before giving up on this entry, retry it against every other
                        // configured password (a fresh archive open each time, since a failed
                        // decrypt/decompress can't be resumed mid-entry on the same stream).
                        entryBytes = TryReadEntryWithOtherPasswords(archiveBytes, entry.Key, password, candidatePasswords);
                        if (entryBytes is null)
                        {
                            result.Findings.Add(new ScanFinding("archive", Verdict.Error, "entry-read-error", $"[{entry.Key}] {ex.Message}", 0));
                            continue;
                        }
                    }

                    if (entryBytes is null)
                    {
                        result.Findings.Add(new ScanFinding("archive", Verdict.Error, "entry-too-large", $"[{entry.Key}] exceeds {MaxArchiveEntryBytes / 1024 / 1024} MB, skipped", 0));
                        continue;
                    }

                    totalBytesRead += entryBytes.LongLength;
                    ScoreArchiveEntry(entry.Key ?? "?", entryBytes, result);
                }

                return; // found a working password (or the archive wasn't encrypted) - done
            }
        }

        if (lastFailure is NotSupportedException)
        {
            result.Findings.Add(new ScanFinding("archive", Verdict.Error, "unsupported-archive",
                $"could not open - uses a compression/encryption combination this version doesn't support ({lastFailure.Message})", 0));
        }
        else
        {
            result.Findings.Add(new ScanFinding("archive", Verdict.Error, "password-protected",
                "could not open - password-protected with an unknown password, or corrupt. Add the password to signatures/archive_passwords.txt to scan it.", 0));
        }
    }

    private void ScoreArchiveEntry(string entryName, byte[] entryBytes, ScanResult result)
    {
        var (_, entryFindings) = ScanContent(entryBytes, null);
        foreach (var finding in entryFindings)
            result.Findings.Add(new ScanFinding("archive", finding.Verdict, finding.Name, $"[{entryName}] {finding.Detail}", finding.Score));
    }

    /// <summary>Retries a single archive entry (matched by key) against every password other than
    /// the one already locked in for the rest of the archive, re-opening a fresh archive/stream
    /// per attempt. Returns null if none of them can decrypt/decompress it.</summary>
    private static byte[]? TryReadEntryWithOtherPasswords(byte[] archiveBytes, string? entryKey, string? alreadyTried, List<string?> candidatePasswords)
    {
        if (entryKey is null)
            return null;

        foreach (var password in candidatePasswords)
        {
            if (password == alreadyTried)
                continue;

            try
            {
                var stream = new MemoryStream(archiveBytes);
                var options = password is null ? new ReaderOptions() : new ReaderOptions { Password = password };
                using var archive = ArchiveFactory.OpenArchive(stream, options);
                var entry = archive.Entries.FirstOrDefault(e => !e.IsDirectory && e.Key == entryKey);
                if (entry is null)
                    continue;

                using var entryStream = entry.OpenEntryStream();
                var bytes = ReadBounded(entryStream, MaxArchiveEntryBytes);
                if (bytes is not null)
                    return bytes;
            }
            catch
            {
                // Wrong password for this entry too - try the next candidate.
            }
        }

        return null;
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
